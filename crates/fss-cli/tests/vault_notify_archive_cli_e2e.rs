#![forbid(unsafe_code)]
//! Real end-to-end binary contract tests for the 3 newly wired unified CLI domains:
//! - `fss vault <init|set|list|revoke|doctor>` (zero plaintext, 0600 enforcement, canary scan)
//! - `fss notify <preview|dispatch>` (real loopback pure-Rust TLS 1.3 + HMAC-SHA256 + durable journal)
//! - `fss archive <seal|verify|upload|restore|crypto-erase>` (real loopback SigV4 S3 + AEAD + PRIV-010)

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fss_core::json_input::{Value, parse as parse_json};
use fss_core::{
    ContentDigest, EffectIntent, EffectState, IdempotencyKey, ObligationId, OperationId,
    TimestampNs,
};
use fss_pack::{PACK_KIND_RAW_PAYLOAD, PackConfig, PackId, PackObjectInput, PackStore};
use fss_reference::notify::ed25519::Ed25519SigningKey;
use fss_reference::notify::tls13::Tls13Stream;
use fss_reference::notify::webhook::verify_webhook_signature;
use fss_reference::notify::x509::{CertBuilderParams, build_ed25519_x509_der, encode_cert_pem};
use fss_vault::{CanaryLeakScanner, LabEntropy};

type TestResult = Result<(), Box<dyn Error>>;

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new(label: &str) -> Result<Self, Box<dyn Error>> {
        static SEQ: AtomicU64 = AtomicU64::new(1);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let tag = &label[..label.len().min(6)];
        #[cfg(target_os = "macos")]
        let base = PathBuf::from("/tmp");
        #[cfg(not(target_os = "macos"))]
        let base = std::env::temp_dir();
        let dir = base.join(format!("fss-vna-{tag}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_secret_0600(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn run_fss(args: &[&str]) -> Result<(i32, String, String), Box<dyn Error>> {
    let out = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(args)
        .output()?;
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8(out.stdout)?;
    let stderr = String::from_utf8(out.stderr)?;
    Ok((code, stdout, stderr))
}

fn json_text<'a>(val: &'a Value, key: &str) -> Result<&'a str, Box<dyn Error>> {
    let Value::Object(map) = val else {
        return Err("expected JSON object".into());
    };
    map.get(key)
        .and_then(Value::text)
        .ok_or_else(|| format!("missing string field `{key}`").into())
}

#[test]
fn fss_vault_cli_lifecycle_permissions_argv_refusal_and_zero_canary_leaks() -> TestResult {
    let dir = TempDirGuard::new("vault")?;
    let vault_dir = dir.path().join("vault");
    let pass_file = dir.path().join("pass.key");
    let secret_file = dir.path().join("secret.key");
    let permissive_file = dir.path().join("loose.key");

    let pass_canary = "CANARY-VAULT-PASS-9918273645!";
    let secret_canary = "CANARY-CAMERA-SECRET-4455667788!";
    write_secret_0600(&pass_file, pass_canary.as_bytes())?;
    write_secret_0600(&secret_file, secret_canary.as_bytes())?;
    fs::write(&permissive_file, b"too-open-secret")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&permissive_file, fs::Permissions::from_mode(0o644))?;
    }

    let mut scanner = CanaryLeakScanner::new();
    scanner.register_bytes("vault_passphrase", pass_canary.as_bytes())?;
    scanner.register_bytes("camera_secret", secret_canary.as_bytes())?;

    let vd = vault_dir.to_string_lossy().into_owned();
    let pf = pass_file.to_string_lossy().into_owned();
    let sf = secret_file.to_string_lossy().into_owned();
    let lf = permissive_file.to_string_lossy().into_owned();

    // 1. Forbidden argv secret flag MUST fail closed.
    let (code, stdout, stderr) = run_fss(&[
        "vault",
        "init",
        "--vault-dir",
        &vd,
        "--passphrase",
        "bad-cli-secret",
        "--json",
    ])?;
    assert_ne!(code, 0);
    assert!(
        stdout.contains("ERR-SECRET-INVALID-INPUT-001"),
        "stdout={stdout} stderr={stderr}"
    );

    // 2. Init vault.
    let (code, stdout, stderr) = run_fss(&[
        "vault",
        "init",
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--json",
    ])?;
    assert_eq!(
        code, 0,
        "vault init failed: stdout={stdout} stderr={stderr}"
    );
    scanner.assert_clean("vault init stdout", stdout.as_bytes())?;
    scanner.assert_clean("vault init stderr", stderr.as_bytes())?;

    // 3. Doctor reports healthy.
    let (code, stdout, _) = run_fss(&["vault", "doctor", "--vault-dir", &vd, "--json"])?;
    assert_eq!(code, 0, "vault doctor failed: {stdout}");
    let doc = parse_json(&stdout)?;
    assert_eq!(json_text(&doc, "verdict")?, "healthy");

    // 4. 0644 secret file MUST be refused with ERR-SECRET-PERMISSION-DENIED-001.
    #[cfg(unix)]
    {
        let (code, stdout, _) = run_fss(&[
            "vault",
            "set",
            "--vault-dir",
            &vd,
            "--passphrase-file",
            &pf,
            "--secret-file",
            &lf,
            "--secret-id",
            "secret:cam:bad-perm",
            "--family",
            "rtsp",
            "--target",
            "sensor:cam-1",
            "--endpoint",
            "rtsp://127.0.0.1:554/stream1",
            "--json",
        ])?;
        assert_ne!(code, 0);
        assert!(
            stdout.contains("ERR-SECRET-PERMISSION-DENIED-001"),
            "expected permission refusal, got: {stdout}"
        );
    }

    // 5. Store scoped secret from 0600 file.
    let (code, stdout, stderr) = run_fss(&[
        "vault",
        "set",
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--secret-file",
        &sf,
        "--secret-id",
        "secret:cam:front-1",
        "--family",
        "rtsp",
        "--target",
        "sensor:cam-1",
        "--endpoint",
        "rtsp://127.0.0.1:554/stream1",
        "--json",
    ])?;
    assert_eq!(code, 0, "vault set failed: {stdout} {stderr}");
    scanner.assert_clean("vault set stdout", stdout.as_bytes())?;

    // 6. List handles without leaking secret bytes (scoped to exact adapter/target/endpoint).
    let (code, stdout, _) = run_fss(&[
        "vault",
        "list",
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--family",
        "rtsp",
        "--target",
        "sensor:cam-1",
        "--endpoint",
        "rtsp://127.0.0.1:554/stream1",
        "--json",
    ])?;
    assert_eq!(code, 0, "vault list failed: {stdout}");
    assert!(stdout.contains("secret:cam:front-1"));
    scanner.assert_clean("vault list stdout", stdout.as_bytes())?;

    // 7. Revoke secret handle (scoped).
    let (code, stdout, _) = run_fss(&[
        "vault",
        "revoke",
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--secret-id",
        "secret:cam:front-1",
        "--family",
        "rtsp",
        "--target",
        "sensor:cam-1",
        "--endpoint",
        "rtsp://127.0.0.1:554/stream1",
        "--json",
    ])?;
    assert_eq!(code, 0, "vault revoke failed: {stdout}");
    assert!(stdout.contains("\"revoked\":true"));
    scanner.assert_clean("vault revoke stdout", stdout.as_bytes())?;

    Ok(())
}

type ParsedHttpRequest = (String, Vec<(String, String)>, Vec<u8>);

fn read_http_req_over_tls(tls: &mut Tls13Stream<TcpStream>) -> Result<ParsedHttpRequest, String> {
    let mut raw = Vec::new();
    let mut buf = [0_u8; 4096];
    let header_end = loop {
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let n = tls
            .read_application_data(&mut buf)
            .map_err(|e| format!("read header failed: {e}"))?;
        if n == 0 {
            return Err("EOF reading TLS HTTP request".to_owned());
        }
        raw.extend_from_slice(&buf[..n]);
    };
    let head = std::str::from_utf8(&raw[..header_end - 4]).map_err(|e| e.to_string())?;
    let mut lines = head.split("\r\n");
    let req_line = lines.next().unwrap_or("").to_owned();
    let mut headers = Vec::new();
    let mut content_len = 0_usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_owned();
            if key == "content-length" {
                content_len = val.parse().unwrap_or(0);
            }
            headers.push((key, val));
        }
    }
    let mut body = raw[header_end..].to_vec();
    while body.len() < content_len {
        let n = tls
            .read_application_data(&mut buf)
            .map_err(|e| format!("read body failed: {e}"))?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }
    body.truncate(content_len);
    Ok((req_line, headers, body))
}

#[test]
fn fss_notify_cli_binds_metadata_and_requires_durable_custody_before_secrets() -> TestResult {
    let dir = TempDirGuard::new("notify-approval")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let url = format!("https://127.0.0.1:{}/alerts", listener.local_addr()?.port());
    let pin = ContentDigest::sha256(b"approval-test-spki").to_text();
    let metadata_approval = ContentDigest::sha256(b"metadata-disclosure-approved").to_text();
    let journal = dir.path().join("effects.fssj");
    let journal_arg = journal.to_string_lossy().into_owned();
    let missing_pass = dir.path().join("missing-passphrase");
    let missing_pass_arg = missing_pass.to_string_lossy().into_owned();
    let missing_vault = dir.path().join("missing-vault");
    let missing_vault_arg = missing_vault.to_string_lossy().into_owned();
    let base = vec![
        "notify",
        "preview",
        "--channel",
        "https-webhook",
        "--target-id",
        "hook-approved",
        "--url",
        &url,
        "--secret-id",
        "secret:notify:approved",
        "--operation-id",
        "op:notify:approved",
        "--idempotency-key",
        "idem:notify:approved",
        "--pin-spki",
        &pin,
        "--disclosure",
        "event-metadata-v1",
        "--metadata-approval",
        &metadata_approval,
        "--event-id",
        "evt:notify:approved",
        "--summary",
        "Approved event summary",
        "--principal",
        "principal:local-operator",
        "--timeout-ms",
        "10000",
        "--json",
    ];
    let (code, preview, stderr) = run_fss(&base)?;
    assert_eq!(code, 0, "preview={preview} stderr={stderr}");
    let preview_json = parse_json(&preview)?;
    let approval = json_text(&preview_json, "approval_digest")?.to_owned();
    assert!(json_text(&preview_json, "request_digest")?.starts_with("sha256:"));

    // A valid approval cannot opt into an ephemeral journal, even when the supplied vault and
    // passphrase paths are unreadable. Admission must fail before attempting either read.
    let mut no_journal = base.clone();
    no_journal[1] = "dispatch";
    no_journal.extend([
        "--approve",
        &approval,
        "--vault-dir",
        &missing_vault_arg,
        "--passphrase-file",
        &missing_pass_arg,
    ]);
    let (code, refused, _) = run_fss(&no_journal)?;
    assert_ne!(code, 0);
    assert!(
        refused.contains("ERR-NOTIFY-JOURNAL-REQUIRED-001"),
        "{refused}"
    );

    // Changing disclosed event identity or summary used to preserve the same approval.
    // The declared principal and original timeout are also part of the exact authorization.
    for (flag, replacement) in [
        ("--event-id", "evt:notify:substituted"),
        ("--summary", "Unapproved replacement summary"),
        ("--principal", "principal:another-operator"),
        ("--timeout-ms", "20000"),
    ] {
        let mut changed = no_journal.clone();
        let index = changed
            .iter()
            .position(|value| *value == flag)
            .ok_or("missing fixture option")?;
        changed[index + 1] = replacement;
        changed.extend(["--effects-journal", &journal_arg]);
        let (code, refused, _) = run_fss(&changed)?;
        assert_ne!(code, 0, "{flag}");
        assert!(
            refused.contains("ERR-NOTIFY-APPROVAL-MISMATCH-001"),
            "{flag}: {refused}"
        );
    }

    // The in-process owner can cancel after initial admission; no credential read or journal
    // creation is allowed just because the first cancellation check returned false.
    let mut cancelled_args = no_journal.clone();
    cancelled_args.extend(["--effects-journal", &journal_arg]);
    let tokens: Vec<_> = cancelled_args[2..]
        .iter()
        .enumerate()
        .map(|(index, arg)| fss_cli::token::ArgToken::new(index, (*arg).to_owned()))
        .collect();
    let probes = AtomicUsize::new(0);
    let cancelled = || probes.fetch_add(1, Ordering::SeqCst) > 0;
    let control = fss_cli::RequestControl::new(&cancelled);
    let (refused, _) = fss_cli::notify_cmd::execute_notify_command("dispatch", &tokens, &control);
    assert!(refused.contains("ERR-CLI-READ-CANCELLED-001"), "{refused}");

    assert!(!journal.exists());
    assert!(!missing_pass.exists());
    assert!(!missing_vault.exists());
    assert!(matches!(
        listener.accept(),
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock
    ));
    Ok(())
}

#[test]
fn fss_notify_cli_preview_and_tls13_hmac_dispatch_with_durable_journal() -> TestResult {
    let dir = TempDirGuard::new("notify")?;
    let vault_dir = dir.path().join("vault");
    let pass_file = dir.path().join("pass.key");
    let hmac_file = dir.path().join("hmac.key");
    let ca_pem_file = dir.path().join("ca.pem");
    let journal_file = dir.path().join("effects.fssj");

    let pass_canary = "CANARY-NOTIFY-VAULT-PASS-8821!";
    let hmac_canary = "CANARY-NOTIFY-HMAC-SECRET-773219!";
    write_secret_0600(&pass_file, pass_canary.as_bytes())?;
    write_secret_0600(&hmac_file, hmac_canary.as_bytes())?;

    let mut scanner = CanaryLeakScanner::new();
    scanner.register_bytes("notify_vault_passphrase", pass_canary.as_bytes())?;
    scanner.register_bytes("notify_hmac_secret", hmac_canary.as_bytes())?;

    // Build self-contained Ed25519 CA + leaf cert valid across current wall clock (2020..2035).
    let ca_sk = Ed25519SigningKey::from_seed([0x31; 32]);
    let leaf_sk = Ed25519SigningKey::from_seed([0x32; 32]);
    let not_before_s = 1_577_836_800_i64; // 2020-01-01
    let not_after_s = 2_051_222_400_i64; // 2035-01-01
    let ca_der = build_ed25519_x509_der(
        &CertBuilderParams {
            serial: 1,
            issuer_cn: "FSS CLI Test CA",
            subject_cn: "FSS CLI Test CA",
            san_dns: &[],
            san_ips: &[],
            not_before_unix_s: not_before_s,
            not_after_unix_s: not_after_s,
            is_ca: true,
        },
        &ca_sk.verifying_key(),
        &ca_sk,
    );
    let leaf_der = build_ed25519_x509_der(
        &CertBuilderParams {
            serial: 2,
            issuer_cn: "FSS CLI Test CA",
            subject_cn: "hooks.fss.test",
            san_dns: &["hooks.fss.test"],
            san_ips: &[],
            not_before_unix_s: not_before_s,
            not_after_unix_s: not_after_s,
            is_ca: false,
        },
        &leaf_sk.verifying_key(),
        &ca_sk,
    );
    fs::write(&ca_pem_file, encode_cert_pem(&ca_der))?;

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let url = format!("https://hooks.fss.test:{}/alerts/hook", addr.port());
    let resolve = format!("hooks.fss.test={addr}");
    let vd = vault_dir.to_string_lossy().into_owned();
    let pf = pass_file.to_string_lossy().into_owned();
    let hf = hmac_file.to_string_lossy().into_owned();
    let cf = ca_pem_file.to_string_lossy().into_owned();
    let jf = journal_file.to_string_lossy().into_owned();

    // Init vault and store HMAC secret under exact AlertWebhook scope.
    let (code, stdout, stderr) = run_fss(&[
        "vault",
        "init",
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--json",
    ])?;
    assert_eq!(code, 0, "vault init failed: {stdout} {stderr}");
    let (code, stdout, stderr) = run_fss(&[
        "vault",
        "set",
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--secret-file",
        &hf,
        "--secret-id",
        "secret:webhook:cli-1",
        "--family",
        "alert_webhook",
        "--target",
        "hook-primary",
        "--endpoint",
        &url,
        "--json",
    ])?;
    assert_eq!(code, 0, "vault set webhook failed: {stdout} {stderr}");

    // 1. Plaintext http:// MUST be refused fail-closed with ERR-NOTIFY-PLAINTEXT-REFUSED-001.
    let (code, stdout, _) = run_fss(&[
        "notify",
        "preview",
        "--channel",
        "https-webhook",
        "--target-id",
        "hook-primary",
        "--url",
        "http://hooks.fss.test/alerts/hook",
        "--secret-id",
        "secret:webhook:cli-1",
        "--operation-id",
        "op:notify:cli:1",
        "--idempotency-key",
        "idem:notify:cli:1",
        "--ca-pem",
        &cf,
        "--json",
    ])?;
    assert_ne!(code, 0);
    assert!(
        stdout.contains("ERR-NOTIFY-PLAINTEXT-REFUSED-001"),
        "expected plaintext refusal, got: {stdout}"
    );

    // 2. Preview computes canonical approval digest with ZERO network I/O.
    let (code, preview_out, stderr) = run_fss(&[
        "notify",
        "preview",
        "--channel",
        "https-webhook",
        "--target-id",
        "hook-primary",
        "--url",
        &url,
        "--secret-id",
        "secret:webhook:cli-1",
        "--operation-id",
        "op:notify:cli:1",
        "--idempotency-key",
        "idem:notify:cli:1",
        "--ca-pem",
        &cf,
        "--json",
    ])?;
    assert_eq!(code, 0, "notify preview failed: {preview_out} {stderr}");
    let preview_json = parse_json(&preview_out)?;
    let approval_digest = json_text(&preview_json, "approval_digest")?.to_owned();
    assert!(approval_digest.starts_with("sha256:"));

    // 3. Dispatch without --approve MUST be refused.
    let (code, no_app_out, _) = run_fss(&[
        "notify",
        "dispatch",
        "--channel",
        "https-webhook",
        "--target-id",
        "hook-primary",
        "--url",
        &url,
        "--secret-id",
        "secret:webhook:cli-1",
        "--operation-id",
        "op:notify:cli:1",
        "--idempotency-key",
        "idem:notify:cli:1",
        "--ca-pem",
        &cf,
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--json",
    ])?;
    assert_ne!(code, 0);
    assert!(no_app_out.contains("ERR-NOTIFY-APPROVAL-REQUIRED-001"));

    // An operation prepared under a different approval cannot be silently adopted by this CLI.
    // The request digest is identical; only the persisted authorization precondition differs.
    let stale_path = dir.path().join("stale-approval.fssj");
    let stale_arg = stale_path.to_string_lossy().into_owned();
    let operation_id = OperationId::parse("op:notify:cli:1")?;
    let mut stale_journal = fss_reference::DurableEffectJournal::open(
        &stale_path,
        fss_ledger::IncompleteTailPolicy::Reject,
    )?;
    let intent = EffectIntent::new(
        operation_id.clone(),
        IdempotencyKey::parse("idem:notify:cli:1")?,
        "notify.tls_dispatch",
        ContentDigest::parse(json_text(&preview_json, "request_digest")?)?,
        ContentDigest::sha256(b"different-prepared-approval"),
    )?;
    let _ = stale_journal.prepare(
        intent,
        ObligationId::parse("obligation:notify:stale-approval")?,
        "notification delivery independently reconciled",
        TimestampNs(1),
    )?;
    drop(stale_journal);
    let stale_before = fs::read(&stale_path)?;
    let (code, stale_out, _) = run_fss(&[
        "notify",
        "dispatch",
        "--channel",
        "https-webhook",
        "--target-id",
        "hook-primary",
        "--url",
        &url,
        "--secret-id",
        "secret:webhook:cli-1",
        "--operation-id",
        operation_id.as_str(),
        "--idempotency-key",
        "idem:notify:cli:1",
        "--ca-pem",
        &cf,
        "--resolve",
        &resolve,
        "--approve",
        &approval_digest,
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--effects-journal",
        &stale_arg,
        "--json",
    ])?;
    assert_ne!(code, 0);
    assert!(stale_out.contains("prepare failed"), "{stale_out}");
    assert_eq!(fs::read(&stale_path)?, stale_before);
    let stale_journal = fss_reference::DurableEffectJournal::open(
        &stale_path,
        fss_ledger::IncompleteTailPolicy::Reject,
    )?;
    assert_eq!(
        stale_journal.operation(&operation_id).map(|op| op.state),
        Some(EffectState::Prepared)
    );
    drop(stale_journal);

    // A second process must refuse the same journal, even through a different hard-link path.
    // Seed a nonempty exact Prepared record so contention also proves no truncation occurs.
    let mut prepared_journal = fss_reference::DurableEffectJournal::open(
        &journal_file,
        fss_ledger::IncompleteTailPolicy::Reject,
    )?;
    let intent = EffectIntent::new(
        operation_id.clone(),
        IdempotencyKey::parse("idem:notify:cli:1")?,
        "notify.tls_dispatch",
        ContentDigest::parse(json_text(&preview_json, "request_digest")?)?,
        ContentDigest::parse(&approval_digest)?,
    )?;
    let _ = prepared_journal.prepare(
        intent,
        ObligationId::parse("obligation:notify:cli:1")?,
        "notification delivery independently reconciled",
        TimestampNs(1),
    )?;
    drop(prepared_journal);
    let alias_path = dir.path().join("effects-alias.fssj");
    fs::hard_link(&journal_file, &alias_path)?;
    let alias_arg = alias_path.to_string_lossy().into_owned();
    let before_contention = fs::read(&journal_file)?;
    assert!(!before_contention.is_empty());
    let lease = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&journal_file)?;
    lease
        .try_lock()
        .map_err(|error| format!("test journal lock: {error:?}"))?;
    let unreadable_pass = dir.path().join("missing-passphrase");
    let unreadable_pass_arg = unreadable_pass.to_string_lossy().into_owned();
    let (code, busy_out, _) = run_fss(&[
        "notify",
        "dispatch",
        "--channel",
        "https-webhook",
        "--target-id",
        "hook-primary",
        "--url",
        &url,
        "--secret-id",
        "secret:webhook:cli-1",
        "--operation-id",
        operation_id.as_str(),
        "--idempotency-key",
        "idem:notify:cli:1",
        "--ca-pem",
        &cf,
        "--resolve",
        &resolve,
        "--approve",
        &approval_digest,
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &unreadable_pass_arg,
        "--effects-journal",
        &alias_arg,
        "--json",
    ])?;
    assert_ne!(code, 0);
    assert!(busy_out.contains("already in use"), "{busy_out}");
    listener.set_nonblocking(true)?;
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    listener.set_nonblocking(false)?;
    drop(lease);
    assert_eq!(fs::read(&journal_file)?, before_contention);

    // 4. Spawn real pure-Rust RFC 8446 TLS 1.3 loopback server verifying HMAC-SHA256!
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_bg = Arc::clone(&hits);
    let expected_hmac = hmac_canary.as_bytes().to_vec();
    let srv_handle = thread::spawn(move || -> Result<(), String> {
        let (sock, _) = listener.accept().map_err(|e| e.to_string())?;
        let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = sock.set_write_timeout(Some(Duration::from_secs(5)));
        let mut entropy = LabEntropy::from_seed([0x77; 32]);
        let mut tls = Tls13Stream::accept_server(sock, &[leaf_der], &leaf_sk, &mut entropy)
            .map_err(|e| e.to_string())?;
        let (req_line, headers, body) = read_http_req_over_tls(&mut tls)?;
        hits_bg.fetch_add(1, Ordering::SeqCst);
        if !req_line.starts_with("POST /alerts/hook HTTP/1.1") {
            return Err(format!("bad request line: {req_line}"));
        }
        let find = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };
        let ts: i64 = find("x-fss-timestamp")
            .ok_or("missing X-FSS-Timestamp")?
            .parse()
            .map_err(|_| "bad X-FSS-Timestamp")?;
        let delivery_id = find("x-fss-delivery-id").ok_or("missing X-FSS-Delivery-Id")?;
        let sig = find("x-fss-signature-256").ok_or("missing X-FSS-Signature-256")?;
        if !verify_webhook_signature(&expected_hmac, ts, delivery_id, &body, sig) {
            return Err("HMAC-SHA256 verification failed on server".to_owned());
        }
        let resp = b"HTTP/1.1 202 Accepted\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}";
        tls.write_application_data(resp)
            .map_err(|e| e.to_string())?;
        let _ = tls.close_notify();
        Ok(())
    });

    let (code, disp_out, stderr) = run_fss(&[
        "notify",
        "dispatch",
        "--channel",
        "https-webhook",
        "--target-id",
        "hook-primary",
        "--url",
        &url,
        "--secret-id",
        "secret:webhook:cli-1",
        "--operation-id",
        "op:notify:cli:1",
        "--idempotency-key",
        "idem:notify:cli:1",
        "--ca-pem",
        &cf,
        "--resolve",
        &resolve,
        "--approve",
        &approval_digest,
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--effects-journal",
        &jf,
        "--json",
    ])?;
    srv_handle
        .join()
        .map_err(|_| "TLS server thread panicked")??;
    assert_eq!(code, 0, "notify dispatch failed: {disp_out} {stderr}");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    let disp_json = parse_json(&disp_out)?;
    assert_eq!(json_text(&disp_json, "effect_state")?, "adapter_accepted");
    scanner.assert_clean("notify dispatch stdout", disp_out.as_bytes())?;

    // 5. Re-running the exact same operation against the durable journal MUST NOT resend!
    let (code, dup_out, _) = run_fss(&[
        "notify",
        "dispatch",
        "--channel",
        "https-webhook",
        "--target-id",
        "hook-primary",
        "--url",
        &url,
        "--secret-id",
        "secret:webhook:cli-1",
        "--operation-id",
        "op:notify:cli:1",
        "--idempotency-key",
        "idem:notify:cli:1",
        "--ca-pem",
        &cf,
        "--resolve",
        &resolve,
        "--approve",
        &approval_digest,
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--effects-journal",
        &jf,
        "--json",
    ])?;
    assert_ne!(
        code, 0,
        "duplicate dispatch against durable journal must fail: {dup_out}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "server must only ever be hit once"
    );
    Ok(())
}

struct LoopbackS3 {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    handle: Option<JoinHandle<()>>,
}

impl LoopbackS3 {
    fn start() -> Result<Self, Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let objects = Arc::new(Mutex::new(BTreeMap::new()));
        let stop_bg = Arc::clone(&stop);
        let objs_bg = Arc::clone(&objects);
        let handle = thread::spawn(move || {
            while !stop_bg.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        let _ = s.set_nonblocking(false);
                        let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                        let _ = handle_s3_conn(&mut s, &objs_bg);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            addr,
            stop,
            objects,
            handle: Some(handle),
        })
    }
}

impl Drop for LoopbackS3 {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn handle_s3_conn(
    stream: &mut TcpStream,
    objects: &Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
) -> Result<(), Box<dyn Error>> {
    let mut raw = Vec::new();
    let mut buf = [0_u8; 8192];
    let head_end = loop {
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        raw.extend_from_slice(&buf[..n]);
    };
    let head = std::str::from_utf8(&raw[..head_end - 4])?;
    let mut lines = head.split("\r\n");
    let req_line = lines.next().unwrap_or("");
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let path = target.split_once('?').map_or(target, |(p, _)| p).to_owned();
    let mut content_len = 0_usize;
    let mut has_sigv4 = false;
    let mut range = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse().unwrap_or(0);
            } else if k.eq_ignore_ascii_case("range") {
                let (start, end) = v
                    .trim()
                    .strip_prefix("bytes=")
                    .and_then(|s| s.split_once('-'))
                    .ok_or("invalid range")?;
                range = Some((start.parse::<usize>()?, end.parse::<usize>()?));
            } else if k.eq_ignore_ascii_case("authorization")
                && v.trim().starts_with("AWS4-HMAC-SHA256 ")
            {
                has_sigv4 = true;
            }
        }
    }
    let mut body = raw[head_end..].to_vec();
    while body.len() < content_len {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }
    body.truncate(content_len);
    if !has_sigv4 {
        stream.write_all(
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )?;
        return Ok(());
    }
    let mut guard = objects.lock().map_err(|_| "lock poisoned")?;
    match method {
        "PUT" => {
            let etag = format!("\"{}\"", &ContentDigest::sha256(&body).to_text()[7..23]);
            guard.insert(path, body);
            let reply = format!(
                "HTTP/1.1 200 OK\r\nETag: {etag}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(reply.as_bytes())?;
        }
        "GET" => {
            if let Some(bytes) = guard.get(&path) {
                let etag = format!("\"{}\"", &ContentDigest::sha256(bytes).to_text()[7..23]);
                if let Some((start, end)) = range {
                    let part = bytes.get(start..=end).ok_or("invalid mock sample range")?;
                    write!(
                        stream,
                        "HTTP/1.1 206 Partial Content\r\nETag: {etag}\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{end}/{}\r\nConnection: close\r\n\r\n",
                        part.len(),
                        bytes.len()
                    )?;
                    stream.write_all(part)?;
                    return Ok(());
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\nETag: {etag}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                );
                stream.write_all(head.as_bytes())?;
                stream.write_all(bytes)?;
            } else {
                stream.write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )?;
            }
        }
        _ => {
            stream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
        }
    }
    Ok(())
}

#[test]
fn fss_archive_cli_seal_verify_s3_upload_restore_and_crypto_erase_e2e() -> TestResult {
    let dir = TempDirGuard::new("archive")?;
    let dep_root = dir.path().join("dep");
    let vault_dir = dir.path().join("vault");
    let key_catalog = dir.path().join("keys.fskc");
    let enc_file = dir.path().join("pack-1-1.fsep");
    let manifests_dir = dir.path().join("cold-manifests");
    let restore_packs_dir = dir.path().join("restored-packs");
    fs::create_dir_all(&restore_packs_dir)?;

    let pass_file = dir.path().join("pass.key");
    let kek_file = dir.path().join("kek.raw");
    let s3_secret_file = dir.path().join("s3.key");

    write_secret_0600(&pass_file, b"archive-cli-vault-passphrase-2026")?;
    write_secret_0600(&kek_file, &[0xA5_u8; 32])?;
    write_secret_0600(&s3_secret_file, b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")?;

    // Populate a real PackStore with objects and leave active pack unsealed so `fss archive seal` seals it.
    let store = PackStore::open(&dep_root, PackConfig::default())?;
    let payload_a = b"retained-surveillance-evidence-payload-alpha-001";
    let payload_b = b"retained-surveillance-evidence-payload-beta-002";
    let _ = store.append_batch(&[
        PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, payload_a),
        PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, payload_b),
    ])?;
    drop(store);

    let s3 = LoopbackS3::start()?;
    let dr = dep_root.to_string_lossy().into_owned();
    let vd = vault_dir.to_string_lossy().into_owned();
    let pf = pass_file.to_string_lossy().into_owned();
    let kf = kek_file.to_string_lossy().into_owned();
    let sf = s3_secret_file.to_string_lossy().into_owned();
    let kc = key_catalog.to_string_lossy().into_owned();
    let ef = enc_file.to_string_lossy().into_owned();
    let md = manifests_dir.to_string_lossy().into_owned();
    let rp = restore_packs_dir.to_string_lossy().into_owned();
    let peer_str = s3.addr.to_string();

    // Setup vault with KEK (32 raw bytes -> --raw-bytes) + S3 secret.
    assert_eq!(
        run_fss(&[
            "vault",
            "init",
            "--vault-dir",
            &vd,
            "--passphrase-file",
            &pf,
            "--json"
        ])?
        .0,
        0
    );
    let (code, out, err) = run_fss(&[
        "vault",
        "set",
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--secret-file",
        &kf,
        "--raw-bytes",
        "--secret-id",
        "secret:kek:site-1",
        "--family",
        "storage_kek",
        "--target",
        "site:archive-e2e",
        "--endpoint",
        "storage-kek://site:archive-e2e/epoch-1",
        "--json",
    ])?;
    assert_eq!(code, 0, "vault set kek failed: {out} {err}");
    let (code, out, err) = run_fss(&[
        "vault",
        "set",
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--secret-file",
        &sf,
        "--secret-id",
        "secret:s3:cold-1",
        "--family",
        "archive_s3",
        "--target",
        "fss-cold-bucket",
        "--endpoint",
        "s3://s3.local/fss-cold-bucket",
        "--json",
    ])?;
    assert_eq!(code, 0, "vault set s3 failed: {out} {err}");

    // 1. `fss archive seal --root <dep>` seals the active packfile!
    let (code, seal_out, err) = run_fss(&["archive", "seal", "--root", &dr, "--json"])?;
    assert_eq!(code, 0, "archive seal failed: {seal_out} {err}");
    let seal_json = parse_json(&seal_out)?;
    let sealed_pack_id = json_text(&seal_json, "pack_id")?.to_owned();
    assert_eq!(sealed_pack_id, "pack-00000001-000000000001");
    let orig_sha = json_text(&seal_json, "whole_pack_sha256")?.to_owned();

    // 2. `fss archive verify --root <dep> --pack-id <pack_id>` verifies read-only (round-trips Display ID)!
    let (code, ver_out, err) = run_fss(&[
        "archive",
        "verify",
        "--root",
        &dr,
        "--pack-id",
        &sealed_pack_id,
        "--json",
    ])?;
    assert_eq!(code, 0, "archive verify failed: {ver_out} {err}");
    assert_eq!(
        json_text(&parse_json(&ver_out)?, "whole_pack_sha256")?,
        orig_sha
    );

    // 3. `fss archive seal --out <file.fsep>` encrypts sealed pack with AEAD!
    let (code, enc_out, err) = run_fss(&[
        "archive",
        "seal",
        "--root",
        &dr,
        "--pack-id",
        "1:1",
        "--out",
        &ef,
        "--key-catalog",
        &kc,
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--kek-secret-id",
        "secret:kek:site-1",
        "--site",
        "site:archive-e2e",
        "--json",
    ])?;
    assert_eq!(code, 0, "archive seal encrypt failed: {enc_out} {err}");
    let local_dek_id = json_text(&parse_json(&enc_out)?, "dek_id")?.to_owned();

    // 4. `fss archive verify --enc-file <file.fsep>` decrypts & authenticates!
    let (code, enc_ver_out, err) = run_fss(&[
        "archive",
        "verify",
        "--pack-id",
        "1:1",
        "--enc-file",
        &ef,
        "--key-catalog",
        &kc,
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--kek-secret-id",
        "secret:kek:site-1",
        "--site",
        "site:archive-e2e",
        "--json",
    ])?;
    assert_eq!(
        code, 0,
        "archive verify encrypted failed: {enc_ver_out} {err}"
    );
    assert!(enc_ver_out.contains("\"verified\":true"));

    // 5. `fss archive upload` preview -> approve -> real SigV4 S3 upload!
    let (code, up_prev, err) = run_fss(&[
        "archive",
        "upload",
        "--root",
        &dr,
        "--pack-id",
        "1:1",
        "--peer",
        &peer_str,
        "--host",
        "s3.local",
        "--bucket",
        "fss-cold-bucket",
        "--min-pack-bytes",
        "64",
        "--json",
    ])?;
    assert_eq!(code, 0, "archive upload preview failed: {up_prev} {err}");
    let up_approval = json_text(&parse_json(&up_prev)?, "approval_digest")?.to_owned();

    let (code, up_out, err) = run_fss(&[
        "archive",
        "upload",
        "--root",
        &dr,
        "--pack-id",
        "1:1",
        "--peer",
        &peer_str,
        "--host",
        "s3.local",
        "--bucket",
        "fss-cold-bucket",
        "--min-pack-bytes",
        "64",
        "--approve",
        &up_approval,
        "--key-catalog",
        &kc,
        "--local-manifest-dir",
        &md,
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--kek-secret-id",
        "secret:kek:site-1",
        "--s3-secret-id",
        "secret:s3:cold-1",
        "--access-key-id",
        "AKIAIOSFODNN7EXAMPLE",
        "--site",
        "site:archive-e2e",
        "--json",
    ])?;
    assert_eq!(code, 0, "archive upload commit failed: {up_out} {err}");
    assert!(
        !s3.objects.lock().map_err(|_| "lock poisoned")?.is_empty(),
        "loopback S3 must hold uploaded encrypted pack object"
    );
    let manifest_file = manifests_dir.join("pack-00000001-000000000001.manifest.fssc");
    assert!(manifest_file.is_file(), "local manifest not written");

    // 6. `fss archive restore` downloads from S3, decrypts, verifies, and writes restored `.fssp`!
    let mf = manifest_file.to_string_lossy().into_owned();
    let (code, rest_out, err) = run_fss(&[
        "archive",
        "restore",
        "--packs-dir",
        &rp,
        "--manifest-file",
        &mf,
        "--key-catalog",
        &kc,
        "--peer",
        &peer_str,
        "--host",
        "s3.local",
        "--bucket",
        "fss-cold-bucket",
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--kek-secret-id",
        "secret:kek:site-1",
        "--s3-secret-id",
        "secret:s3:cold-1",
        "--access-key-id",
        "AKIAIOSFODNN7EXAMPLE",
        "--site",
        "site:archive-e2e",
        "--json",
    ])?;
    assert_eq!(code, 0, "archive restore failed: {rest_out} {err}");
    let restored_pack = restore_packs_dir.join(PackId::new(1, 1).file_name());
    assert!(restored_pack.is_file());
    let orig_bytes = fs::read(
        dep_root
            .join("objects/packs")
            .join(PackId::new(1, 1).file_name()),
    )?;
    let restored_bytes = fs::read(&restored_pack)?;
    assert_eq!(
        orig_bytes, restored_bytes,
        "restored pack bytes must match original bit-for-bit"
    );

    // Recover after both the original plaintext pack and every local manifest have been lost.
    let upload = parse_json(&up_out)?;
    let remote_key = json_text(&upload, "manifest_object_key")?.to_owned();
    let manifest_pin = json_text(&upload, "manifest_digest")?.to_owned();
    fs::remove_dir_all(&manifests_dir)?;
    fs::remove_file(
        dep_root
            .join("objects/packs")
            .join(PackId::new(1, 1).file_name()),
    )?;
    fs::remove_file(&restored_pack)?;
    // The cold read audit uses only S3 credentials and the independent upload pin.
    // At this point the plaintext pack, restored copy, and local manifests are all absent.
    let audit_args = [
        "archive",
        "audit",
        "--manifest-object-key",
        &remote_key,
        "--expected-manifest",
        &manifest_pin,
        "--peer",
        &peer_str,
        "--host",
        "s3.local",
        "--bucket",
        "fss-cold-bucket",
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--s3-secret-id",
        "secret:s3:cold-1",
        "--access-key-id",
        "AKIAIOSFODNN7EXAMPLE",
        "--site",
        "site:archive-e2e",
        "--json",
    ];
    let (code, report, err) = run_fss(&audit_args)?;
    assert_eq!(code, 0, "{report} {err}");
    let report = parse_json(&report)?;
    let Value::Object(fields) = report else {
        return Err("expected audit response".into());
    };
    let audit = fields.get("audit").ok_or("missing cold audit receipt")?;
    assert_eq!(json_text(audit, "verdict")?, "verified");
    assert_eq!(json_text(audit, "manifest_digest")?, manifest_pin);
    let Value::Object(fields) = audit else {
        return Err("expected receipt object".into());
    };
    assert!(
        matches!(fields.get("sample_results"), Some(Value::Array(ranges)) if !ranges.is_empty())
    );
    assert!(!restored_pack.exists());

    let mut limited = audit_args.to_vec();
    limited.extend(["--max-download-bytes", "1"]);
    let (code, report, err) = run_fss(&limited)?;
    assert_ne!(code, 0, "{report} {err}");
    assert!(format!("{report}{err}").contains("download budget"));

    let pack_object = format!("/fss-cold-bucket/{}", json_text(&upload, "pack_object_key")?);
    let ciphertext = s3.objects.lock().map_err(|_| "lock poisoned")?
        .remove(&pack_object).ok_or("expected uploaded ciphertext")?;
    let (code, report, err) = run_fss(&audit_args)?;
    assert_ne!(code, 0, "{report} {err}");
    let body = if report.trim().is_empty() { &err } else { &report };
    let Value::Object(fields) = parse_json(body)? else {
        return Err("expected failed audit response".into());
    };
    let audit = fields.get("audit").ok_or("missing failure evidence")?;
    assert_eq!(json_text(audit, "verdict")?, "missing");
    s3.objects.lock().map_err(|_| "lock poisoned")?.insert(pack_object, ciphertext);

    let remote_args = [
        "archive",
        "restore",
        "--packs-dir",
        &rp,
        "--manifest-object-key",
        &remote_key,
        "--expected-manifest",
        &manifest_pin,
        "--key-catalog",
        &kc,
        "--peer",
        &peer_str,
        "--host",
        "s3.local",
        "--bucket",
        "fss-cold-bucket",
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--kek-secret-id",
        "secret:kek:site-1",
        "--s3-secret-id",
        "secret:s3:cold-1",
        "--access-key-id",
        "AKIAIOSFODNN7EXAMPLE",
        "--site",
        "site:archive-e2e",
        "--json",
    ];
    let pin_index = remote_args
        .iter()
        .position(|arg| *arg == "--expected-manifest")
        .ok_or("missing pin option")?
        + 1;
    let wrong_pin = ContentDigest::sha256(b"a different independently retained manifest").to_text();
    let mut wrong_args = remote_args;
    wrong_args[pin_index] = &wrong_pin;
    let (code, rejected, _) = run_fss(&wrong_args)?;
    assert_ne!(code, 0, "wrong root pin was accepted: {rejected}");
    assert!(!restored_pack.exists());

    let remote_path = format!("/fss-cold-bucket/{remote_key}");
    let remote_bytes = s3
        .objects
        .lock()
        .map_err(|_| "S3 lock poisoned")?
        .get(&remote_path)
        .ok_or("missing remote root")?
        .clone();
    let mut tampered = remote_bytes.clone();
    tampered[0] ^= 1;
    for bytes in [
        tampered,
        vec![0; fss_pack::MAX_COLD_MANIFEST_DOWNLOAD_BYTES + 1],
    ] {
        s3.objects
            .lock()
            .map_err(|_| "S3 lock poisoned")?
            .insert(remote_path.clone(), bytes);
        let (code, rejected, _) = run_fss(&remote_args)?;
        assert_ne!(code, 0, "invalid remote manifest was accepted: {rejected}");
        assert!(!restored_pack.exists());
    }
    s3.objects
        .lock()
        .map_err(|_| "S3 lock poisoned")?
        .remove(&remote_path);
    let (code, missing, _) = run_fss(&remote_args)?;
    assert_ne!(code, 0, "missing remote manifest was accepted: {missing}");
    assert!(!restored_pack.exists());

    let original_manifest = fss_pack::ColdPackArchiveManifest::from_canonical_bytes(&remote_bytes)?;
    let wrong_source = fss_pack::ColdPackArchiveManifest::build(
        original_manifest.pack_id,
        original_manifest.key_epoch,
        original_manifest.dek_id,
        original_manifest.wrapped_dek_digest,
        ContentDigest::sha256(b"incorrect original plaintext identity"),
        original_manifest.plaintext_bytes,
        original_manifest.ciphertext_sha256,
        original_manifest.ciphertext_bytes,
        original_manifest.object_key.clone(),
        original_manifest.etag.clone(),
        original_manifest.storage_tier,
        original_manifest.part_count,
        original_manifest.published_at_ns,
    )?;
    s3.objects
        .lock()
        .map_err(|_| "S3 lock poisoned")?
        .insert(remote_path.clone(), wrong_source.to_canonical_bytes()?);
    let wrong_source_pin = wrong_source.manifest_digest.to_text();
    let mut wrong_source_args = remote_args;
    wrong_source_args[pin_index] = &wrong_source_pin;
    let (code, rejected, _) = run_fss(&wrong_source_args)?;
    assert_ne!(
        code, 0,
        "incorrect plaintext identity was accepted: {rejected}"
    );
    assert!(rejected.contains("plaintext pack length or SHA-256"));
    assert!(!restored_pack.exists());

    s3.objects
        .lock()
        .map_err(|_| "S3 lock poisoned")?
        .insert(remote_path, remote_bytes);
    let (code, recovered_out, err) = run_fss(&remote_args)?;
    assert_eq!(
        code, 0,
        "remote-root recovery failed: {recovered_out} {err}"
    );
    let recovered = parse_json(&recovered_out)?;
    assert_eq!(json_text(&recovered, "manifest_source")?, "remote_object");
    assert_eq!(json_text(&recovered, "manifest_digest")?, manifest_pin);
    assert!(recovered_out.contains("\"manifest_pin_verified\":true"));
    assert_eq!(fs::read(&restored_pack)?, orig_bytes);
    assert!(!manifest_file.exists());

    // A retry after successful publication preserves the original file. A different pack
    // under the same logical ID (even the exact same length) must survive a refused restore.
    let retry_witness = restore_packs_dir.join("restore-retry-witness");
    fs::hard_link(&restored_pack, &retry_witness)?;
    let (code, retried, err) = run_fss(&remote_args)?;
    assert_eq!(code, 0, "identical restore retry failed: {retried} {err}");
    let mut conflicting = orig_bytes.clone();
    conflicting[0] ^= 1;
    fs::write(&retry_witness, &conflicting)?;
    assert_eq!(fs::read(&restored_pack)?, conflicting);
    let (code, refused, _) = run_fss(&remote_args)?;
    assert_ne!(code, 0, "restore overwrote an existing pack: {refused}");
    assert_eq!(fs::read(&restored_pack)?, conflicting);
    fs::remove_file(&retry_witness)?;

    // 7. `fss archive crypto-erase` preview -> approve -> signed erasure -> verify fails with ERR-CRYPTO-KEY-ERASED-001!
    let (code, ce_prev, err) = run_fss(&[
        "archive",
        "crypto-erase",
        "--key-catalog",
        &kc,
        "--dek-id",
        &local_dek_id,
        "--reason",
        "gdpr-erasure-e2e",
        "--site",
        "site:archive-e2e",
        "--json",
    ])?;
    assert_eq!(code, 0, "crypto-erase preview failed: {ce_prev} {err}");
    let ce_approval = json_text(&parse_json(&ce_prev)?, "approval_digest")?.to_owned();

    let (code, ce_out, err) = run_fss(&[
        "archive",
        "crypto-erase",
        "--key-catalog",
        &kc,
        "--dek-id",
        &local_dek_id,
        "--reason",
        "gdpr-erasure-e2e",
        "--approve",
        &ce_approval,
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--kek-secret-id",
        "secret:kek:site-1",
        "--site",
        "site:archive-e2e",
        "--json",
    ])?;
    assert_eq!(code, 0, "crypto-erase commit failed: {ce_out} {err}");
    assert!(ce_out.contains("\"cryptographic_erasure\":true"));
    assert!(ce_out.contains("\"signed_with_kek\":true"));

    // Post-erasure decrypt MUST fail closed with ERR-CRYPTO-KEY-ERASED-001!
    let (code, after_out, _) = run_fss(&[
        "archive",
        "verify",
        "--pack-id",
        "1:1",
        "--enc-file",
        &ef,
        "--key-catalog",
        &kc,
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--kek-secret-id",
        "secret:kek:site-1",
        "--site",
        "site:archive-e2e",
        "--json",
    ])?;
    assert_ne!(code, 0);
    assert!(
        after_out.contains("ERR-CRYPTO-KEY-ERASED-001"),
        "expected ERR-CRYPTO-KEY-ERASED-001 after erasure, got: {after_out}"
    );

    // A verified remote root cannot revive an archived DEK that the current catalog erased.
    let archive_dek = json_text(&upload, "dek_id")?;
    let erase_args = [
        "archive",
        "crypto-erase",
        "--key-catalog",
        &kc,
        "--dek-id",
        archive_dek,
        "--reason",
        "remote-recovery-erasure",
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--kek-secret-id",
        "secret:kek:site-1",
        "--site",
        "site:archive-e2e",
        "--json",
    ];
    let (code, preview, err) = run_fss(&erase_args)?;
    assert_eq!(
        code, 0,
        "archived DEK erasure preview failed: {preview} {err}"
    );
    let approval = json_text(&parse_json(&preview)?, "approval_digest")?.to_owned();
    let mut approved_erasure = erase_args.to_vec();
    approved_erasure.extend(["--approve", &approval]);
    assert_eq!(run_fss(&approved_erasure)?.0, 0);
    fs::remove_file(&restored_pack)?;
    let (code, erased, _) = run_fss(&remote_args)?;
    assert_ne!(code, 0);
    assert!(erased.contains("ERR-CRYPTO-KEY-ERASED-001"), "{erased}");
    assert!(!restored_pack.exists());

    Ok(())
}

fn encode_basic_header_value(user: &str, pass: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let raw = format!("{user}:{pass}").into_bytes();
    let mut out = String::with_capacity(raw.len().div_ceil(3) * 4);
    let mut i = 0;
    while i < raw.len() {
        let b0 = raw[i];
        let b1 = if i + 1 < raw.len() { raw[i + 1] } else { 0 };
        let b2 = if i + 2 < raw.len() { raw[i + 2] } else { 0 };
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if i + 1 < raw.len() {
            TABLE[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if i + 2 < raw.len() {
            TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
        i += 3;
    }
    format!("Basic {out}")
}

#[test]
fn fss_site_run_authenticates_http_mjpeg_camera_from_vault_with_zero_canary_leaks() -> TestResult {
    let dir = TempDirGuard::new("site-run-vault")?;
    let deploy_root = dir.path().join("deploy");
    let vault_dir = dir.path().join("vault");
    let pass_file = dir.path().join("pass.key");
    let cam_cred_file = dir.path().join("cam-cred.key");
    let manifest_file = dir.path().join("site.json");

    let pass_canary = "CANARY-DAEMON-VAULT-PASS-918273!";
    let cam_pass_canary = "CANARY-CAMERA-BASIC-PASS-556677!";
    let cam_user = "fssoperator";
    write_secret_0600(&pass_file, pass_canary.as_bytes())?;
    write_secret_0600(
        &cam_cred_file,
        format!("{cam_user}:{cam_pass_canary}").as_bytes(),
    )?;

    let mut scanner = CanaryLeakScanner::new();
    scanner.register_bytes("daemon_vault_passphrase", pass_canary.as_bytes())?;
    scanner.register_bytes("camera_basic_password", cam_pass_canary.as_bytes())?;

    let expected_auth = encode_basic_header_value(cam_user, cam_pass_canary);
    let jpeg_bytes = include_bytes!("fixtures/retained_file_8x8.jpg").to_vec();

    // Real loopback HTTP/1.1 Basic-Auth multipart MJPEG camera server.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let auth_hits = Arc::new(AtomicUsize::new(0));
    let unauth_hits = Arc::new(AtomicUsize::new(0));
    let stop_bg = Arc::clone(&stop);
    let auth_hits_bg = Arc::clone(&auth_hits);
    let unauth_hits_bg = Arc::clone(&unauth_hits);
    let srv = thread::spawn(move || {
        while !stop_bg.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut s, _)) => {
                    let _ = s.set_nonblocking(false);
                    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                    let mut buf = [0_u8; 4096];
                    if let Ok(n) = s.read(&mut buf)
                        && n > 0
                    {
                        let head = String::from_utf8_lossy(&buf[..n]);
                        let authed = head.lines().any(|line| {
                            line.split_once(':').is_some_and(|(k, v)| {
                                k.eq_ignore_ascii_case("authorization") && v.trim() == expected_auth
                            })
                        });
                        if !authed {
                            unauth_hits_bg.fetch_add(1, Ordering::SeqCst);
                            let _ = s.write_all(
                                b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"cam\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            );
                        } else {
                            auth_hits_bg.fetch_add(1, Ordering::SeqCst);
                            let _ = s.write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=frame\r\n\r\n",
                            );
                            for _ in 0..6 {
                                let part_hdr = format!(
                                    "--frame\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n",
                                    jpeg_bytes.len()
                                );
                                if s.write_all(part_hdr.as_bytes()).is_err()
                                    || s.write_all(&jpeg_bytes).is_err()
                                    || s.write_all(b"\r\n").is_err()
                                {
                                    break;
                                }
                                let _ = s.flush();
                                thread::sleep(Duration::from_millis(10));
                            }
                        }
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    let endpoint = format!("http://{addr}/mjpeg");
    let vd = vault_dir.to_string_lossy().into_owned();
    let pf = pass_file.to_string_lossy().into_owned();
    let cf = cam_cred_file.to_string_lossy().into_owned();
    let dr = deploy_root.to_string_lossy().into_owned();
    let mf = manifest_file.to_string_lossy().into_owned();

    // 1. Store camera Basic-Auth credential in fss-vault scoped strictly to this ONVIF/HTTP endpoint.
    assert_eq!(
        run_fss(&[
            "vault",
            "init",
            "--vault-dir",
            &vd,
            "--passphrase-file",
            &pf,
            "--json",
        ])?
        .0,
        0
    );
    let (code, set_out, set_err) = run_fss(&[
        "vault",
        "set",
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--secret-file",
        &cf,
        "--secret-id",
        "secret:cam:auth-http-1",
        "--family",
        "onvif",
        "--target",
        "sensor:cam-auth-1",
        "--endpoint",
        &endpoint,
        "--json",
    ])?;
    assert_eq!(code, 0, "vault set camera cred failed: {set_out} {set_err}");
    scanner.assert_clean("vault set stdout", set_out.as_bytes())?;

    // 2. Write secret-free site.json referencing ONLY the opaque vault secret_id handle.
    let manifest_json = format!(
        r#"{{
  "schema": "fss.site_manifest.v1",
  "site_id": "site:vault-auth-e2e",
  "deployment_root": "{}",
  "gop_frames": 2,
  "cameras": [
    {{
      "sensor_id": "sensor:cam-auth-1",
      "adapter": "onvif_http",
      "endpoint": "{}",
      "secret_id": "secret:cam:auth-http-1",
      "primary_zone": "zone:driveway",
      "dimensions": [8, 8],
      "failure_domain": "poe:switch-1"
    }}
  ]
}}"#,
        dr.replace('\\', "\\\\"),
        endpoint
    );
    fs::write(&manifest_file, &manifest_json)?;
    scanner.assert_clean("site.json", manifest_json.as_bytes())?;

    // 3. Plaintext --passphrase on CLI argv MUST fail closed.
    let (code, bad_out, bad_err) = run_fss(&[
        "site",
        "run",
        "--manifest",
        &mf,
        "--root",
        &dr,
        "--vault-dir",
        &vd,
        "--passphrase",
        "never-allow-argv-secret",
        "--once-ticks",
        "1",
        "--json",
    ])?;
    assert_ne!(
        code, 0,
        "argv passphrase must be refused: {bad_out} {bad_err}"
    );

    // 4. Real `fss site run` unlocks vault, attaches credentials, authenticates HTTP MJPEG,
    //    decodes real JPEG pixels, commits v2 packfile/MVCC batches, and shuts down cleanly!
    let (code, run_out, run_err) = run_fss(&[
        "site",
        "run",
        "--manifest",
        &mf,
        "--root",
        &dr,
        "--vault-dir",
        &vd,
        "--passphrase-file",
        &pf,
        "--once-ticks",
        "10",
        "--tick-ms",
        "20",
        "--json",
    ])?;
    stop.store(true, Ordering::Relaxed);
    let _ = srv.join();

    assert_eq!(
        code, 0,
        "fss site run failed: stdout={run_out} stderr={run_err}"
    );
    assert!(
        auth_hits.load(Ordering::SeqCst) >= 1,
        "camera server must receive authenticated Basic-Auth request from vault"
    );
    assert_eq!(
        unauth_hits.load(Ordering::SeqCst),
        0,
        "camera server must not see unauthenticated requests when vault is wired"
    );
    let run_json = parse_json(&run_out)?;
    assert_eq!(
        run_json
            .object()
            .and_then(|m| m.get("active_tasks"))
            .and_then(Value::integer),
        Some(0)
    );
    assert_eq!(
        run_json
            .object()
            .and_then(|m| m.get("leaked_obligations"))
            .and_then(Value::integer),
        Some(0)
    );
    assert!(
        run_json
            .object()
            .and_then(|m| m.get("head_commit_sequence"))
            .and_then(Value::integer)
            .unwrap_or(0)
            >= 2,
        "expected committed media & coverage batches from authenticated camera: {run_out}"
    );
    scanner.assert_clean("fss site run stdout", run_out.as_bytes())?;
    scanner.assert_clean("fss site run stderr", run_err.as_bytes())?;

    // 5. Resulting v2 root passes `fss doctor --json --root <dep>` healthy!
    let (doc_code, doc_out, doc_err) = run_fss(&["doctor", "--json", "--root", &dr])?;
    assert_eq!(doc_code, 0, "fss doctor failed: {doc_out} {doc_err}");
    assert!(
        doc_out.contains("\"verdict\":\"healthy\""),
        "doctor={doc_out}"
    );
    assert!(doc_out.contains("\"format_version\":2"), "doctor={doc_out}");
    scanner.assert_clean("fss doctor stdout", doc_out.as_bytes())?;

    Ok(())
}

#[test]
fn remote_archive_restore_refuses_ambiguous_or_unpinned_modes_before_io() -> TestResult {
    let valid = ContentDigest::sha256(b"trusted upload manifest identity").to_text();
    let zero = format!("sha256:{}", "0".repeat(64));
    let blake = format!("blake3:{}", "1".repeat(64));
    for flags in [
        vec!["--manifest-object-key", "remote/root"],
        vec!["--expected-manifest", valid.as_str()],
        vec![
            "--manifest-file",
            "/absent/local",
            "--manifest-object-key",
            "remote/root",
            "--expected-manifest",
            valid.as_str(),
        ],
        vec![
            "--manifest-object-key",
            "remote/root",
            "--expected-manifest",
            zero.as_str(),
        ],
        vec![
            "--manifest-object-key",
            "remote/root",
            "--expected-manifest",
            blake.as_str(),
        ],
        vec![
            "--manifest-object-key",
            "remote/root",
            "--manifest-object-key",
            "other/root",
            "--expected-manifest",
            valid.as_str(),
        ],
        vec![
            "--manifest-object-key",
            "remote/root",
            "--expected-manifest",
            valid.as_str(),
            "--expected-manifest",
            valid.as_str(),
        ],
    ] {
        let mut args = vec!["archive", "restore", "--packs-dir", "/absent/destination"];
        args.extend(flags);
        let (code, stdout, _) = run_fss(&args)?;
        assert_ne!(code, 0);
        assert!(stdout.contains("ERR-CLI-MALFORMED-VALUE-001"), "{stdout}");
    }
    Ok(())
}
