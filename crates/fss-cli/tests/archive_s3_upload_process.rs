#![forbid(unsafe_code)]
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
//! Actual-process native S3 upload and cold journal reuse against a bounded loopback oracle.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;
use fss_object::uploader::{CompletionObservationOutcome, CompletionObservationReceipt};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const BODY: &[u8] = b"owner supplied archive object";
const SECRET: &str = "loopback-only-test-secret";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-native-s3-process-{label}-{}-{attempt}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                    fs::write(path.join("source"), BODY)?;
                    fs::write(
                        path.join("credentials"),
                        format!("FSS_TEST_ACCESS\n{SECRET}\n"),
                    )?;
                    fs::set_permissions(
                        path.join("credentials"),
                        fs::Permissions::from_mode(0o600),
                    )?;
                    return Ok(Self(path));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn arguments(directory: &Directory, peer: SocketAddr, command: &str) -> Test<Vec<String>> {
    let deadline = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() + 120_000_000_000;
    let mut args = vec![command.to_owned()];
    for (key, value) in [
        ("--source", directory.0.join("source").display().to_string()),
        ("--source-sha256", ContentDigest::sha256(BODY).to_text()),
        ("--source-bytes", BODY.len().to_string()),
        (
            "--journal",
            directory.0.join("journal").display().to_string(),
        ),
        ("--peer", peer.to_string()),
        ("--host", peer.to_string()),
        ("--region", "us-east-1".into()),
        ("--bucket", "test-archive".into()),
        ("--key", "object.bin".into()),
        (
            "--credentials",
            directory.0.join("credentials").display().to_string(),
        ),
        (
            "--plaintext-approval",
            ContentDigest::sha256(b"approved loopback test").to_text(),
        ),
        ("--operation", "operation:native-s3-process".into()),
        ("--deadline-ns", deadline.to_string()),
        ("--max-memory-bytes", (256_u64 * 1024 * 1024).to_string()),
        ("--max-wire-bytes", (64_u64 * 1024 * 1024).to_string()),
        ("--max-requests", "32".into()),
        ("--max-local-bytes", (256_u64 * 1024 * 1024).to_string()),
        ("--max-local-operations", "200000".into()),
    ] {
        args.push(key.to_owned());
        args.push(value);
    }
    Ok(args)
}

fn run(args: &[String]) -> Test<Output> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fss-archive"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if child.try_wait()?.is_some() {
            return Ok(child.wait_with_output()?);
        }
        if Instant::now() >= deadline {
            child.kill()?;
            let _ = child.wait();
            return Err("archive process exceeded its test deadline".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn fields(output: &Output) -> Test<BTreeMap<String, Value>> {
    let text = std::str::from_utf8(&output.stdout)?;
    assert!(!text.contains(SECRET), "secret in report");
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains(SECRET),
        "secret in diagnostic"
    );
    let value = parse(text)?;
    Ok(value.object().ok_or("report is not an object")?.clone())
}

fn with_pin(
    mut args: Vec<String>,
    preparation: &BTreeMap<String, Value>,
    command: &str,
) -> Test<Vec<String>> {
    args[0] = command.into();
    args.extend([
        "--minimum-sequence".into(),
        preparation
            .get("journal_sequence")
            .and_then(Value::integer)
            .ok_or("journal sequence absent")?
            .to_string(),
        "--minimum-root".into(),
        preparation
            .get("journal_head")
            .and_then(Value::text)
            .ok_or("journal pin absent")?
            .to_owned(),
    ]);
    Ok(args)
}

fn observation_arguments(
    resume: &[String],
    directory: &Directory,
    label: &str,
) -> Test<Vec<String>> {
    let mut args = resume.to_vec();
    args[0] = "upload-s3-reconcile".into();
    let deadline = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() + 180_000_000_000;
    for (name, value) in [
        ("--deadline-ns", deadline.to_string()),
        ("--max-memory-bytes", (16_u64 * 1024 * 1024).to_string()),
        ("--max-wire-bytes", (2_u64 * 1024 * 1024).to_string()),
        ("--max-requests", "1".into()),
    ] {
        let index = args
            .iter()
            .position(|argument| argument == name)
            .ok_or("observation argument")?
            + 1;
        args[index] = value;
    }
    args.extend([
        "--observation-operation".into(),
        format!("operation:independent-completion-observation:{label}"),
        "--observation-receipt".into(),
        directory
            .0
            .join(format!("observation-{label}.bin"))
            .display()
            .to_string(),
    ]);
    Ok(args)
}

fn journal_bytes(directory: &Directory) -> Test<BTreeMap<PathBuf, Vec<u8>>> {
    let root = directory.0.join("journal");
    let mut pending = vec![root.clone()];
    let mut result = BTreeMap::new();
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                result.insert(
                    entry.path().strip_prefix(&root)?.to_owned(),
                    fs::read(entry.path())?,
                );
            } else {
                return Err("unexpected journal fixture entry".into());
            }
            if result.len() + pending.len() > 65_536 {
                return Err("fixture journal inventory bound".into());
            }
        }
    }
    Ok(result)
}

fn b64(bytes: &[u8]) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        result.push(alphabet[usize::from(a >> 2)] as char);
        result.push(alphabet[usize::from(((a & 3) << 4) | (b >> 4))] as char);
        result.push(if chunk.len() > 1 {
            alphabet[usize::from(((b & 15) << 2) | (c >> 6))] as char
        } else {
            '='
        });
        result.push(if chunk.len() > 2 {
            alphabet[usize::from(c & 63)] as char
        } else {
            '='
        });
    }
    result
}

#[derive(Debug)]
struct Request {
    first: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}
fn request(stream: &mut TcpStream) -> Result<Request, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    let end = loop {
        let read = stream.read(&mut chunk).map_err(|e| e.to_string())?;
        if read == 0 {
            return Err("truncated request head".into());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break end + 4;
        }
        if bytes.len() > 16 * 1024 {
            return Err("request header bound".into());
        }
    };
    let head = std::str::from_utf8(&bytes[..end]).map_err(|e| e.to_string())?;
    let mut lines = head.split("\r\n");
    let first = lines.next().ok_or("missing request line")?.to_owned();
    let mut headers = BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or("malformed request header")?;
        if headers
            .insert(name.to_ascii_lowercase(), value.trim().to_owned())
            .is_some()
        {
            return Err("duplicate request header".into());
        }
    }
    let length: usize = headers
        .get("content-length")
        .ok_or("missing body length")?
        .parse()
        .map_err(|_| "invalid body length")?;
    if length > 16 * 1024 {
        return Err("request body bound".into());
    }
    while bytes.len() - end < length {
        let read = stream.read(&mut chunk).map_err(|e| e.to_string())?;
        if read == 0 {
            return Err("truncated request body".into());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() - end > length {
            return Err("unexpected request suffix".into());
        }
    }
    Ok(Request {
        first,
        headers,
        body: bytes[end..].to_vec(),
    })
}

struct Server {
    peer: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<Vec<Request>, String>>>,
}
#[derive(Clone, Copy)]
enum HeadOutcome {
    Completed,
    Absent,
    WrongChecksum,
    WrongIntent,
    WrongOrigin,
}
impl Server {
    fn new(fail_completion: bool) -> Test<Self> {
        Self::configured(fail_completion, false, None)
    }

    fn lost_completion(outcome: HeadOutcome) -> Test<Self> {
        Self::configured(false, true, Some(outcome))
    }

    fn configured(
        fail_completion: bool,
        lose_completion: bool,
        observation: Option<HeadOutcome>,
    ) -> Test<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let peer = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let cancelled = stop.clone();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(25);
            let mut received = Vec::new();
            let expected_requests = if observation.is_some() { 4 } else { 3 };
            while received.len() < expected_requests {
                if cancelled.load(Ordering::SeqCst) {
                    return Err("oracle stopped".into());
                }
                if Instant::now() >= deadline {
                    return Err("oracle accept deadline".into());
                }
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => return Err(error.to_string()),
                };
                let request = request(&mut stream)?;
                if !request
                    .headers
                    .get("authorization")
                    .is_some_and(|value| value.starts_with("AWS4-HMAC-SHA256 "))
                {
                    return Err("SigV4 authorization absent".into());
                }
                if request.headers.values().any(|value| value.contains(SECRET)) {
                    return Err("raw secret key on wire".into());
                }
                if request.headers.get("x-amz-content-sha256")
                    != Some(&ContentDigest::sha256(&request.body).to_text()[7..].to_owned())
                {
                    return Err("signed body digest mismatch".into());
                }
                if received.len() == 3 {
                    if request.first != "HEAD /test-archive/object.bin HTTP/1.1"
                        || !request.body.is_empty()
                        || request
                            .headers
                            .get("x-amz-checksum-mode")
                            .map(String::as_str)
                            != Some("ENABLED")
                    {
                        return Err("reconciliation was not an exact checksum-enabled HEAD".into());
                    }
                    let outcome = observation.ok_or("unexpected observation")?;
                    let head = if matches!(outcome, HeadOutcome::Absent) {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .into()
                    } else {
                        let original: &Request = received.first().ok_or("initiation absent")?;
                        let checksum = if matches!(outcome, HeadOutcome::WrongChecksum) {
                            b64(&ContentDigest::sha256(b"other composite").bytes())
                        } else {
                            b64(&ContentDigest::sha256(&ContentDigest::sha256(BODY).bytes())
                                .bytes())
                        };
                        let mut metadata = String::new();
                        for name in [
                            "x-amz-meta-fss-intent",
                            "x-amz-meta-fss-plan",
                            "x-amz-meta-fss-root",
                            "x-amz-meta-fss-origin",
                        ] {
                            let value = if name == "x-amz-meta-fss-intent"
                                && matches!(outcome, HeadOutcome::WrongIntent)
                            {
                                ContentDigest::sha256(b"other intent").to_text()[7..].to_owned()
                            } else if name == "x-amz-meta-fss-origin"
                                && matches!(outcome, HeadOutcome::WrongOrigin)
                            {
                                ContentDigest::sha256(b"another journal's earlier object").to_text()
                                    [7..]
                                    .to_owned()
                            } else {
                                original
                                    .headers
                                    .get(name)
                                    .ok_or("original metadata absent")?
                                    .clone()
                            };
                            metadata.push_str(&format!("{name}: {value}\r\n"));
                        }
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"opaque-completed-object\"\r\nx-amz-checksum-sha256: {checksum}-1\r\nx-amz-checksum-type: COMPOSITE\r\n{metadata}Connection: close\r\n\r\n",
                            BODY.len()
                        )
                    };
                    stream
                        .write_all(head.as_bytes())
                        .map_err(|e| e.to_string())?;
                    received.push(request);
                    continue;
                }
                let (headers, body) = match received.len() {
                    0 => {
                        if request.first != "POST /test-archive/object.bin?uploads= HTTP/1.1" {
                            return Err("unexpected initiation target".into());
                        }
                        if request
                            .headers
                            .get("x-amz-checksum-algorithm")
                            .map(String::as_str)
                            != Some("SHA256")
                        {
                            return Err("checksum algorithm not initiated".into());
                        }
                        ("", "<InitiateMultipartUploadResult><Bucket>test-archive</Bucket><Key>object.bin</Key><UploadId>fixture-upload</UploadId></InitiateMultipartUploadResult>".to_owned())
                    }
                    1 => {
                        if !request.first.starts_with("PUT ") || request.body != BODY {
                            return Err("source bytes or part method changed".into());
                        }
                        let checksum = b64(&ContentDigest::sha256(BODY).bytes());
                        if request.headers.get("x-amz-checksum-sha256") != Some(&checksum) {
                            return Err("independent part checksum absent".into());
                        }
                        received.push(request);
                        let head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nETag: \"opaque-part-token\"\r\nx-amz-checksum-sha256: {checksum}\r\nConnection: close\r\n\r\n"
                        );
                        stream
                            .write_all(head.as_bytes())
                            .map_err(|e| e.to_string())?;
                        continue;
                    }
                    _ => {
                        if request.headers.get("if-none-match").map(String::as_str) != Some("*") {
                            return Err("completion could overwrite".into());
                        }
                        let body = String::from_utf8_lossy(&request.body);
                        if !body.contains("<PartNumber>1</PartNumber>")
                            || !body.contains("opaque-part-token")
                        {
                            return Err("completion omitted exact part".into());
                        }
                        if fail_completion {
                            ("", "<Error><Code>InternalError</Code><Message>fixture failure</Message></Error>".into())
                        } else {
                            let composite =
                                b64(&ContentDigest::sha256(&ContentDigest::sha256(BODY).bytes())
                                    .bytes());
                            (
                                "",
                                format!(
                                    "<CompleteMultipartUploadResult><Bucket>test-archive</Bucket><Key>object.bin</Key><ETag>opaque-final-token</ETag><ChecksumSHA256>{composite}-1</ChecksumSHA256><ChecksumType>COMPOSITE</ChecksumType></CompleteMultipartUploadResult>"
                                ),
                            )
                        }
                    }
                };
                if lose_completion && received.len() == 2 {
                    // Provider commits, then closes without acknowledging the request.
                    received.push(request);
                    continue;
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n",
                    body.len()
                );
                stream
                    .write_all(head.as_bytes())
                    .and_then(|()| stream.write_all(body.as_bytes()))
                    .map_err(|e| e.to_string())?;
                received.push(request);
            }
            Ok(received)
        });
        Ok(Self {
            peer,
            stop,
            worker: Some(worker),
        })
    }
    fn finish(mut self) -> Test<Vec<Request>> {
        self.worker
            .take()
            .ok_or("oracle worker absent")?
            .join()
            .map_err(|_| "oracle worker panicked")?
            .map_err(Into::into)
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn complete_real_upload_then_cold_status_needs_neither_source_nor_credentials() -> Test {
    let directory = Directory::new("complete")?;
    let server = Server::new(false)?;
    let args = arguments(&directory, server.peer, "upload-s3-prepare")?;
    let prepared = run(&args)?;
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    let prepared = fields(&prepared)?;
    assert_eq!(
        prepared.get("phase").and_then(Value::text),
        Some("prepared")
    );
    let resume = with_pin(args, &prepared, "upload-s3-resume")?;
    let completed = run(&resume)?;
    assert!(
        completed.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&completed.stdout),
        String::from_utf8_lossy(&completed.stderr)
    );
    let completed = fields(&completed)?;
    assert_eq!(
        completed.get("phase").and_then(Value::text),
        Some("completed")
    );
    assert_eq!(completed.get("locally_settled"), Some(&Value::Bool(true)));
    assert_eq!(
        completed.get("independent_retrievability_verified"),
        Some(&Value::Bool(false))
    );
    assert_eq!(server.finish()?.len(), 3);
    fs::remove_file(directory.0.join("source"))?;
    fs::remove_file(directory.0.join("credentials"))?;
    let cold = run(&resume)?;
    assert!(
        cold.status.success(),
        "{}",
        String::from_utf8_lossy(&cold.stderr)
    );
    let cold = fields(&cold)?;
    assert_eq!(cold.get("phase").and_then(Value::text), Some("completed"));
    assert_eq!(
        cold.get("source_verified_this_invocation"),
        Some(&Value::Bool(false))
    );
    assert_eq!(
        cold.get("provider_work_requested_this_invocation"),
        Some(&Value::Bool(false))
    );
    Ok(())
}

#[test]
fn embedded_200_error_remains_indeterminate_and_cold_retry_does_not_touch_provider() -> Test {
    let directory = Directory::new("uncertain")?;
    let server = Server::new(true)?;
    let args = arguments(&directory, server.peer, "upload-s3-prepare")?;
    let prepared = run(&args)?;
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    let resume = with_pin(args, &fields(&prepared)?, "upload-s3-resume")?;
    let failed = run(&resume)?;
    assert!(!failed.status.success());
    let report = fields(&failed)?;
    assert_eq!(report.get("phase").and_then(Value::text), Some("uncertain"));
    assert_eq!(
        report.get("uncertain_operation").and_then(Value::text),
        Some("complete")
    );
    assert_eq!(report.get("locally_settled"), Some(&Value::Bool(true)));
    assert_eq!(server.finish()?.len(), 3);
    fs::remove_file(directory.0.join("source"))?;
    fs::remove_file(directory.0.join("credentials"))?;
    let cold = run(&resume)?;
    assert!(!cold.status.success());
    let cold = fields(&cold)?;
    assert_eq!(cold.get("phase").and_then(Value::text), Some("uncertain"));
    assert_eq!(
        cold.get("provider_work_requested_this_invocation"),
        Some(&Value::Bool(false))
    );
    Ok(())
}

#[test]
fn wrong_source_digest_and_missing_pin_refuse_before_initial_journal_creation() -> Test {
    let directory = Directory::new("source-refusal")?;
    let mut args = arguments(&directory, "127.0.0.1:1".parse()?, "upload-s3-prepare")?;
    let index = args
        .iter()
        .position(|value| value == "--source-sha256")
        .ok_or("digest argument")?
        + 1;
    args[index] = ContentDigest::sha256(b"different expected source").to_text();
    let refused = run(&args)?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert!(!directory.0.join("journal").exists());
    args[0] = "upload-s3-resume".into();
    let refused = run(&args)?;
    assert_eq!(refused.status.code(), Some(64));
    assert!(refused.stdout.is_empty());
    assert!(!directory.0.join("journal").exists());
    Ok(())
}

#[test]
fn prepared_abort_requires_no_source_or_credentials_and_preserves_terminal_pin() -> Test {
    let directory = Directory::new("prepared-abort")?;
    let args = arguments(&directory, "127.0.0.1:1".parse()?, "upload-s3-prepare")?;
    let prepared = run(&args)?;
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    let abort = with_pin(args, &fields(&prepared)?, "upload-s3-abort")?;
    fs::remove_file(directory.0.join("source"))?;
    fs::remove_file(directory.0.join("credentials"))?;
    let aborted = run(&abort)?;
    assert!(
        aborted.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&aborted.stdout),
        String::from_utf8_lossy(&aborted.stderr)
    );
    let report = fields(&aborted)?;
    assert_eq!(report.get("phase").and_then(Value::text), Some("aborted"));
    assert_eq!(report.get("locally_settled"), Some(&Value::Bool(true)));
    assert_eq!(
        report.get("provider_work_requested_this_invocation"),
        Some(&Value::Bool(false))
    );
    let repeated = run(&abort)?;
    assert!(repeated.status.success());
    Ok(())
}

#[test]
fn lost_completion_is_observed_after_restart_without_source_or_old_owner_mutation() -> Test {
    let directory = Directory::new("observe-complete")?;
    let server = Server::lost_completion(HeadOutcome::Completed)?;
    let args = arguments(&directory, server.peer, "upload-s3-prepare")?;
    let prepared = run(&args)?;
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    let resume = with_pin(args, &fields(&prepared)?, "upload-s3-resume")?;
    let failed = run(&resume)?;
    assert!(!failed.status.success());
    let failed = fields(&failed)?;
    assert_eq!(
        failed.get("uncertain_operation").and_then(Value::text),
        Some("complete")
    );
    assert_eq!(failed.get("locally_settled"), Some(&Value::Bool(true)));
    let before = journal_bytes(&directory)?;
    fs::remove_file(directory.0.join("source"))?;
    let observation = observation_arguments(&resume, &directory, "complete")?;
    let output = run(&observation)?;
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = fields(&output)?;
    assert_eq!(
        report.get("schema").and_then(Value::text),
        Some("fss.s3_completion_observation_cli.v1")
    );
    assert_eq!(
        report.get("observation_outcome").and_then(Value::text),
        Some("completed")
    );
    assert_eq!(
        report
            .get("original_local_owner_state")
            .and_then(Value::text),
        Some("indeterminate")
    );
    assert_eq!(
        report.get("observation_receipt_durable"),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        report.get("source_verified_this_invocation"),
        Some(&Value::Bool(false))
    );
    assert_eq!(
        report.get("independent_retrievability_verified"),
        Some(&Value::Bool(false))
    );
    assert_eq!(
        report.get("original_upload_consumed"),
        failed.get("upload_consumed")
    );
    assert_eq!(
        report.get("original_upload_remaining"),
        failed.get("upload_remaining")
    );
    assert_eq!(
        report.get("original_indeterminate_receipt_digest"),
        failed.get("receipt_digest")
    );
    let receipt_path = directory.0.join("observation-complete.bin");
    let canonical = fs::read(&receipt_path)?;
    let receipt = CompletionObservationReceipt::decode(&canonical)?;
    assert_eq!(receipt.outcome(), CompletionObservationOutcome::Completed);
    assert_eq!(receipt.consumed().storage_operations, 1);
    assert_eq!(receipt.budget().storage_operations, 1);
    assert_eq!(
        report
            .get("observation_receipt_digest")
            .and_then(Value::text),
        Some(receipt.digest()?.to_text().as_str())
    );
    assert_eq!(
        report.get("source_journal_head"),
        failed.get("journal_head")
    );
    assert_eq!(fs::metadata(&receipt_path)?.permissions().mode() & 0o077, 0);
    assert_eq!(journal_bytes(&directory)?, before);
    let requests = server.finish()?;
    assert_eq!(requests.len(), 4);
    assert!(
        requests
            .last()
            .ok_or("HEAD request absent")?
            .first
            .starts_with("HEAD ")
    );
    fs::remove_file(directory.0.join("credentials"))?;
    let repeated = run(&observation)?;
    assert!(!repeated.status.success());
    assert!(repeated.stdout.is_empty());
    assert_eq!(fs::read(&receipt_path)?, canonical);
    // The old mutation command still reports its historical indeterminate owner.
    let old_status = run(&resume)?;
    assert!(!old_status.status.success());
    let old_status = fields(&old_status)?;
    assert_eq!(
        old_status.get("phase").and_then(Value::text),
        Some("uncertain")
    );
    assert_eq!(
        old_status.get("provider_work_requested_this_invocation"),
        Some(&Value::Bool(false))
    );
    assert_eq!(journal_bytes(&directory)?, before);
    Ok(())
}

#[test]
fn missing_or_conflicting_object_retains_unknown_in_a_separate_durable_receipt() -> Test {
    for (label, outcome) in [
        ("absent", HeadOutcome::Absent),
        ("checksum", HeadOutcome::WrongChecksum),
        ("intent", HeadOutcome::WrongIntent),
        ("origin", HeadOutcome::WrongOrigin),
    ] {
        let directory = Directory::new(label)?;
        let server = Server::lost_completion(outcome)?;
        let args = arguments(&directory, server.peer, "upload-s3-prepare")?;
        let prepared = run(&args)?;
        assert!(
            prepared.status.success(),
            "{}",
            String::from_utf8_lossy(&prepared.stderr)
        );
        let resume = with_pin(args, &fields(&prepared)?, "upload-s3-resume")?;
        let failed = run(&resume)?;
        assert!(!failed.status.success());
        let before = journal_bytes(&directory)?;
        fs::remove_file(directory.0.join("source"))?;
        let observation = observation_arguments(&resume, &directory, label)?;
        let output = run(&observation)?;
        assert!(!output.status.success());
        let report = fields(&output)?;
        assert_eq!(
            report.get("observation_outcome").and_then(Value::text),
            Some("unknown"),
            "{label}"
        );
        assert_eq!(
            report.get("observation_receipt_durable"),
            Some(&Value::Bool(true))
        );
        assert_eq!(report.get("completion_receipt_digest"), Some(&Value::Null));
        let receipt = CompletionObservationReceipt::decode(&fs::read(
            directory.0.join(format!("observation-{label}.bin")),
        )?)?;
        assert_eq!(receipt.outcome(), CompletionObservationOutcome::Unknown);
        assert_eq!(receipt.consumed().storage_operations, 1);
        assert_eq!(journal_bytes(&directory)?, before);
        assert_eq!(server.finish()?.len(), 4);
    }
    Ok(())
}

#[test]
fn reconciliation_rejects_wrong_intent_operation_pin_or_deadline_before_secret_access() -> Test {
    let directory = Directory::new("observe-refusal")?;
    let server = Server::new(true)?;
    let args = arguments(&directory, server.peer, "upload-s3-prepare")?;
    let prepared = run(&args)?;
    assert!(prepared.status.success());
    let resume = with_pin(args, &fields(&prepared)?, "upload-s3-resume")?;
    assert!(!run(&resume)?.status.success());
    assert_eq!(server.finish()?.len(), 3);
    fs::remove_file(directory.0.join("source"))?;
    fs::remove_file(directory.0.join("credentials"))?;
    let before = journal_bytes(&directory)?;
    for (name, value) in [
        (
            "--source-sha256",
            ContentDigest::sha256(b"another source").to_text(),
        ),
        (
            "--minimum-root",
            ContentDigest::sha256(b"unretained root").to_text(),
        ),
        (
            "--observation-operation",
            "operation:native-s3-process".into(),
        ),
        ("--deadline-ns", "1".into()),
    ] {
        let mut observation = observation_arguments(&resume, &directory, "refused")?;
        let index = observation
            .iter()
            .position(|argument| argument == name)
            .ok_or("test argument")?
            + 1;
        observation[index] = value;
        let output = run(&observation)?;
        assert!(!output.status.success(), "{name}");
        assert!(output.stdout.is_empty(), "{name}");
        assert!(!directory.0.join("observation-refused.bin").exists());
        assert_eq!(journal_bytes(&directory)?, before);
    }
    Ok(())
}

#[test]
fn missing_observation_secret_records_not_observed_without_reopening_upload() -> Test {
    let directory = Directory::new("observe-no-secret")?;
    let server = Server::new(true)?;
    let args = arguments(&directory, server.peer, "upload-s3-prepare")?;
    let prepared = run(&args)?;
    assert!(prepared.status.success());
    let resume = with_pin(args, &fields(&prepared)?, "upload-s3-resume")?;
    assert!(!run(&resume)?.status.success());
    assert_eq!(server.finish()?.len(), 3);
    fs::remove_file(directory.0.join("credentials"))?;
    let before = journal_bytes(&directory)?;
    let observation = observation_arguments(&resume, &directory, "no-secret")?;
    let output = run(&observation)?;
    assert!(!output.status.success());
    let report = fields(&output)?;
    assert_eq!(
        report.get("observation_outcome").and_then(Value::text),
        Some("not_observed")
    );
    assert_eq!(
        report.get("provider_work_requested_this_invocation"),
        Some(&Value::Bool(false))
    );
    assert_eq!(
        report.get("observation_receipt_durable"),
        Some(&Value::Bool(true))
    );
    let receipt = CompletionObservationReceipt::decode(&fs::read(
        directory.0.join("observation-no-secret.bin"),
    )?)?;
    assert_eq!(receipt.outcome(), CompletionObservationOutcome::NotObserved);
    assert_eq!(receipt.consumed().storage_operations, 0);
    assert_eq!(journal_bytes(&directory)?, before);
    Ok(())
}
