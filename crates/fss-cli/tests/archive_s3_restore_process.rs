#![forbid(unsafe_code)]
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
//! Actual-process source-independent S3 restoration and failure-safe local publication.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{PermissionsExt, symlink};
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
use fss_object::uploader::{
    CompletionObservationOutcome, CompletionObservationReceipt, MAX_RETRIEVAL_RANGE_BYTES,
    RetrievalOutcome, RetrievalReceipt,
};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const BODY: &[u8] = b"owner supplied archive object";
const SECRET: &str = "loopback-only-test-secret";
const MAX_FIXTURE_BODY: usize = 512 * 1024;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-native-s3-restore-process-{label}-{}-{attempt}",
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

fn replace_argument(args: &mut [String], name: &str, value: String) -> Test {
    let index = args
        .iter()
        .position(|argument| argument == name)
        .ok_or("fixture argument absent")?
        + 1;
    *args.get_mut(index).ok_or("fixture argument value absent")? = value;
    Ok(())
}

fn restoration_arguments(resume: &[String], directory: &Directory, label: &str) -> Vec<String> {
    let mut args = resume.to_vec();
    args[0] = "upload-s3-restore".into();
    args.extend([
        "--observation-operation".into(),
        format!("operation:independent-restoration:{label}"),
        "--observation-receipt".into(),
        directory
            .0
            .join(format!("receipt-{label}.bin"))
            .display()
            .to_string(),
        "--output".into(),
        directory
            .0
            .join(format!("restored-{label}.bin"))
            .display()
            .to_string(),
    ]);
    args
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
    if length > MAX_FIXTURE_BODY {
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadOutcome {
    Verified,
    Corrupt,
    ChangedEtag,
    ObservedVerified,
    NoRead,
}

struct Server {
    peer: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<Vec<Request>, String>>>,
}

impl Server {
    fn new(source: &[u8], outcome: ReadOutcome) -> Test<Self> {
        if source.is_empty() || source.len() > MAX_FIXTURE_BODY {
            return Err("restoration fixture source bound".into());
        }
        let source = source.to_vec();
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let peer = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let cancelled = stop.clone();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(25);
            let mut received: Vec<Request> = Vec::new();
            let mut metadata = String::new();
            loop {
                if cancelled.load(Ordering::SeqCst) {
                    return Ok(received);
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
                    || request.headers.values().any(|value| value.contains(SECRET))
                    || request.headers.get("x-amz-content-sha256")
                        != Some(&ContentDigest::sha256(&request.body).to_text()[7..].to_owned())
                {
                    return Err("request lost its secret-free signed body identity".into());
                }
                if outcome == ReadOutcome::ObservedVerified && received.len() == 3 {
                    if request.first != "HEAD /test-archive/object.bin HTTP/1.1"
                        || !request.body.is_empty()
                        || request
                            .headers
                            .get("x-amz-checksum-mode")
                            .map(String::as_str)
                            != Some("ENABLED")
                    {
                        return Err("completion observation was not an exact signed HEAD".into());
                    }
                    let composite = b64(&ContentDigest::sha256(
                        &ContentDigest::sha256(&source).bytes(),
                    )
                    .bytes());
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"opaque-completed-object\"\r\nx-amz-checksum-sha256: {composite}-1\r\nx-amz-checksum-type: COMPOSITE\r\n{metadata}Connection: close\r\n\r\n",
                        source.len(),
                    );
                    stream
                        .write_all(head.as_bytes())
                        .map_err(|error| error.to_string())?;
                    received.push(request);
                    continue;
                }
                let (status, headers, body) = match received.len() {
                    0 => {
                        if request.first != "POST /test-archive/object.bin?uploads= HTTP/1.1" {
                            return Err("unexpected initiation target".into());
                        }
                        for name in [
                            "x-amz-meta-fss-intent",
                            "x-amz-meta-fss-plan",
                            "x-amz-meta-fss-root",
                            "x-amz-meta-fss-origin",
                        ] {
                            let value =
                                request.headers.get(name).ok_or("upload identity absent")?;
                            metadata.push_str(&format!("{name}: {value}\r\n"));
                        }
                        (200, String::new(), b"<InitiateMultipartUploadResult><Bucket>test-archive</Bucket><Key>object.bin</Key><UploadId>fixture-upload</UploadId></InitiateMultipartUploadResult>".to_vec())
                    }
                    1 => {
                        if !request.first.starts_with("PUT ") || request.body != source {
                            return Err("source bytes or part method changed".into());
                        }
                        let checksum = b64(&ContentDigest::sha256(&source).bytes());
                        if request.headers.get("x-amz-checksum-sha256") != Some(&checksum) {
                            return Err("independent part checksum absent".into());
                        }
                        (
                            200,
                            format!(
                                "ETag: \"opaque-part-token\"\r\nx-amz-checksum-sha256: {checksum}\r\n"
                            ),
                            Vec::new(),
                        )
                    }
                    2 => {
                        if !request.first.starts_with("POST ")
                            || request.headers.get("if-none-match").map(String::as_str) != Some("*")
                        {
                            return Err("completion was not a create-only POST".into());
                        }
                        let composite = b64(&ContentDigest::sha256(
                            &ContentDigest::sha256(&source).bytes(),
                        )
                        .bytes());
                        (200, String::new(), format!(
                            "<CompleteMultipartUploadResult><Bucket>test-archive</Bucket><Key>object.bin</Key><ETag>opaque-final-token</ETag><ChecksumSHA256>{composite}-1</ChecksumSHA256><ChecksumType>COMPOSITE</ChecksumType></CompleteMultipartUploadResult>"
                        ).into_bytes())
                    }
                    position => {
                        if outcome == ReadOutcome::NoRead {
                            return Err("refused restoration contacted the provider".into());
                        }
                        let first_read = 3 + usize::from(outcome == ReadOutcome::ObservedVerified);
                        let ordinal = position - first_read;
                        let offset = ordinal * MAX_RETRIEVAL_RANGE_BYTES as usize;
                        let length = source
                            .len()
                            .saturating_sub(offset)
                            .min(MAX_RETRIEVAL_RANGE_BYTES as usize);
                        if length == 0
                            || request.first != "GET /test-archive/object.bin HTTP/1.1"
                            || !request.body.is_empty()
                            || request.headers.get("range")
                                != Some(&format!("bytes={offset}-{}", offset + length - 1))
                            || request.headers.get("accept-encoding").map(String::as_str)
                                != Some("identity")
                            || !request
                                .headers
                                .get("authorization")
                                .is_some_and(|value| value.contains(";range;"))
                        {
                            return Err("restore did not request an exact signed range".into());
                        }
                        if ordinal == 0 {
                            if request.headers.contains_key("if-match") {
                                return Err("first range used an unobserved representation".into());
                            }
                        } else if request.headers.get("if-match").map(String::as_str)
                            != Some("\"opaque-retrieval-token\"")
                            || !request
                                .headers
                                .get("authorization")
                                .is_some_and(|value| value.contains(";if-match;"))
                        {
                            return Err("later range lost its signed representation pin".into());
                        }
                        let mut body = source[offset..offset + length].to_vec();
                        if outcome == ReadOutcome::Corrupt {
                            body[0] ^= 0xff;
                        }
                        let etag = if outcome == ReadOutcome::ChangedEtag && ordinal > 0 {
                            "\"replaced-object-token\""
                        } else {
                            "\"opaque-retrieval-token\""
                        };
                        (
                            206,
                            format!(
                                "Content-Range: bytes {offset}-{}/{}\r\nETag: {etag}\r\n{metadata}",
                                offset + length - 1,
                                source.len(),
                            ),
                            body,
                        )
                    }
                };
                if outcome == ReadOutcome::ObservedVerified && received.len() == 2 {
                    // Provider commits, then drops the acknowledgement before a cold observer.
                    received.push(request);
                    continue;
                }
                let head = format!(
                    "HTTP/1.1 {status} fixture\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n",
                    body.len(),
                );
                stream
                    .write_all(head.as_bytes())
                    .and_then(|()| stream.write_all(&body))
                    .map_err(|error| error.to_string())?;
                received.push(request);
            }
        });
        Ok(Self {
            peer,
            stop,
            worker: Some(worker),
        })
    }

    fn finish(mut self) -> Test<Vec<Request>> {
        self.stop.store(true, Ordering::SeqCst);
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

fn completed_fixture(directory: &Directory, server: &Server, bytes: &[u8]) -> Test<Vec<String>> {
    fs::write(directory.0.join("source"), bytes)?;
    let mut args = arguments(directory, server.peer, "upload-s3-prepare")?;
    replace_argument(
        &mut args,
        "--source-sha256",
        ContentDigest::sha256(bytes).to_text(),
    )?;
    replace_argument(&mut args, "--source-bytes", bytes.len().to_string())?;
    let prepared = run(&args)?;
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    let resume = with_pin(args, &fields(&prepared)?, "upload-s3-resume")?;
    let completed = run(&resume)?;
    assert!(
        completed.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&completed.stdout),
        String::from_utf8_lossy(&completed.stderr)
    );
    let report = fields(&completed)?;
    assert_eq!(report.get("phase").and_then(Value::text), Some("completed"));
    assert_eq!(report.get("locally_settled"), Some(&Value::Bool(true)));
    fs::remove_file(directory.0.join("source"))?;
    Ok(resume)
}

#[test]
fn restore_publishes_exact_private_bytes_after_source_removal_and_keeps_upload_history() -> Test {
    let directory = Directory::new("round-trip")?;
    let bytes: Vec<u8> = (0..MAX_RETRIEVAL_RANGE_BYTES as usize + 37)
        .map(|index| (index % 251) as u8)
        .collect();
    let server = Server::new(&bytes, ReadOutcome::Verified)?;
    let resume = completed_fixture(&directory, &server, &bytes)?;
    let before = journal_bytes(&directory)?;
    let args = restoration_arguments(&resume, &directory, "round-trip");
    let output = run(&args)?;
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = fields(&output)?;
    assert_eq!(
        report.get("schema").and_then(Value::text),
        Some("fss.s3_restoration_cli.v1")
    );
    assert_eq!(report.get("command").and_then(Value::text), Some("restore"));
    for field in [
        "independent_retrievability_verified",
        "output_created",
        "output_verified",
        "output_durable",
        "observation_receipt_durable",
        "original_upload_unchanged",
    ] {
        assert_eq!(report.get(field), Some(&Value::Bool(true)), "{field}");
    }
    for field in [
        "source_verified_this_invocation",
        "graph_closure_verified",
        "client_side_encryption_performed",
        "replication_verified",
    ] {
        assert_eq!(report.get(field), Some(&Value::Bool(false)), "{field}");
    }
    assert_eq!(
        report.get("restored_bytes").and_then(Value::integer),
        Some(bytes.len() as i128)
    );
    assert_eq!(
        report.get("restored_digest").and_then(Value::text),
        Some(ContentDigest::sha256(&bytes).to_text().as_str())
    );
    let restored = directory.0.join("restored-round-trip.bin");
    assert_eq!(fs::read(&restored)?, bytes);
    assert_eq!(fs::metadata(&restored)?.permissions().mode() & 0o777, 0o600);
    let receipt_path = directory.0.join("receipt-round-trip.bin");
    let canonical = fs::read(&receipt_path)?;
    let receipt = RetrievalReceipt::decode(&canonical)?;
    assert_eq!(receipt.outcome(), RetrievalOutcome::Verified);
    assert_eq!(receipt.expected_digest(), ContentDigest::sha256(&bytes));
    assert_eq!(receipt.bytes_read(), bytes.len() as u64);
    assert_eq!(receipt.attempted_ranges(), 2);
    assert_eq!(receipt.consumed().storage_operations, 2);
    assert_eq!(journal_bytes(&directory)?, before);
    let requests = server.finish()?;
    assert_eq!(requests.len(), 5);
    assert!(
        requests[3..]
            .iter()
            .all(|request| request.first.starts_with("GET "))
    );

    // A retry must not overwrite either immutable artifact, even without credentials.
    fs::remove_file(directory.0.join("credentials"))?;
    let retry = run(&args)?;
    assert!(!retry.status.success());
    assert!(retry.stdout.is_empty());
    assert_eq!(fs::read(&restored)?, bytes);
    assert_eq!(fs::read(&receipt_path)?, canonical);
    assert_eq!(journal_bytes(&directory)?, before);
    Ok(())
}

#[test]
fn corrupt_remote_bytes_never_create_output_and_keep_independent_mismatch_receipt() -> Test {
    let directory = Directory::new("corrupt")?;
    let server = Server::new(BODY, ReadOutcome::Corrupt)?;
    let resume = completed_fixture(&directory, &server, BODY)?;
    let before = journal_bytes(&directory)?;
    let output = run(&restoration_arguments(&resume, &directory, "corrupt"))?;
    assert!(!output.status.success());
    let report = fields(&output)?;
    assert_eq!(
        report.get("observation_outcome").and_then(Value::text),
        Some("mismatch")
    );
    for field in [
        "independent_retrievability_verified",
        "output_created",
        "output_verified",
        "output_durable",
    ] {
        assert_eq!(report.get(field), Some(&Value::Bool(false)), "{field}");
    }
    assert!(!directory.0.join("restored-corrupt.bin").exists());
    assert_eq!(
        report.get("observation_receipt_durable"),
        Some(&Value::Bool(true))
    );
    let receipt = RetrievalReceipt::decode(&fs::read(directory.0.join("receipt-corrupt.bin"))?)?;
    assert_eq!(receipt.outcome(), RetrievalOutcome::Mismatch);
    assert_eq!(receipt.verified_parts(), 0);
    assert_eq!(receipt.attempted_ranges(), 1);
    assert_eq!(journal_bytes(&directory)?, before);
    assert_eq!(server.finish()?.len(), 4);
    Ok(())
}

#[test]
fn replacement_between_ranges_discards_verified_prefix_without_publishing_media() -> Test {
    let directory = Directory::new("replacement")?;
    let bytes = vec![b'x'; MAX_RETRIEVAL_RANGE_BYTES as usize + 37];
    let server = Server::new(&bytes, ReadOutcome::ChangedEtag)?;
    let resume = completed_fixture(&directory, &server, &bytes)?;
    let before = journal_bytes(&directory)?;
    let output = run(&restoration_arguments(&resume, &directory, "replacement"))?;
    assert!(!output.status.success());
    let report = fields(&output)?;
    assert_eq!(
        report.get("observation_outcome").and_then(Value::text),
        Some("unknown")
    );
    assert_eq!(report.get("output_created"), Some(&Value::Bool(false)));
    assert_eq!(report.get("output_verified"), Some(&Value::Bool(false)));
    assert_eq!(report.get("output_durable"), Some(&Value::Bool(false)));
    assert!(!directory.0.join("restored-replacement.bin").exists());
    let receipt =
        RetrievalReceipt::decode(&fs::read(directory.0.join("receipt-replacement.bin"))?)?;
    assert_eq!(receipt.outcome(), RetrievalOutcome::Unknown);
    assert_eq!(receipt.bytes_read(), MAX_RETRIEVAL_RANGE_BYTES);
    assert_eq!(receipt.attempted_ranges(), 2);
    assert_eq!(journal_bytes(&directory)?, before);
    assert_eq!(server.finish()?.len(), 5);
    Ok(())
}

#[test]
fn occupied_symlink_alias_and_expired_output_requests_refuse_before_provider_access() -> Test {
    let directory = Directory::new("preflight")?;
    let server = Server::new(BODY, ReadOutcome::NoRead)?;
    let resume = completed_fixture(&directory, &server, BODY)?;
    let before = journal_bytes(&directory)?;
    let retained = directory.0.join("already-present.bin");
    fs::write(&retained, b"retain existing bytes")?;
    let linked = directory.0.join("linked.bin");
    symlink(&retained, &linked)?;
    let hardlinked = directory.0.join("hardlinked.bin");
    fs::hard_link(&retained, &hardlinked)?;
    let alias_directory = directory.0.join("alias-directory");
    symlink(&directory.0, &alias_directory)?;
    let credentials = fs::read(directory.0.join("credentials"))?;
    for (label, path) in [
        ("occupied", retained.clone()),
        ("symlink", linked),
        ("hardlink", hardlinked),
        ("ancestor-symlink", alias_directory.join("restored.bin")),
        ("credentials-alias", directory.0.join("credentials")),
        ("source-alias", directory.0.join("source")),
        (
            "journal-alias",
            directory.0.join("journal").join("restored.bin"),
        ),
        (
            "receipt-alias",
            directory.0.join("receipt-receipt-alias.bin"),
        ),
    ] {
        let mut args = restoration_arguments(&resume, &directory, label);
        replace_argument(&mut args, "--output", path.display().to_string())?;
        let output = run(&args)?;
        assert!(!output.status.success(), "{label}");
        assert!(output.stdout.is_empty(), "{label}");
        assert!(
            !directory.0.join(format!("receipt-{label}.bin")).exists(),
            "{label}"
        );
        assert_eq!(fs::read(&retained)?, b"retain existing bytes", "{label}");
        assert_eq!(
            fs::read(directory.0.join("credentials"))?,
            credentials,
            "{label}"
        );
        assert_eq!(journal_bytes(&directory)?, before, "{label}");
    }
    let mut expired = restoration_arguments(&resume, &directory, "expired");
    replace_argument(&mut expired, "--deadline-ns", "1".into())?;
    let output = run(&expired)?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!directory.0.join("restored-expired.bin").exists());
    assert!(!directory.0.join("receipt-expired.bin").exists());
    assert_eq!(journal_bytes(&directory)?, before);
    assert_eq!(server.finish()?.len(), 3);
    Ok(())
}

#[test]
fn lost_completion_observation_allows_restore_without_rewriting_indeterminate_upload() -> Test {
    let directory = Directory::new("observed")?;
    let server = Server::new(BODY, ReadOutcome::ObservedVerified)?;
    let args = arguments(&directory, server.peer, "upload-s3-prepare")?;
    let prepared = run(&args)?;
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    let resume = with_pin(args, &fields(&prepared)?, "upload-s3-resume")?;
    let completed = run(&resume)?;
    assert!(!completed.status.success());
    let original = fields(&completed)?;
    assert_eq!(
        original.get("uncertain_operation").and_then(Value::text),
        Some("complete")
    );
    assert_eq!(original.get("locally_settled"), Some(&Value::Bool(true)));
    fs::remove_file(directory.0.join("source"))?;
    let before = journal_bytes(&directory)?;

    let observation_path = directory.0.join("completion-observation.bin");
    let mut observation_args = resume.clone();
    observation_args[0] = "upload-s3-reconcile".into();
    replace_argument(&mut observation_args, "--max-requests", "1".into())?;
    observation_args.extend([
        "--observation-operation".into(),
        "operation:restore-completion-observation".into(),
        "--observation-receipt".into(),
        observation_path.display().to_string(),
    ]);
    let observed = run(&observation_args)?;
    assert!(
        observed.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&observed.stdout),
        String::from_utf8_lossy(&observed.stderr)
    );
    let observation_bytes = fs::read(&observation_path)?;
    let observation = CompletionObservationReceipt::decode(&observation_bytes)?;
    assert_eq!(
        observation.outcome(),
        CompletionObservationOutcome::Completed
    );
    assert_eq!(
        fields(&observed)?.get("independent_retrievability_verified"),
        Some(&Value::Bool(false))
    );

    let mut args = restoration_arguments(&resume, &directory, "observed");
    args.extend([
        "--completion-observation".into(),
        observation_path.display().to_string(),
        "--completion-observation-sha256".into(),
        observation.digest()?.to_text(),
    ]);
    let output = run(&args)?;
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = fields(&output)?;
    assert_eq!(
        report.get("schema").and_then(Value::text),
        Some("fss.s3_restoration_cli.v1")
    );
    assert_eq!(
        report.get("original_phase").and_then(Value::text),
        Some("uncertain")
    );
    assert_eq!(
        report.get("original_indeterminate_receipt_digest"),
        original.get("receipt_digest")
    );
    assert_eq!(
        report.get("source_journal_head"),
        original.get("journal_head")
    );
    for field in [
        "independent_retrievability_verified",
        "output_created",
        "output_verified",
        "output_durable",
        "observation_receipt_durable",
        "original_upload_unchanged",
    ] {
        assert_eq!(report.get(field), Some(&Value::Bool(true)), "{field}");
    }
    assert_eq!(fs::read(directory.0.join("restored-observed.bin"))?, BODY);
    let receipt = RetrievalReceipt::decode(&fs::read(directory.0.join("receipt-observed.bin"))?)?;
    assert_eq!(receipt.outcome(), RetrievalOutcome::Verified);
    assert_eq!(
        receipt.completion_observation_digest(),
        Some(observation.digest()?)
    );
    assert_eq!(
        receipt.indeterminate_receipt_digest(),
        Some(observation.indeterminate_receipt_digest())
    );
    assert_eq!(fs::read(observation_path)?, observation_bytes);
    assert_eq!(journal_bytes(&directory)?, before);
    let requests = server.finish()?;
    assert_eq!(requests.len(), 5);
    assert!(requests[3].first.starts_with("HEAD "));
    assert!(requests[4].first.starts_with("GET "));
    Ok(())
}
