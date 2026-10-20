#![forbid(unsafe_code)]
//! `fss-import-s3`: fetch a bounded object from an owner-provided presigned URL
//! (S3-compatible store / NAS) over plain HTTP, stage it to a transient file, and
//! import it through the real `FileIngestAdapter` path into an owner-named deployment
//! root. This is the main-goal "locally-cached footage off a NAS" lane for the
//! `ADP-S3-IMPORT-001` adapter row.
//!
//! The presigned URL is the operator's: it is a time-limited capability token, not a
//! cloud credential, and no ambient secret is held in config. The presigned query
//! (signature, expiry) is stripped from the report — only the host and object path are
//! echoed. Without `--owner-authorized` the command refuses. The report is
//! `fss.s3_import_cli.v1` JSON: digests, byte counts and the import identity — no pixels.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs, sha256};
use fss_reference::ingest::{
    FileFormatHint, FileIngestAdapter, FileIngestRequest, RetainedFileImport, RetainedReadLimits,
};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx};

/// Report schema identity.
const REPORT_SCHEMA: &str = "fss.s3_import_cli.v1";
/// Deployment site lineage of every S3 import root (fixed, so reports are root-independent).
const SITE: &str = "site:lab-s3-import";
/// Default ceiling on the fetched object (256 MiB); the operator may raise it to 1 GiB.
const DEFAULT_MAX_SOURCE_BYTES: u64 = 256 * 1024 * 1024;
/// Hard ceiling on the operator-overridable source-byte bound.
const MAX_ALLOWED_SOURCE_BYTES: u64 = 1024 * 1024 * 1024;
/// TCP connect deadline for the presigned-URL fetch.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Per-read deadline for the presigned-URL fetch.
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Fetch read-buffer size.
const CHUNK: usize = 16384;
/// Argument-count guard (no external argv parsing crate).
const MAX_ARGS: usize = 24;

const HELP: &str = "fss-import-s3 --url PRESIGNED_HTTP_URL --root ABSOLUTE_DEPLOYMENT \\\n\
  --sensor-id ID --stream-id ID --receive-time-ns N --owner-authorized \\\n\
  [--media-format auto|mjpeg|annexb|hevc] [--max-source-bytes N]\n\
  Fetch a bounded object from an owner-provided presigned URL (S3-compatible / NAS) over\n\
  plain HTTP, stage it, and import it through the FileIngestAdapter path into the deployment\n\
  root. No vendor cloud is involved. Without --owner-authorized: refused. The presigned\n\
  query (signature/expiry) is not echoed; only host + object path are. Report: \
  fss.s3_import_cli.v1 JSON on stdout.\n";

/// Parsed, bounded fetch + import options.
#[derive(Debug, Clone)]
struct Options {
    /// The operator-supplied presigned `http://` URL.
    url: String,
    /// Absolute deployment root for the import (absent or empty).
    root: PathBuf,
    /// Sensor identity assigned to the imported file.
    sensor_id: String,
    /// Stream identity assigned to the imported file.
    stream_id: String,
    /// Arrival/receive time in nanoseconds (never capture time).
    receive_time_ns: i128,
    /// Owner attests the object source is theirs.
    owner_authorized: bool,
    /// Optional container format hint; `auto` lets the ingest detect it.
    media_format: Option<FileFormatHint>,
    /// Ceiling on the fetched object, in bytes.
    max_source_bytes: u64,
}

fn malformed<T>(message: impl Into<String>) -> Result<T, String> {
    Err(message.into())
}

/// Splits a `http://host:port/path?query` URL into host, port, object path and the presigned
/// query (kept out of the report). Only `http://` is supported; TLS is the NAS's own concern.
fn parse_url(url: &str) -> Result<(String, u16, String, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or("only http:// presigned URLs are supported; TLS is the NAS's own concern")?;
    let (hostport, tail) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match hostport.rfind(':') {
        Some(i) => (
            hostport[..i].trim_end_matches('[').to_owned(),
            hostport[i + 1..]
                .parse::<u16>()
                .map_err(|_| "port must be a number")?,
        ),
        None => (hostport.to_owned(), 80),
    };
    if host.is_empty() {
        return malformed("host is empty");
    }
    let (object_path, query) = match tail.find('?') {
        Some(i) => (tail[..i].to_owned(), tail[i + 1..].to_owned()),
        None => (tail.to_owned(), String::new()),
    };
    Ok((host, port, object_path, query))
}

/// Bounded plain-HTTP GET over a single TCP connection (`Connection: close`). Returns the body;
/// refuses a non-200 status or a body over `max_bytes`.
fn http_get(host: &str, port: u16, request_path: &str, max_bytes: u64) -> Result<Vec<u8>, String> {
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {host}:{port}: {e}"))?
        .next()
        .ok_or_else(|| format!("no address for {host}:{port}"))?;
    let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|e| format!("connect {host}:{port}: {e}"))?;
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(|e| format!("set read timeout: {e}"))?;
    let req = format!("GET {request_path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("send request: {e}"))?;
    stream.flush().map_err(|e| format!("flush: {e}"))?;
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; CHUNK];
    loop {
        let n = stream.read(&mut tmp).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if (buf.len() as u64) > max_bytes + 8192 {
            return Err(format!("object exceeds --max-source-bytes {max_bytes}"));
        }
    }
    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("response has no header terminator")?
        + 4;
    let head = std::str::from_utf8(&buf[..header_end]).map_err(|_| "non-UTF-8 HTTP head")?;
    let status = head.lines().next().ok_or("empty HTTP response")?;
    let code = status.split_whitespace().nth(1).unwrap_or("");
    if !status.starts_with("HTTP/1.") || code != "200" {
        return Err(format!("HTTP {status}"));
    }
    let body = &buf[header_end..];
    if (body.len() as u64) > max_bytes {
        return Err(format!(
            "object {} bytes exceeds --max-source-bytes {max_bytes}",
            body.len()
        ));
    }
    Ok(body.to_vec())
}

/// Stages the fetched bytes to a transient, uniquely-named file the `FileIngestAdapter` reads.
fn stage(bytes: &[u8]) -> Result<PathBuf, String> {
    let path = std::env::temp_dir().join(format!("fss-s3-import-{}.bin", std::process::id()));
    std::fs::write(&path, bytes).map_err(|e| format!("stage write: {e}"))?;
    Ok(path)
}

/// Region authority for the import, mirroring the lab decode (replay capability, ephemeral
/// retention, local-authorized privacy).
fn context(root: &std::path::Path) -> Result<ReplayCx, String> {
    let error = |e: &dyn std::fmt::Display| format!("s3 import authority: {e}");
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:lab:s3-import".to_owned(),
        operation_id: OperationId::parse("op:lab:s3-import").map_err(|e| error(&e))?,
        principal: "operator:lab".to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(DEFAULT_MAX_SOURCE_BYTES)
            .storage_operations(1 << 20)
            .build()
            .map_err(|e| error(&e))?,
        privacy_scope: "privacy:local-authorized-files".to_owned(),
        retention_scope: "retention:ephemeral".to_owned(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })
    .map_err(|e| error(&e))?;
    authority.validate().map_err(|e| error(&e))?;
    ReplayCx::from_context_authority(&authority, root.to_path_buf()).map_err(|e| error(&e))
}

/// The JSON report of one successful fetch + import.
struct Report {
    host: String,
    port: u16,
    object_path: String,
    bytes: u64,
    object_sha256: [u8; 32],
    import_identity: String,
    import_outcome: String,
    media_format: String,
    import_root: String,
}

/// Runs the full lane: fetch → stage → context → deployment → ingest → report.
fn run(options: &Options) -> Result<String, String> {
    let (host, port, object_path, query) = parse_url(&options.url)?;
    let request_path = if query.is_empty() {
        object_path.clone()
    } else {
        format!("{object_path}?{query}")
    };
    let bytes = http_get(&host, port, &request_path, options.max_source_bytes)?;
    let object_sha256 = sha256(&bytes);
    let staging = stage(&bytes)?;
    let cx = context(&options.root)?;
    let report = run_in(options, &staging, object_sha256, &cx);
    let _ = std::fs::remove_file(&staging);
    cx.drain_and_finalize();
    report
}

fn run_in(
    options: &Options,
    staging: &std::path::Path,
    object_sha256: [u8; 32],
    cx: &ReplayCx,
) -> Result<String, String> {
    let mut deployment = ReferenceDeployment::open(&options.root, SITE, cx)
        .map_err(|e| format!("s3 import deployment: {e}"))?;
    let sensor = SensorId::parse(&options.sensor_id).map_err(|e| format!("sensor-id: {e}"))?;
    let stream = StreamId::parse(&options.stream_id).map_err(|e| format!("stream-id: {e}"))?;
    let mut request = FileIngestRequest::new(staging.to_path_buf(), sensor, stream)
        .with_receive_time(TimestampNs(options.receive_time_ns));
    if let Some(hint) = options.media_format {
        request.format_hint = Some(hint);
    }
    let imported = FileIngestAdapter::ingest(request, cx, &mut deployment)
        .map_err(|e| format!("s3 import ingest: {e}"))?;
    let retained = RetainedFileImport::open(
        &deployment,
        imported.import_identity,
        RetainedReadLimits::default(),
        cx,
    )
    .map_err(|e| format!("s3 import retained: {e}"))?;
    let manifest = retained.manifest().clone();
    // The report names the fetched body, not a different staged file or a chunk digest.
    if manifest.input_sha256.bytes() != object_sha256 {
        return Err("fetched object SHA-256 differs from retained input SHA-256".to_owned());
    }
    let (host, port, object_path, _) = parse_url(&options.url)?;
    Ok(render(&Report {
        host,
        port,
        object_path,
        bytes: manifest.input_bytes,
        object_sha256,
        import_identity: imported.import_identity.to_text(),
        import_outcome: imported.outcome.as_str().to_owned(),
        media_format: manifest.format.clone(),
        import_root: retained.import_root().to_text(),
    }))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn render(r: &Report) -> String {
    let mut out = String::new();
    use std::fmt::Write as _;
    let _ = writeln!(out, "{{");
    let _ = writeln!(out, "  \"schema\": \"{REPORT_SCHEMA}\",");
    let _ = writeln!(out, "  \"source\": {{");
    let _ = writeln!(out, "    \"host\": \"{}\",", r.host);
    let _ = writeln!(out, "    \"port\": {},", r.port);
    let _ = writeln!(out, "    \"object_path\": \"{}\"", r.object_path);
    let _ = writeln!(out, "  }},");
    let _ = writeln!(out, "  \"bytes\": {},", r.bytes);
    let _ = writeln!(
        out,
        "  \"object_sha256\": \"sha256:{}\",",
        hex(&r.object_sha256)
    );
    let _ = writeln!(out, "  \"import_identity\": \"{}\",", r.import_identity);
    let _ = writeln!(out, "  \"import_outcome\": \"{}\",", r.import_outcome);
    let _ = writeln!(out, "  \"media_format\": \"{}\",", r.media_format);
    let _ = writeln!(out, "  \"import_root\": \"{}\",", r.import_root);
    let _ = writeln!(out, "  \"owner_authorized\": true,");
    let _ = writeln!(
        out,
        "  \"note\": \"NAS/S3 object fetched over plain HTTP from an owner presigned URL and imported through FileIngestAdapter; no vendor cloud involved.\""
    );
    let _ = writeln!(out, "}}");
    out
}

fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() > MAX_ARGS {
        return malformed("too many arguments");
    }
    let mut opts = Options {
        url: String::new(),
        root: PathBuf::new(),
        sensor_id: String::new(),
        stream_id: String::new(),
        receive_time_ns: 0,
        owner_authorized: false,
        media_format: None,
        max_source_bytes: DEFAULT_MAX_SOURCE_BYTES,
    };
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let next = if i + 1 < args.len() {
            Some(args[i + 1].as_str())
        } else {
            None
        };
        match a.as_str() {
            "--url" => {
                let v = next.ok_or("--url requires a value")?;
                opts.url = v.to_owned();
                i += 2;
            }
            "--root" => {
                let v = next.ok_or("--root requires a value")?;
                opts.root = PathBuf::from(v);
                i += 2;
            }
            "--sensor-id" => {
                let v = next.ok_or("--sensor-id requires a value")?;
                opts.sensor_id = v.to_owned();
                i += 2;
            }
            "--stream-id" => {
                let v = next.ok_or("--stream-id requires a value")?;
                opts.stream_id = v.to_owned();
                i += 2;
            }
            "--receive-time-ns" => {
                let v = next.ok_or("--receive-time-ns requires a value")?;
                opts.receive_time_ns = v
                    .parse()
                    .map_err(|_| "--receive-time-ns must be an integer")?;
                i += 2;
            }
            "--media-format" => {
                let v = next.ok_or("--media-format requires a value")?;
                opts.media_format = parse_format(v)?;
                i += 2;
            }
            "--max-source-bytes" => {
                let v = next.ok_or("--max-source-bytes requires a value")?;
                let n: u64 = v
                    .parse()
                    .map_err(|_| "--max-source-bytes must be a number")?;
                if n == 0 || n > MAX_ALLOWED_SOURCE_BYTES {
                    return malformed("--max-source-bytes must be 1..=1073741824");
                }
                opts.max_source_bytes = n;
                i += 2;
            }
            "--owner-authorized" => {
                opts.owner_authorized = true;
                i += 1;
            }
            "help" | "--help" | "-h" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            other => return malformed(format!("unknown argument: {other}")),
        }
    }
    if opts.url.is_empty() {
        return malformed("--url is required");
    }
    if opts.root.as_os_str().is_empty() {
        return malformed("--root is required");
    }
    if opts.sensor_id.is_empty() {
        return malformed("--sensor-id is required");
    }
    if opts.stream_id.is_empty() {
        return malformed("--stream-id is required");
    }
    if opts.receive_time_ns == 0 {
        return malformed("--receive-time-ns is required");
    }
    if !opts.owner_authorized {
        return malformed("refused: pass --owner-authorized to attest the object source is yours");
    }
    Ok(opts)
}

fn parse_format(s: &str) -> Result<Option<FileFormatHint>, &'static str> {
    match s {
        "auto" => Ok(None),
        "mjpeg" => Ok(Some(FileFormatHint::JpegStream)),
        "annexb" => Ok(Some(FileFormatHint::AnnexB)),
        "hevc" => Ok(Some(FileFormatHint::Hevc)),
        _ => Err("media format must be auto, mjpeg, annexb or hevc"),
    }
}

/// Exit identity: runtime failure (parse, network, authority, or ingest refused).
fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty()
        || matches!(
            args.first().map(String::as_str),
            Some("help" | "--help" | "-h")
        )
    {
        print!("{HELP}");
        return std::process::ExitCode::from(0);
    }
    let opts = match parse(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("fss-import-s3: {e}");
            return std::process::ExitCode::from(64);
        }
    };
    match run(&opts) {
        Ok(report) => {
            let mut out = std::io::stdout().lock();
            if out.write_all(report.as_bytes()).is_err() || out.flush().is_err() {
                return std::process::ExitCode::from(70);
            }
            std::process::ExitCode::from(0)
        }
        Err(e) => {
            eprintln!("fss-import-s3: {e}");
            std::process::ExitCode::from(70)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

    struct Directory(PathBuf);
    impl Directory {
        fn new(label: &str) -> Test<Self> {
            for attempt in 0..100 {
                let path = std::env::temp_dir().join(format!(
                    "fss-s3-import-{label}-{}-{attempt}",
                    std::process::id()
                ));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Ok(Self(path)),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Err("temporary directory capacity".into())
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A minimal one-shot loopback HTTP server: serves `body` once, then closes.
    fn serve_loopback(body: Vec<u8>, status: &'static str, port_tx: std::sync::mpsc::Sender<u16>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        port_tx.send(port).unwrap();
        for stream in listener.incoming() {
            let mut s = match stream {
                Ok(s) => s,
                Err(_) => break,
            };
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut req = [0u8; 4096];
            let _ = s.read(&mut req);
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
            let _ = s.write_all(&body);
            let _ = s.flush();
            break;
        }
    }

    #[test]
    fn parse_url_splits_host_port_path_query() {
        let (host, port, path, query) = parse_url(
            "http://192.168.5.211:9000/bucket/clip.mjpeg?X-Amz-Signature=abc&X-Amz-Expires=600",
        )
        .unwrap();
        assert_eq!(host, "192.168.5.211");
        assert_eq!(port, 9000);
        assert_eq!(path, "/bucket/clip.mjpeg");
        assert_eq!(query, "X-Amz-Signature=abc&X-Amz-Expires=600");
    }

    #[test]
    fn parse_url_defaults_port_and_no_query() {
        let (host, port, path, query) = parse_url("http://nas.local/footage/a.mp4").unwrap();
        assert_eq!(host, "nas.local");
        assert_eq!(port, 80);
        assert_eq!(path, "/footage/a.mp4");
        assert!(query.is_empty());
    }

    #[test]
    fn parse_url_rejects_non_http() {
        assert!(parse_url("https://nas/bucket/a").is_err());
        assert!(parse_url("s3://bucket/a").is_err());
        assert!(parse_url("http://:9000/a").is_err());
    }

    #[test]
    fn http_get_fetches_bounded_body() {
        let body = b"hello nas object".to_vec();
        let expected = body.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || serve_loopback(body, "200 OK", tx));
        let port = rx.recv().unwrap();
        let got = http_get("127.0.0.1", port, "/o.bin", 1024).unwrap();
        assert_eq!(got, expected);
        t.join().unwrap();
    }

    #[test]
    fn http_get_enforces_max_bytes() {
        let body = vec![0u8; 4096];
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || serve_loopback(body, "200 OK", tx));
        let port = rx.recv().unwrap();
        let err = http_get("127.0.0.1", port, "/big.bin", 16).unwrap_err();
        assert!(err.contains("exceeds"), "{err}");
        t.join().unwrap();
    }

    #[test]
    fn http_get_refuses_non_200() {
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || serve_loopback(b"nope".to_vec(), "404 Not Found", tx));
        let port = rx.recv().unwrap();
        let err = http_get("127.0.0.1", port, "/missing", 1024).unwrap_err();
        assert!(err.contains("404"), "{err}");
        t.join().unwrap();
    }

    #[test]
    fn refuses_missing_owner_attestation() {
        let args = vec![
            "--url".into(),
            "http://127.0.0.1:1/o".into(),
            "--root".into(),
            "/tmp/x".into(),
            "--sensor-id".into(),
            "sensor:a".into(),
            "--stream-id".into(),
            "stream:a".into(),
            "--receive-time-ns".into(),
            "1000000000".into(),
        ];
        assert!(parse(&args).is_err());
    }

    #[test]
    fn loopback_fetch_and_ingest_end_to_end() -> Test {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/media/mjpeg/mjpeg_clean_3frames.mjpeg");
        let body = std::fs::read(&fixture)?;
        let expected_hash = ContentDigest::sha256(&body);
        let expected_bytes = body.len() as u64;
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || serve_loopback(body, "200 OK", tx));
        let port = rx.recv_timeout(Duration::from_secs(5))?;
        let directory = Directory::new("e2e")?;
        let opts = Options {
            url: format!("http://127.0.0.1:{port}/bucket/clip.mjpeg?X-Amz-Signature=s3cr3t"),
            root: directory.0.join("deployment"),
            sensor_id: "sensor:s3-e2e".to_owned(),
            stream_id: "stream:s3-e2e".to_owned(),
            receive_time_ns: 1_000_000_000,
            owner_authorized: true,
            media_format: Some(FileFormatHint::JpegStream),
            max_source_bytes: DEFAULT_MAX_SOURCE_BYTES,
        };
        let report = run(&opts)?;
        t.join().map_err(|_| "loopback server panicked")?;
        let parsed = fss_cli::json_input::parse(&report)?;
        let fields = parsed.object().ok_or("report object")?;
        assert_eq!(
            fields.get("schema").and_then(|value| value.text()),
            Some(REPORT_SCHEMA)
        );
        assert_eq!(
            fields.get("object_sha256").and_then(|value| value.text()),
            Some(expected_hash.to_text().as_str()),
        );
        assert_eq!(
            fields.get("bytes").and_then(|value| value.integer()),
            Some(i128::from(expected_bytes))
        );
        let import_identity = ContentDigest::parse(
            fields
                .get("import_identity")
                .and_then(|value| value.text())
                .ok_or("import identity")?,
        )?;
        let cx = context(&opts.root)?;
        let deployment = ReferenceDeployment::open(&opts.root, SITE, &cx)?;
        let limits = RetainedReadLimits::default();
        let retained = RetainedFileImport::open(&deployment, import_identity, limits, &cx)?;
        assert_eq!(retained.manifest().input_sha256, expected_hash);
        assert_eq!(retained.manifest().input_bytes, expected_bytes);
        assert_eq!(
            retained.verify_source(&deployment, limits, &cx)?,
            expected_hash
        );
        assert_eq!(
            fields.get("import_root").and_then(|value| value.text()),
            Some(retained.import_root().to_text().as_str()),
        );
        cx.drain_and_finalize();
        assert!(report.contains("127.0.0.1"), "report:\n{report}");
        assert!(report.contains("/bucket/clip.mjpeg"), "report:\n{report}");
        assert!(
            !report.contains("X-Amz-Signature"),
            "presigned query leaked: {report}"
        );
        assert!(
            !report.contains("s3cr3t"),
            "presigned signature leaked: {report}"
        );
        Ok(())
    }

    #[test]
    fn unknown_argument_diagnostic_owns_its_formatted_message() -> Test {
        let error = {
            let arguments = vec!["--not-an-option".to_owned()];
            parse(&arguments).err().ok_or("unknown option accepted")?
        };
        assert_eq!(error, "unknown argument: --not-an-option");
        Ok(())
    }

    #[test]
    fn a_different_fetched_hash_cannot_be_reported_for_the_retained_input() -> Test {
        let directory = Directory::new("hash-binding")?;
        let staging = directory.0.join("staged.mjpeg");
        let body = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/media/mjpeg/mjpeg_clean_3frames.mjpeg"
        ));
        std::fs::write(&staging, body)?;
        let options = Options {
            url: "http://127.0.0.1:1/bucket/clip.mjpeg".to_owned(),
            root: directory.0.join("deployment"),
            sensor_id: "sensor:s3-hash-binding".to_owned(),
            stream_id: "stream:s3-hash-binding".to_owned(),
            receive_time_ns: 1_000_000_000,
            owner_authorized: true,
            media_format: Some(FileFormatHint::JpegStream),
            max_source_bytes: DEFAULT_MAX_SOURCE_BYTES,
        };
        let cx = context(&options.root)?;
        let result = run_in(&options, &staging, sha256(b"different fetched object"), &cx);
        cx.drain_and_finalize();
        assert_eq!(
            result
                .err()
                .ok_or("mismatched source hash produced a report")?,
            "fetched object SHA-256 differs from retained input SHA-256",
        );
        Ok(())
    }
}
