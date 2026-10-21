#![forbid(unsafe_code)]
//! Fetch one owner-authorized ONVIF Profile T snapshot (a single JPEG) directly from a
//! camera's ONVIF Media1 service over plain HTTP, stage it, and import it through the
//! `FileIngestAdapter` path into the deployment root. No vendor cloud is involved.
//!
//! The lane is read-only: it negotiates the snapshot URI with `GetProfiles` +
//! `GetSnapshotUri` (both read-only ONVIF Media1 operations) and then performs one bounded
//! `GET` of the JPEG. The snapshot URI's query (token/expiry) is never echoed; the report
//! names only host, port, and object path.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs, sha256};
use fss_reference::ingest::{
    FileFormatHint, FileIngestAdapter, FileIngestRequest, RetainedFileImport, RetainedReadLimits,
};
use fss_reference::onvif::wire::{self, MediaProfile, MAX_SOAP_BYTES};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx};

/// Report schema identity.
const REPORT_SCHEMA: &str = "fss.onvif_capture_cli.v1";
/// Deployment site lineage of every ONVIF snapshot import root (fixed, so reports are root-independent).
const SITE: &str = "site:lab-onvif-import";
/// Default ceiling on the fetched JPEG (4 MiB); a snapshot is one frame, not a stream.
const DEFAULT_MAX_SOURCE_BYTES: u64 = 4 * 1024 * 1024;
/// Hard ceiling on the operator-overridable source-byte bound.
const MAX_ALLOWED_SOURCE_BYTES: u64 = 64 * 1024 * 1024;
/// TCP connect deadline for each ONVIF request and the snapshot fetch.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Per-read deadline.
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Read-buffer size.
const CHUNK: usize = 16384;
/// Argument-count guard (no external argv parsing crate).
const MAX_ARGS: usize = 26;

const HELP: &str = "fss-capture-onvif --xaddr ONVIF_MEDIA1_SERVICE_URL --root ABSOLUTE_DEPLOYMENT \\\n\
  --sensor-id ID --stream-id ID --receive-time-ns N --owner-authorized \\\n\
  [--profile TOKEN] [--max-source-bytes N]\n\
  Negotiate one owner-authorized ONVIF Profile T snapshot (a single JPEG) directly from the\n\
  camera's ONVIF Media1 service over plain HTTP, stage it, and import it through the\n\
  FileIngestAdapter path into the deployment root. No vendor cloud is involved.\n\
  Read-only lane: GetProfiles + GetSnapshotUri (both read-only ONVIF operations), then one\n\
  bounded GET of the JPEG. The snapshot URI's query (token/expiry) is not echoed; only\n\
  host + object path are. Without --owner-authorized: refused. Report: fss.onvif_capture_cli.v1\n\
  JSON on stdout.\n";

/// Parsed, bounded fetch + import options.
#[derive(Debug, Clone)]
struct Options {
    /// The operator-supplied ONVIF Media1 service URL (`http://`).
    xaddr: String,
    /// Absolute deployment root for the import.
    root: PathBuf,
    /// Sensor identity assigned to the imported file.
    sensor_id: String,
    /// Stream identity assigned to the imported file.
    stream_id: String,
    /// Arrival/receive time in nanoseconds (never capture time).
    receive_time_ns: i128,
    /// Owner attests the device and its media are theirs.
    owner_authorized: bool,
    /// Optional profile token; when absent, the first video-capable profile is used.
    profile: Option<String>,
    /// Ceiling on the fetched JPEG, in bytes.
    max_source_bytes: u64,
}

fn malformed<T>(message: impl Into<String>) -> Result<T, String> {
    Err(message.into())
}

/// Splits a `http://host:port/path?query` URL into host, port, path and the query (kept out of
/// the report). Only `http://` is supported; TLS is the device's own concern.
fn parse_url(url: &str) -> Result<(String, u16, String, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or("only http:// ONVIF and snapshot URLs are supported; TLS is the device's own concern")?;
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
    let (path, query) = match tail.find('?') {
        Some(i) => (tail[..i].to_owned(), tail[i + 1..].to_owned()),
        None => (tail.to_owned(), String::new()),
    };
    Ok((host, port, path, query))
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
            return Err(format!("snapshot exceeds --max-source-bytes {max_bytes}"));
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
            "snapshot {} bytes exceeds --max-source-bytes {max_bytes}",
            body.len()
        ));
    }
    Ok(body.to_vec())
}

/// Bounded plain-HTTP SOAP 1.2 POST over a single TCP connection (`Connection: close`). Returns
/// the body; refuses a non-200 status or a body over `max_bytes`. A SOAP fault arrives as HTTP
/// 500 and is reported by its status, not its raw device text.
fn http_post(
    host: &str,
    port: u16,
    request_path: &str,
    action: &str,
    body: &[u8],
    max_bytes: u64,
) -> Result<Vec<u8>, String> {
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
    let req = format!(
        "POST {request_path} HTTP/1.1\r\nHost: {host}\r\n\
         Content-Type: application/soap+xml; charset=utf-8\r\n\
         SOAPAction: {action}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("send request: {e}"))?;
    stream
        .write_all(body)
        .map_err(|e| format!("send body: {e}"))?;
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
            return Err(format!("SOAP response exceeds {max_bytes} bytes"));
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
            "SOAP response {} bytes exceeds {max_bytes}",
            body.len()
        ));
    }
    Ok(body.to_vec())
}

/// Choose the profile to snapshot. An explicit token must match exactly; otherwise the first
/// profile that advertises a video encoder is used, falling back to the first profile.
fn pick_profile(profiles: &[MediaProfile], token: Option<&str>) -> Result<MediaProfile, String> {
    match token {
        Some(t) => profiles
            .iter()
            .find(|p| p.token == t)
            .cloned()
            .ok_or_else(|| format!("no ONVIF profile with token {t}")),
        None => profiles
            .iter()
            .find(|p| p.video.is_some())
            .or_else(|| profiles.first())
            .cloned()
            .ok_or("GetProfiles returned no profiles".to_string()),
    }
}

/// Stages the fetched bytes to a transient, uniquely-named file the `FileIngestAdapter` reads.
fn stage(bytes: &[u8]) -> Result<PathBuf, String> {
    let path =
        std::env::temp_dir().join(format!("fss-onvif-import-{}.jpg", std::process::id()));
    std::fs::write(&path, bytes).map_err(|e| format!("stage write: {e}"))?;
    Ok(path)
}

/// Region authority for the import, mirroring the lab decode (replay capability, ephemeral
/// retention, local-authorized privacy).
fn context(root: &std::path::Path) -> Result<ReplayCx, String> {
    let error = |e: &dyn std::fmt::Display| format!("onvif import authority: {e}");
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:lab:onvif-import".to_owned(),
        operation_id: OperationId::parse("op:lab:onvif-import").map_err(|e| error(&e))?,
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

/// The JSON report of one successful snapshot fetch + import.
struct Report {
    xaddr_host: String,
    xaddr_port: u16,
    xaddr_path: String,
    snapshot_host: String,
    snapshot_port: u16,
    snapshot_path: String,
    bytes: u64,
    jpeg_sha256: [u8; 32],
    import_identity: String,
    import_outcome: String,
    media_format: String,
    import_root: String,
    valid_until: Option<String>,
}

/// Runs the full lane: GetProfiles → pick profile → GetSnapshotUri → GET JPEG → stage →
/// context → deployment → ingest → report.
fn run(options: &Options) -> Result<String, String> {
    let (xhost, xport, xpath, xquery) = parse_url(&options.xaddr)?;
    let xpath_req = if xquery.is_empty() {
        xpath.clone()
    } else {
        format!("{xpath}?{xquery}")
    };

    // 1. Enumerate profiles (read-only ONVIF operation).
    let profiles_req = wire::get_profiles_request();
    let profiles_resp = http_post(
        &xhost,
        xport,
        &xpath_req,
        profiles_req.action(),
        profiles_req.body(),
        MAX_SOAP_BYTES as u64,
    )?;
    let profiles = wire::parse_profiles(&profiles_resp)
        .map_err(|e| format!("parse GetProfiles response: {e}"))?;
    let profile = pick_profile(&profiles, options.profile.as_deref())?;

    // 2. Request the selected profile's snapshot URI (read-only ONVIF operation).
    let snap_req =
        wire::get_snapshot_uri_request(&profile.token).map_err(|e| format!("build GetSnapshotUri: {e}"))?;
    let snap_resp = http_post(
        &xhost,
        xport,
        &xpath_req,
        snap_req.action(),
        snap_req.body(),
        MAX_SOAP_BYTES as u64,
    )?;
    let snap = wire::parse_snapshot_uri(&snap_resp)
        .map_err(|e| format!("parse GetSnapshotUri response: {e}"))?;

    // 3. Fetch the JPEG (bounded, must begin with a SOI marker).
    let (sphot, sport, spath, spquery) =
        parse_url(&snap.uri).map_err(|e| format!("snapshot URI: {e}"))?;
    let spath_req = if spquery.is_empty() {
        spath.clone()
    } else {
        format!("{spath}?{spquery}")
    };
    let jpeg = http_get(&sphot, sport, &spath_req, options.max_source_bytes)?;
    if !jpeg.starts_with(&[0xffu8, 0xd8u8]) {
        return Err("snapshot body does not begin with a JPEG SOI marker (FF D8)".to_owned());
    }
    let object_sha256 = sha256(&jpeg);
    let staging = stage(&jpeg)?;
    let cx = context(&options.root)?;
    let report = run_in(options, &snap, &staging, object_sha256, &cx);
    let _ = std::fs::remove_file(&staging);
    cx.drain_and_finalize();
    report
}

fn run_in(
    options: &Options,
    snap: &wire::SnapshotUri,
    staging: &std::path::Path,
    object_sha256: [u8; 32],
    cx: &ReplayCx,
) -> Result<String, String> {
    let mut deployment = ReferenceDeployment::open(&options.root, SITE, cx)
        .map_err(|e| format!("onvif import deployment: {e}"))?;
    let sensor = SensorId::parse(&options.sensor_id).map_err(|e| format!("sensor-id: {e}"))?;
    let stream = StreamId::parse(&options.stream_id).map_err(|e| format!("stream-id: {e}"))?;
    let mut request = FileIngestRequest::new(staging.to_path_buf(), sensor, stream)
        .with_receive_time(TimestampNs(options.receive_time_ns));
    // A Profile T snapshot is one JPEG frame, i.e. a single-frame MJPEG stream.
    request.format_hint = Some(FileFormatHint::JpegStream);
    let imported = FileIngestAdapter::ingest(request, cx, &mut deployment)
        .map_err(|e| format!("onvif import ingest: {e}"))?;
    let retained = RetainedFileImport::open(
        &deployment,
        imported.import_identity,
        RetainedReadLimits::default(),
        cx,
    )
    .map_err(|e| format!("onvif import retained: {e}"))?;
    let manifest = retained.manifest().clone();
    // The report names the fetched JPEG, not a different staged file or a chunk digest.
    if manifest.input_sha256.bytes() != object_sha256 {
        return Err("fetched JPEG SHA-256 differs from retained input SHA-256".to_owned());
    }
    let (xhost, xport, xpath, _) = parse_url(&options.xaddr)?;
    let (sphot, sport, spath, _) = parse_url(&snap.uri)?;
    Ok(render(&Report {
        xaddr_host: xhost,
        xaddr_port: xport,
        xaddr_path: xpath,
        snapshot_host: sphot,
        snapshot_port: sport,
        snapshot_path: spath,
        bytes: manifest.input_bytes,
        jpeg_sha256: object_sha256,
        import_identity: imported.import_identity.to_text(),
        import_outcome: imported.outcome.as_str().to_owned(),
        media_format: manifest.format.clone(),
        import_root: retained.import_root().to_text(),
        valid_until: snap.valid_until.clone(),
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
    let _ = writeln!(out, "  \"onvif_service\": {{");
    let _ = writeln!(out, "    \"host\": \"{}\",", r.xaddr_host);
    let _ = writeln!(out, "    \"port\": {},", r.xaddr_port);
    let _ = writeln!(out, "    \"path\": \"{}\"", r.xaddr_path);
    let _ = writeln!(out, "  }},");
    let _ = writeln!(out, "  \"snapshot\": {{");
    let _ = writeln!(out, "    \"host\": \"{}\",", r.snapshot_host);
    let _ = writeln!(out, "    \"port\": {},", r.snapshot_port);
    let _ = writeln!(out, "    \"path\": \"{}\"", r.snapshot_path);
    let _ = writeln!(out, "  }},");
    let _ = writeln!(out, "  \"bytes\": {},", r.bytes);
    let _ = writeln!(
        out,
        "  \"jpeg_sha256\": \"sha256:{}\",",
        hex(&r.jpeg_sha256)
    );
    let _ = writeln!(out, "  \"import_identity\": \"{}\",", r.import_identity);
    let _ = writeln!(out, "  \"import_outcome\": \"{}\",", r.import_outcome);
    let _ = writeln!(out, "  \"media_format\": \"{}\",", r.media_format);
    let _ = writeln!(out, "  \"import_root\": \"{}\",", r.import_root);
    if let Some(v) = &r.valid_until {
        let _ = writeln!(out, "  \"valid_until\": \"{v}\",");
    } else {
        let _ = writeln!(out, "  \"valid_until\": null,");
    }
    let _ = writeln!(out, "  \"owner_authorized\": true,");
    let _ = writeln!(out, "  \"media_continuity\": \"unverified\",");
    let _ = writeln!(
        out,
        "  \"note\": \"Single ONVIF Profile T snapshot (JPEG) negotiated with GetProfiles + GetSnapshotUri and fetched over plain HTTP; no vendor cloud involved. A single frame is not a continuity-checked stream.\""
    );
    let _ = writeln!(out, "}}");
    out
}

fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() > MAX_ARGS {
        return malformed("too many arguments");
    }
    let mut opts = Options {
        xaddr: String::new(),
        root: PathBuf::new(),
        sensor_id: String::new(),
        stream_id: String::new(),
        receive_time_ns: 0,
        owner_authorized: false,
        profile: None,
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
            "--xaddr" => {
                let v = next.ok_or("--xaddr requires a value")?;
                opts.xaddr = v.to_owned();
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
            "--profile" => {
                let v = next.ok_or("--profile requires a value")?;
                opts.profile = Some(v.to_owned());
                i += 2;
            }
            "--max-source-bytes" => {
                let v = next.ok_or("--max-source-bytes requires a value")?;
                let n: u64 = v
                    .parse()
                    .map_err(|_| "--max-source-bytes must be a number")?;
                if n == 0 || n > MAX_ALLOWED_SOURCE_BYTES {
                    return malformed("--max-source-bytes must be 1..=67108864");
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
    if opts.xaddr.is_empty() {
        return malformed("--xaddr is required");
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
        return malformed("refused: pass --owner-authorized to attest the device and its media are yours");
    }
    Ok(opts)
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
            eprintln!("fss-capture-onvif: {e}");
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
            eprintln!("fss-capture-onvif: {e}");
            std::process::ExitCode::from(70)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

    /// A canned Media1 GetProfilesResponse with one JPEG-capable profile.
    const GET_PROFILES_RESPONSE: &str = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"",
        " xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\"",
        " xmlns:tt=\"http://www.onvif.org/ver10/schema\">",
        "<s:Body>",
        "<trt:GetProfilesResponse>",
        "<trt:Profiles token=\"Profile_1\">",
        "<tt:Name>Profile_1</tt:Name>",
        "<tt:VideoEncoderConfiguration>",
        "<tt:Encoding>JPEG</tt:Encoding>",
        "<tt:Resolution><tt:Width>640</tt:Width><tt:Height>480</tt:Height></tt:Resolution>",
        "</tt:VideoEncoderConfiguration>",
        "</trt:Profiles>",
        "</trt:GetProfilesResponse>",
        "</s:Body>",
        "</s:Envelope>"
    );

    struct Directory(PathBuf);
    impl Directory {
        fn new(label: &str) -> Test<Self> {
            for attempt in 0..100 {
                let path = std::env::temp_dir().join(format!(
                    "fss-onvif-import-{label}-{}-{attempt}",
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

    /// Read a full request (head + any Content-Length body) off a loopback connection.
    fn read_request(s: &mut TcpStream) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 1024];
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        loop {
            match s.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    out.extend_from_slice(&chunk[..n]);
                    if out.windows(4).any(|w| w == b"\r\n\r\n") {
                        // Head is present; drain a short window for the POST body, then stop.
                        s.set_read_timeout(Some(Duration::from_millis(60))).unwrap();
                        match s.read(&mut chunk) {
                            Ok(0) | Err(_) => {}
                            Ok(m) => out.extend_from_slice(&chunk[..m]),
                        }
                        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        out
    }

    /// A loopback ONVIF Media1 server: routes GetProfiles, GetSnapshotUri, and the JPEG GET,
    /// then stops after three connections.
    fn serve_onvif(jpeg: Vec<u8>, port_tx: std::sync::mpsc::Sender<u16>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        port_tx.send(port).unwrap();
        let mut served = 0;
        for stream in listener.incoming() {
            let mut s = match stream {
                Ok(s) => s,
                Err(_) => break,
            };
            let req = String::from_utf8_lossy(&read_request(&mut s)).to_string();
            let body: Vec<u8> = if req.contains("GetProfiles") {
                GET_PROFILES_RESPONSE.as_bytes().to_vec()
            } else if req.contains("GetSnapshotUri") {
                format!(
                    concat!(
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
                        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"",
                        " xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\"",
                        " xmlns:tt=\"http://www.onvif.org/ver10/schema\">",
                        "<s:Body>",
                        "<trt:GetSnapshotUriResponse>",
                        "<trt:MediaUri>",
                        "<tt:Uri>http://127.0.0.1:{port}/snapshot.jpg?token=sn4p5h0t</tt:Uri>",
                        "<tt:ValidUntil>2026-10-20T00:05:00Z</tt:ValidUntil>",
                        "</trt:MediaUri>",
                        "</trt:GetSnapshotUriResponse>",
                        "</s:Body>",
                        "</s:Envelope>"
                    ),
                    port = port
                )
                .into_bytes()
            } else {
                jpeg.clone()
            };
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(head.as_bytes());
            let _ = s.write_all(&body);
            let _ = s.flush();
            served += 1;
            if served >= 3 {
                break;
            }
        }
    }

    #[test]
    fn parse_url_splits_host_port_path_query() {
        let (host, port, path, query) =
            parse_url("http://192.168.5.211:8080/onvif/media?x=1&y=2").unwrap();
        assert_eq!(host, "192.168.5.211");
        assert_eq!(port, 8080);
        assert_eq!(path, "/onvif/media");
        assert_eq!(query, "x=1&y=2");
    }

    #[test]
    fn parse_url_defaults_port_and_no_query() {
        let (host, port, path, query) = parse_url("http://cam.local/onvif").unwrap();
        assert_eq!(host, "cam.local");
        assert_eq!(port, 80);
        assert_eq!(path, "/onvif");
        assert!(query.is_empty());
    }

    #[test]
    fn parse_url_rejects_non_http() {
        assert!(parse_url("https://cam/onvif").is_err());
        assert!(parse_url("rtsp://cam/stream").is_err());
        assert!(parse_url("http://:80/onvif").is_err());
    }

    #[test]
    fn http_post_fetches_bounded_body() {
        let body = b"soap-response-body".to_vec();
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            port_tx_send(&listener, tx);
            if let Ok((mut s, _)) = listener.accept() {
                let _ = read_request(&mut s);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
                let _ = s.write_all(&body);
                let _ = s.flush();
            }
        });
        let port = rx.recv().unwrap();
        let got = http_post("127.0.0.1", port, "/onvif", "action", b"req", 1024).unwrap();
        assert_eq!(got, b"soap-response-body");
        t.join().unwrap();
    }

    fn port_tx_send(
        listener: &std::net::TcpListener,
        tx: std::sync::mpsc::Sender<u16>,
    ) {
        tx.send(listener.local_addr().unwrap().port())
            .unwrap();
    }

    #[test]
    fn http_post_refuses_non_200() {
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            tx.send(listener.local_addr().unwrap().port()).unwrap();
            if let Ok((mut s, _)) = listener.accept() {
                let _ = read_request(&mut s);
                let body = b"fault".to_vec();
                let resp = format!(
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
                let _ = s.write_all(&body);
                let _ = s.flush();
            }
        });
        let port = rx.recv().unwrap();
        let err = http_post("127.0.0.1", port, "/onvif", "action", b"req", 1024).unwrap_err();
        assert!(err.contains("500"), "{err}");
        t.join().unwrap();
    }

    #[test]
    fn refuses_missing_owner_attestation() {
        let args = vec![
            "--xaddr".into(),
            "http://127.0.0.1:1/onvif".into(),
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
    fn unknown_argument_diagnostic_owns_its_formatted_message() {
        let error = parse(&["--not-an-option".to_owned()]).unwrap_err();
        assert_eq!(error, "unknown argument: --not-an-option");
    }

    #[test]
    fn loopback_onvif_snapshot_end_to_end() -> Test {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/media/mjpeg/mjpeg_clean_3frames.mjpeg");
        let jpeg = std::fs::read(&fixture)?;
        let expected_hash = ContentDigest::sha256(&jpeg);
        let expected_bytes = jpeg.len() as u64;
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || serve_onvif(jpeg, tx));
        let port = rx.recv_timeout(Duration::from_secs(5))?;
        let directory = Directory::new("e2e")?;
        let opts = Options {
            xaddr: format!("http://127.0.0.1:{port}/onvif/media"),
            root: directory.0.join("deployment"),
            sensor_id: "sensor:onvif-e2e".to_owned(),
            stream_id: "stream:onvif-e2e".to_owned(),
            receive_time_ns: 1_000_000_000,
            owner_authorized: true,
            profile: None,
            max_source_bytes: DEFAULT_MAX_SOURCE_BYTES,
        };
        let report = run(&opts)?;
        t.join().map_err(|_| "loopback server panicked")?;
        let parsed = fss_cli::json_input::parse(&report)?;
        let fields = parsed.object().ok_or("report object")?;
        assert_eq!(
            fields.get("schema").and_then(|v| v.text()),
            Some(REPORT_SCHEMA)
        );
        assert_eq!(
            fields.get("jpeg_sha256").and_then(|v| v.text()),
            Some(expected_hash.to_text().as_str())
        );
        assert_eq!(
            fields.get("bytes").and_then(|v| v.integer()),
            Some(i128::from(expected_bytes))
        );
        let import_identity = ContentDigest::parse(
            fields
                .get("import_identity")
                .and_then(|v| v.text())
                .ok_or("import identity")?,
        )?;
        let cx = context(&opts.root)?;
        let deployment = ReferenceDeployment::open(&opts.root, SITE, &cx)?;
        let limits = RetainedReadLimits::default();
        let retained = RetainedFileImport::open(&deployment, import_identity, limits, &cx)?;
        assert_eq!(retained.manifest().input_sha256, expected_hash);
        assert_eq!(retained.manifest().input_bytes, expected_bytes);
        assert_eq!(retained.verify_source(&deployment, limits, &cx)?, expected_hash);
        assert_eq!(
            fields.get("import_root").and_then(|v| v.text()),
            Some(retained.import_root().to_text().as_str())
        );
        cx.drain_and_finalize();
        assert!(report.contains("127.0.0.1"), "report:\n{report}");
        assert!(report.contains("/onvif/media"), "report:\n{report}");
        assert!(report.contains("/snapshot.jpg"), "report:\n{report}");
        assert!(
            !report.contains("sn4p5h0t"),
            "snapshot query token leaked: {report}"
        );
        assert!(report.contains("\"media_continuity\": \"unverified\""), "report:\n{report}");
        Ok(())
    }

    #[test]
    fn a_different_fetched_hash_cannot_be_reported_for_the_retained_input() -> Test {
        let directory = Directory::new("hash-binding")?;
        let staging = directory.0.join("staged.jpg");
        let body = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/media/mjpeg/mjpeg_clean_3frames.mjpeg"
        ));
        std::fs::write(&staging, body)?;
        let snap = wire::SnapshotUri {
            uri: "http://127.0.0.1:1/snapshot.jpg".to_owned(),
            valid_until: None,
        };
        let options = Options {
            xaddr: "http://127.0.0.1:1/onvif".to_owned(),
            root: directory.0.join("deployment"),
            sensor_id: "sensor:onvif-hash-binding".to_owned(),
            stream_id: "stream:onvif-hash-binding".to_owned(),
            receive_time_ns: 1_000_000_000,
            owner_authorized: true,
            profile: None,
            max_source_bytes: DEFAULT_MAX_SOURCE_BYTES,
        };
        let cx = context(&options.root)?;
        let result = run_in(&options, &snap, &staging, sha256(b"different fetched jpeg"), &cx);
        cx.drain_and_finalize();
        assert_eq!(
            result
                .err()
                .ok_or("mismatched source hash produced a report")?,
            "fetched JPEG SHA-256 differs from retained input SHA-256",
        );
        Ok(())
    }
}
