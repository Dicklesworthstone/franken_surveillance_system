#![forbid(unsafe_code)]

use super::*;
use fss_reference::onvif::http::HttpTotals;
use fss_reference::onvif::wire;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

type Test<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const JPEG: &[u8] = include_bytes!("../../../tests/fixtures/retained_file_8x8.jpg");
const PROFILES: &str = concat!(
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\"><s:Body><trt:GetProfilesResponse>",
    "<trt:Profiles token=\"video\"><tt:Name>Camera</tt:Name><tt:VideoEncoderConfiguration><tt:Encoding>JPEG</tt:Encoding><tt:Resolution><tt:Width>8</tt:Width><tt:Height>8</tt:Height></tt:Resolution></tt:VideoEncoderConfiguration></trt:Profiles>",
    "</trt:GetProfilesResponse></s:Body></s:Envelope>"
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

fn options(root: PathBuf) -> Options {
    Options {
        xaddr: "http://127.0.0.1:8080/onvif/media".into(),
        peer: None,
        root,
        sensor_id: "sensor:onvif-test".into(),
        stream_id: "stream:onvif-test".into(),
        receive_time_ns: 1_000_000_000,
        profile: Some("video".into()),
        max_source_bytes: DEFAULT_MAX_SOURCE_BYTES,
        timeout_ms: 2000,
    }
}

fn arguments() -> Vec<String> {
    [
        "--xaddr",
        "http://127.0.0.1:8080/onvif/media",
        "--root",
        "/tmp/fss-onvif-parse",
        "--sensor-id",
        "sensor:test",
        "--stream-id",
        "stream:test",
        "--receive-time-ns",
        "1000000000",
        "--owner-authorized",
    ]
    .map(str::to_owned)
    .to_vec()
}

#[test]
fn arguments_pin_destinations_and_refuse_implicit_authority() -> Test {
    let options = parse(&arguments())?;
    assert_eq!(
        options.plan()?.media.peer(),
        "127.0.0.1:8080".parse::<SocketAddr>()?
    );
    let mut named = arguments();
    named[1] = "http://camera.invalid:8080/onvif/media".into();
    assert!(parse(&named).is_err());
    named.extend(["--peer", "127.0.0.1:8080"].map(str::to_owned));
    assert_eq!(
        parse(&named)?.plan()?.media.authority(),
        "camera.invalid:8080"
    );
    let mut ipv6 = arguments();
    ipv6[1] = "http://[::1]:8080/onvif/media".into();
    assert_eq!(
        parse(&ipv6)?.plan()?.media.peer(),
        "[::1]:8080".parse::<SocketAddr>()?
    );
    for url in [
        "http://user@127.0.0.1:8080/onvif/media",
        "http://127.0.0.1:8080/onvif/media?secret=TOKEN",
        "http://127.0.0.1:8080/onvif/../admin",
        "http://127.0.0.1:8080/onvif\r\nheader",
        "https://127.0.0.1:8080/onvif/media",
    ] {
        let mut args = arguments();
        args[1] = url.into();
        assert!(parse(&args).is_err());
    }
    let mut missing = arguments();
    missing.pop();
    assert!(parse(&missing).is_err());
    for (key, value) in [
        ("--timeout-ms", "0"),
        ("--timeout-ms", "60001"),
        ("--max-source-bytes", "0"),
        ("--max-source-bytes", "67108865"),
        ("--profile", ""),
        ("--root", "/tmp/duplicate"),
    ] {
        let mut args = arguments();
        args.extend([key, value].map(str::to_owned));
        assert!(parse(&args).is_err());
    }
    let error = parse(&["--PRIVATE-TOKEN".into()])
        .err()
        .ok_or("accepted unknown flag")?;
    assert!(!error.contains("PRIVATE"));
    Ok(())
}

fn read_request(stream: &mut TcpStream) -> Test<String> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut bytes = Vec::new();
    loop {
        if bytes.len() > 65536 {
            return Err("request limit".into());
        }
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = std::str::from_utf8(&bytes[..end])?;
            let count = head
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .map(str::parse::<usize>)
                .transpose()?
                .unwrap_or(0);
            if bytes.len() >= end + 4 + count {
                return Ok(String::from_utf8(bytes)?);
            }
        }
        let mut chunk = [0; 2048];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err("early EOF".into());
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
}

fn serve(listener: TcpListener, other_origin: bool) -> Test {
    let port = listener.local_addr()?.port();
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(4);
    for index in 0..if other_origin { 2 } else { 3 } {
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(stream) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(error) => return Err(error.into()),
            }
        };
        let request = read_request(&mut stream)?;
        let uri_port = if other_origin { 1 } else { port };
        let snapshot = format!(
            "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\"><s:Body><trt:GetSnapshotUriResponse><trt:MediaUri><tt:Uri>http://127.0.0.1:{uri_port}/PRIVATE-PATH/snapshot.jpg?token=PRIVATE-QUERY</tt:Uri></trt:MediaUri></trt:GetSnapshotUriResponse></s:Body></s:Envelope>"
        );
        let body = match index {
            0 => PROFILES.as_bytes(),
            1 => snapshot.as_bytes(),
            _ => JPEG,
        };
        if index == 2 {
            assert!(
                request.starts_with("GET /PRIVATE-PATH/snapshot.jpg?token=PRIVATE-QUERY HTTP/1.1")
            );
            assert!(!request.contains("Authorization:"));
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")?;
            for chunk in body.chunks(13) {
                stream.write_all(format!("{:x}\r\n", chunk.len()).as_bytes())?;
                stream.write_all(chunk)?;
                stream.write_all(b"\r\n")?;
            }
            stream.write_all(b"0\r\n\r\n")?;
        } else {
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes())?;
            stream.write_all(body)?;
        }
    }
    Ok(())
}

fn fixture(root: PathBuf, other_origin: bool) -> Test<Result<String, &'static str>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let mut options = options(root);
    options.xaddr = format!("http://{}/onvif/media", listener.local_addr()?);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| serve(listener, other_origin));
        let result = run(&options);
        worker.join().map_err(|_| "loopback panic")??;
        Ok(result)
    })
}

#[test]
fn real_snapshot_transport_retains_and_reopens_exact_jpeg_without_token_leaks() -> Test {
    let directory = Directory::new("native-custody")?;
    let root = directory.0.join("deployment");
    let report = fixture(root.clone(), false)??;
    let parsed = fss_cli::json_input::parse(&report)?;
    let fields = parsed.object().ok_or("report object")?;
    assert_eq!(
        fields.get("schema").and_then(|value| value.text()),
        Some(REPORT_SCHEMA)
    );
    assert_eq!(
        fields
            .get("media_continuity")
            .and_then(|value| value.text()),
        Some("unverified")
    );
    assert_eq!(
        fields.get("bytes").and_then(|value| value.integer()),
        Some(JPEG.len() as i128)
    );
    let digest = ContentDigest::sha256(JPEG);
    assert_eq!(
        fields.get("jpeg_sha256").and_then(|value| value.text()),
        Some(digest.to_text().as_str())
    );
    let identity = ContentDigest::parse(
        fields
            .get("import_identity")
            .and_then(|value| value.text())
            .ok_or("import identity")?,
    )?;
    let cx = context(&root, DEFAULT_MAX_SOURCE_BYTES)?;
    let deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let limits = RetainedReadLimits::default();
    let retained = RetainedFileImport::open(&deployment, identity, limits, &cx)?;
    assert_eq!(retained.manifest().input_sha256, digest);
    assert_eq!(retained.verify_source(&deployment, limits, &cx)?, digest);
    cx.drain_and_finalize();
    assert!(!report.contains("PRIVATE-PATH"));
    assert!(!report.contains("PRIVATE-QUERY"));
    assert!(report.contains("[redacted]"));
    Ok(())
}

#[test]
fn unapproved_snapshot_origin_creates_no_deployment() -> Test {
    let directory = Directory::new("scope-refusal")?;
    let root = directory.0.join("deployment");
    assert_eq!(fixture(root.clone(), true)?, Err(SCOPE));
    assert!(!root.exists());
    Ok(())
}

#[test]
fn private_staging_is_unique_and_cleans_up_after_cancellation() -> Test {
    let directory = Directory::new("private-stage")?;
    let cx = context(&directory.0, DEFAULT_MAX_SOURCE_BYTES)?;
    let mut first = staging::Source::new(JPEG, &cx)?;
    let second = staging::Source::new(JPEG, &cx)?;
    assert_ne!(first.path(), second.path());
    assert_eq!(std::fs::read(first.path())?, JPEG);
    let first_path = first.path().to_path_buf();
    let second_path = second.path().to_path_buf();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(first.path())?.permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(first.path().parent().ok_or("parent")?)?
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    first.close()?;
    assert!(!first_path.exists());
    assert!(second_path.exists());
    cx.request_cancellation();
    assert!(staging::Source::new(JPEG, &cx).is_err());
    drop(second);
    assert!(!second_path.exists());
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn fetched_digest_must_match_retained_source_before_success_report() -> Test {
    let directory = Directory::new("custody-refusal")?;
    let options = options(directory.0.join("deployment"));
    let cx = context(&options.root, options.max_source_bytes)?;
    let staged = staging::Source::new(JPEG, &cx)?;
    let snapshot = Snapshot {
        profile: wire::parse_profiles(PROFILES.as_bytes())?.remove(0),
        uri: wire::SnapshotUri {
            uri: "http://127.0.0.1:8080/snapshot.jpg".into(),
            valid_until: None,
        },
        jpeg: JPEG.to_vec(),
        source_digest: ContentDigest::sha256(b"different source"),
        network: HttpTotals::default(),
    };
    assert_eq!(
        retain(&options, &options.plan()?, &snapshot, staged.path(), &cx),
        Err(CUSTODY)
    );
    drop(staged);
    cx.drain_and_finalize();
    Ok(())
}
