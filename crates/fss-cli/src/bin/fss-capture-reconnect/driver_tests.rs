#![forbid(unsafe_code)]
use super::*;
use fss_core::ContentDigest;
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::thread;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const JPEG: &[u8] = include_bytes!("../../../../fss-codec-mjpeg/tests/fixtures/gray.jpg");

struct Directory(PathBuf);
impl Directory {
    fn new(name: &str) -> Result<Self, io::Error> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!("fss-reconnect-cli-{name}-{}-{attempt}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {},
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::other("owned test directory bound"))
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn options(root: &std::path::Path, peer: std::net::SocketAddr, generations: &str, after_complete: &str) -> Result<Options, &'static str> {
    let digest = ContentDigest::sha256(b"reconnect-cli-native-test").to_text();
    let args: Vec<OsString> = ["--root", root.to_str().ok_or("UTF-8 path")?, "--peer", &peer.to_string(),
        "--host", "camera.invalid", "--target", "/stream", "--source", &digest,
        "--generations", generations, "--receive-clock", &digest, "--retention-evidence", &digest,
        "--owner-authorized", "yes", "--plaintext", "yes", "--retain-originals", "yes",
        "--timeout-ms", "5000", "--initial-backoff-ms", "1", "--maximum-backoff-ms", "2", "--after-complete", after_complete]
        .into_iter().map(Into::into).collect();
    let mut options = Options::parse(&args)?;
    options.approve = Some(options.approval());
    Ok(options)
}
fn response() -> Vec<u8> {
    let mut body = format!("--camera\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n", JPEG.len()).into_bytes();
    body.extend_from_slice(JPEG); body.extend_from_slice(b"\r\n--camera--\r\n");
    let mut result = format!("HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=camera\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    result.extend(body); result
}
fn read_request(socket: &mut TcpStream) -> io::Result<()> {
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        if request.len() >= 4096 { return Err(io::Error::other("request bound")); }
        let mut byte = [0];
        if socket.read(&mut byte)? == 0 { return Err(io::ErrorKind::UnexpectedEof.into()); }
        request.push(byte[0]);
    }
    if !request.starts_with(b"GET /stream HTTP/1.1\r\n") { return Err(io::Error::other("wrong request")); }
    Ok(())
}
fn serve(listener: TcpListener, responses: Vec<Vec<u8>>) -> thread::JoinHandle<io::Result<usize>> {
    thread::spawn(move || {
        listener.set_nonblocking(true)?;
        let deadline = Instant::now() + Duration::from_secs(6);
        let mut served = 0;
        for response in responses {
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => thread::sleep(Duration::from_millis(1)),
                    Err(e) => return Err(e),
                }
            };
            read_request(&mut socket)?;
            socket.set_write_timeout(Some(Duration::from_secs(3)))?;
            socket.write_all(&response)?;
            served += 1;
        }
        Ok(served)
    })
}
fn joined(handle: thread::JoinHandle<io::Result<usize>>) -> Result<usize, io::Error> {
    handle.join().map_err(|_| io::Error::other("fixture thread panicked"))?
}

#[test]
fn real_truncation_is_retained_then_reacquired_in_the_next_explicit_generation() -> TestResult {
    let directory = Directory::new("truncation")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let options = options(&directory.0.join("archive"), listener.local_addr()?, "40,50", "no")?;
    let truncated = b"HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=camera\r\nContent-Length: 1000\r\n\r\n--camera\r\n".to_vec();
    let server = serve(listener, vec![truncated, response()]);
    let mut out = Vec::new(); let result = capture(&options, &mut out);
    assert_eq!(joined(server)?, 2); assert_eq!(result, Ok(true));
    let text = String::from_utf8(out)?;
    assert!(text.contains("\"outcome\":\"source_failed\""));
    assert!(text.contains("\"generation\":\"40\""));
    assert!(text.contains("\"generation\":\"50\""));
    assert!(!text.contains("\"generation\":\"41\""));
    assert!(text.contains("\"connections_started\":2"));
    assert!(text.contains("\"frames_taken\":1"));
    assert!(text.contains("\"unpublished_received_bytes\":0"));
    assert!(text.contains("\"capture_continuity\":false"));
    let first_boundary = text.find("\"kind\":\"boundary_verified\"").ok_or("boundary")?;
    let second_connect = text.rfind("\"kind\":\"connected\"").ok_or("second connect")?;
    assert!(first_boundary < second_connect);
    // The same source namespace cannot be restarted even with its exact acquisition approval.
    let mut rerun = Vec::new(); assert_eq!(capture(&options, &mut rerun), Ok(false));
    assert!(String::from_utf8(rerun)?.contains("\"connect_attempts\":0"));
    Ok(())
}
#[test]
fn complete_responses_reconnect_only_when_explicitly_approved() -> TestResult {
    for (after_complete, expected) in [("no", 1), ("yes", 2)] {
        let directory = Directory::new(after_complete)?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let options = options(&directory.0.join("archive"), listener.local_addr()?, "1,3", after_complete)?;
        let server = serve(listener, vec![response(); expected]);
        let mut out = Vec::new(); let result = capture(&options, &mut out);
        assert_eq!(joined(server)?, expected); assert_eq!(result, Ok(true));
        let text = String::from_utf8(out)?;
        assert!(text.contains(&format!("\"connections_started\":{expected}")));
        assert!(text.contains(&format!("\"frames_taken\":{expected}")));
    }
    Ok(())
}
#[test]
fn http_status_denial_is_terminal_and_never_uses_the_next_reserved_slot() -> TestResult {
    let directory = Directory::new("denied")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let options = options(&directory.0.join("archive"), listener.local_addr()?, "4,5", "yes")?;
    let server = serve(listener, vec![b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n".to_vec()]);
    let mut out = Vec::new(); let result = capture(&options, &mut out);
    assert_eq!(joined(server)?, 1); assert_eq!(result, Ok(false));
    let text = String::from_utf8(out)?;
    assert!(text.contains("\"connections_started\":1"));
    assert!(text.contains("NotRetryable"));
    assert!(text.contains("\"frames_taken\":0"));
    assert!(text.contains("\"request_satisfied\":false"));
    Ok(())
}
struct FailingBoundary { bytes: Vec<u8>, failed: bool }
impl Write for FailingBoundary {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.failed && bytes.windows(b"boundary_verified".len()).any(|w| w == b"boundary_verified") {
            self.failed = true; return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.bytes.extend_from_slice(bytes); Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
#[test]
fn output_failure_at_the_boundary_prevents_a_second_connect() -> TestResult {
    let directory = Directory::new("output")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let options = options(&directory.0.join("archive"), listener.local_addr()?, "7,9", "yes")?;
    let server = serve(listener, vec![response()]);
    let mut out = FailingBoundary { bytes: Vec::new(), failed: false };
    let result = capture(&options, &mut out);
    assert_eq!(joined(server)?, 1); assert_eq!(result, Ok(false)); assert!(out.failed);
    let text = String::from_utf8(out.bytes)?;
    assert!(text.contains("ERR-CAPTURE-RECONNECT-OUTPUT-001"));
    assert!(text.contains("\"connections_started\":1"));
    assert!(text.contains("\"released\":false"));
    Ok(())
}
#[test]
fn stale_approval_and_failed_admission_output_create_no_archive_or_connection() -> TestResult {
    let directory = Directory::new("no-io")?;
    let root = directory.0.join("absent");
    let mut options = options(&root, "127.0.0.1:9".parse()?, "1,2", "no")?;
    options.approve = Some(ContentDigest::sha256(b"stale"));
    let mut out = Vec::new();
    assert_eq!(capture(&options, &mut out), Err("ERR-CAPTURE-RECONNECT-APPROVAL-STALE-001"));
    assert!(out.is_empty()); assert!(!root.exists());
    options.approve = Some(options.approval());
    struct Closed;
    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> { Err(io::ErrorKind::BrokenPipe.into()) }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }
    assert_eq!(capture(&options, &mut Closed), Err("ERR-CAPTURE-RECONNECT-OUTPUT-001"));
    assert!(!root.exists());
    Ok(())
}
#[test]
fn transcript_keeps_a_terminal_reserve_and_finite_interrupted_writes() {
    let mut out = Vec::new();
    let mut log = Transcript { out: &mut out, used: 0, maximum: RESERVE * 2, sequence: 0 };
    assert!(matches!(log.emit("too_large", string(&"x".repeat(RESERVE)), false), Err(Failure::Output)));
    assert!(log.emit("finish", "{}".into(), true).is_ok());
    struct Interrupted;
    impl Write for Interrupted {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> { Err(io::ErrorKind::Interrupted.into()) }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }
    assert!(write_bounded(&mut Interrupted, b"x").is_err());
}
