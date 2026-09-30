#![forbid(unsafe_code)]
//! End-to-end acquisition descriptor -> process-state loss -> local-only source recovery.
use super::*;
use fss_geometry::WorkBudget;
use fss_publication::NeverCancel;
use fss_reference::ingest::http_archive::recovery::HttpWireRecoveryState;

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
            let path = std::env::temp_dir().join(format!(
                "fss-recovery-capture-{name}-{}-{attempt}", std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::other("owned test directory bound"))
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
fn options(root: &std::path::Path, peer: std::net::SocketAddr,
    generations: &str, after_complete: &str) -> Result<Options, &'static str>
{
    let digest = ContentDigest::sha256(b"reconnect-cli-native-test").to_text();
    let args: Vec<OsString> = [
        "--root", root.to_str().ok_or("UTF-8 path")?, "--peer", &peer.to_string(),
        "--host", "camera.invalid", "--target", "/stream", "--source", &digest,
        "--generations", generations, "--receive-clock", &digest,
        "--retention-evidence", &digest, "--owner-authorized", "yes", "--plaintext", "yes",
        "--retain-originals", "yes", "--timeout-ms", "5000", "--initial-backoff-ms", "1",
        "--maximum-backoff-ms", "2", "--after-complete", after_complete,
    ].into_iter().map(Into::into).collect();
    let mut options = Options::parse(&args)?;
    options.approve = Some(options.approval());
    Ok(options)
}
fn response() -> Vec<u8> {
    let mut body = format!(
        "--camera\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n", JPEG.len(),
    ).into_bytes();
    body.extend_from_slice(JPEG);
    body.extend_from_slice(b"\r\n--camera--\r\n");
    let mut result = format!("HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=camera\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    result.extend(body);
    result
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
    if !request.starts_with(b"GET /stream HTTP/1.1\r\n") {
        return Err(io::Error::other("wrong request"));
    }
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
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(1))
                    }
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

fn keys(text: &str) -> Result<Vec<HttpWireRecoveryKey>, Box<dyn std::error::Error>> {
    let mut keys = Vec::new();
    for row in text.lines().filter(|row| row.contains("\"kind\":\"wire_prepared\"")) {
        let value = row.split_once("\"recovery_key\":\"").ok_or("missing recovery key")?.1;
        let key = value.split_once('"').ok_or("unterminated recovery key")?.0;
        keys.push(HttpWireRecoveryKey::from_text(key)?);
    }
    Ok(keys)
}
fn storage() -> LocalPublicationLimits {
    LocalPublicationLimits::new(8192, MAX_MANIFEST_CHILDREN, 8192, 65536,
        SpoolLimits::new(65536, 1024 * 1024 * 1024, 16 * 1024 * 1024, 131072))
}

#[test]
fn opt_in_keys_round_trip_across_real_connections_and_default_reports_have_none() -> TestResult {
    for enabled in [false, true] {
        let directory = Directory::new(if enabled { "keys" } else { "legacy-keys" })?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut options = options(&directory.0.join("archive"), listener.local_addr()?, "11,19", "yes")?;
        options.recoverable = enabled;
        options.approve = Some(options.approval());
        let server = serve(listener, vec![response(), response()]);
        let mut out = Vec::new();
        let result = capture(&options, &mut out);
        assert_eq!(joined(server)?, 2);
        assert_eq!(result, Ok(true));
        let text = String::from_utf8(out)?;
        if !enabled { assert!(!text.contains("recovery_key")); continue; }
        let saved = keys(&text)?;
        let mut latest = BTreeMap::new();
        for key in saved {
            assert_eq!(key.scope().stream.source, options.source.bytes());
            assert!(options.generations.contains(&key.scope().stream.generation));
            latest.insert(key.scope().stream.generation, key);
        }
        assert_eq!(latest.len(), 2);
        let mut p = LocalRootPublisher::open(&options.root, storage())?;
        let count = p.visible_roots().count();
        for key in latest.values() {
            assert_eq!(key.inspect(&p, options.archive, &NeverCancel, &mut WorkBudget::new(options.source_work))?, HttpWireRecoveryState::Durable);
            assert_eq!(key.recover(&mut p, options.archive, &NeverCancel, &mut WorkBudget::new(options.source_work))?.pin, key.expected_pin());
        }
        assert_eq!(p.visible_roots().count(), count);
    }
    Ok(())
}

#[test]
fn every_publication_cut_recovers_from_the_real_prepared_jsonl_without_a_camera() -> TestResult {
    for cut in [PublishCutPoint::AfterChildrenVerified, PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite, PublishCutPoint::AfterRootRename]
    {
        let directory = Directory::new(&format!("key-cut-{cut}"))?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut options = options(&directory.0.join("archive"), listener.local_addr()?, "23", "no")?;
        options.recoverable = true;
        options.approve = Some(options.approval());
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:http-key-crash".into(), operation_id: OperationId::parse("operation:http-key-crash")?,
            principal: options.principal.clone(),
            capabilities: STORAGE_CAPS.iter().map(|s| (*s).to_owned()).chain(["ADP-REPLAY-001".to_owned(), "CAP-ADAPTER-NET-001".to_owned()]).collect(),
            deadline: None, priority: 10,
            budgets: BudgetVector::builder().bytes(1024 * 1024 * 1024).storage_operations(1_000_000).build()?,
            privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
            anchor_universe: options.approval(), generation: 1,
        })?;
        authority.validate()?;
        let cx = ReplayCx::from_context_authority(&authority, options.root.clone())?;
        let owner = Owner { cx: &cx, authority: &authority,
            routes: options.plan()?.slots.into_iter().map(|s| s.source.route).collect(),
            start: Instant::now(), deadline: options.timeout_ns };
        let mut p = LocalRootPublisher::open(&options.root, storage())?;
        p.inject_crash_at(cut);
        let mut recording = options.recording()?;
        let server = serve(listener, vec![response()]);
        let mut saved = Vec::new();
        let result = drive(&options, &mut recording, &mut p, &owner,
            &mut Transcript { out: &mut saved, used: 0, maximum: options.report_bytes, sequence: 0, io_failed: false },
            &mut Statistics::default(), None, None);
        // Close the socket and join the fixture before inspecting failures; no detached work.
        drop(recording.retire());
        assert_eq!(joined(server)?, 1);
        cx.drain_and_finalize();
        assert!(result.is_err());
        assert!(p.is_poisoned());
        drop(p);
        let text = String::from_utf8(saved)?;
        assert!(!text.contains("\"kind\":\"wire_durable\""));
        let saved = keys(&text)?;
        assert_eq!(saved.len(), 1);
        let key = &saved[0];
        let mut reopened = LocalRootPublisher::open(&options.root, storage())?;
        let receipt = key.recover(&mut reopened, options.archive, &NeverCancel, &mut WorkBudget::new(options.source_work))?;
        assert_eq!(receipt.pin, key.expected_pin());
        assert_eq!(receipt.pin.reads, 1);
        assert_eq!(reopened.visible_roots().count(), 1);
        // This is source-byte recovery only: not a second connection, parse ACK or decoded image.
        assert_eq!(receipt.local.claims.local, fss_publication::LocalPublicationState::Durable);
    }
    Ok(())
}
