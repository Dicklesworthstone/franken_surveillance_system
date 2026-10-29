#![forbid(unsafe_code)]
//! Real-process native metadata capture against an owned, bounded loopback peer.
//! These fixtures exercise the actual runtime, protocol and custody command wiring;
//! they do not qualify a camera, trusted clock or authenticated scene.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use fss_core::ContentDigest;
use fss_reference::rtsp::metadata_source::NativeMetadataSource;

type Test<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const SITE: &str = "site:native-metadata-cli-test";
const SENSOR: &str = "sensor:private-native-camera";
const PROFILE: &str = "private-native-profile";
const AUTHORITY: &str = "private-native-route.example";
const URL: &str = "rtsp://private-native-route.example/live/";
const ROOT_URI: &str = "rtsp://private-native-route.example/live";
const SESSION: &str = "PRIVATE_NATIVE_SESSION_CANARY";
const NONCE: &str = "PRIVATE_NATIVE_NONCE_CANARY";
const SDP: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=PRIVATE_NATIVE_SDP_CANARY\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:video\r\nm=application 0 RTP/AVP 107\r\na=rtpmap:107 vnd.onvif.metadata/90000\r\na=control:metadata\r\n";
const XML: &[u8] = br#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema"><t:VideoAnalytics><t:Frame UtcTime="2026-10-29T00:00:00Z" Source="PRIVATE_NATIVE_MODULE_CANARY"><t:Object ObjectId="819753"/></t:Frame></t:VideoAnalytics></t:MetadataStream>"#;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "fss-native-capture-cli-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("fixture directory allowance exhausted".into())
    }
    fn root(&self) -> PathBuf {
        self.0.join("deployment")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binary() -> Test<PathBuf> {
    std::env::var_os("FSS_ONVIF_METADATA_BIN")
        .or_else(|| option_env!("CARGO_BIN_EXE_fss-onvif-metadata").map(OsString::from))
        .map(PathBuf::from)
        .ok_or_else(|| "missing real metadata executable; set FSS_ONVIF_METADATA_BIN".into())
}
fn output_bytes(reader: impl Read, exceeded: &AtomicBool) -> io::Result<Vec<u8>> {
    const MAX_OUTPUT: u64 = 1024 * 1024;
    let mut bytes = Vec::new();
    reader.take(MAX_OUTPUT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_OUTPUT {
        exceeded.store(true, Ordering::Release);
        return Err(io::Error::other("fixture output bound exceeded"));
    }
    Ok(bytes)
}
fn run(args: &[OsString]) -> Test<Output> {
    let mut child = Command::new(binary()?)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("missing stdout")?;
    let stderr = child.stderr.take().ok_or("missing stderr")?;
    let exceeded = AtomicBool::new(false);
    thread::scope(|scope| {
        let stdout = scope.spawn(|| output_bytes(stdout, &exceeded));
        let stderr = scope.spawn(|| output_bytes(stderr, &exceeded));
        let deadline = Instant::now() + Duration::from_secs(25);
        let mut timed_out = false;
        let status = loop {
            if exceeded.load(Ordering::Acquire) || Instant::now() >= deadline {
                timed_out = Instant::now() >= deadline;
                let _ = child.kill();
                break child.wait();
            }
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => thread::sleep(Duration::from_millis(2)),
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(error);
                }
            }
        };
        let stdout = stdout.join().map_err(|_| "stdout reader panicked")??;
        let stderr = stderr.join().map_err(|_| "stderr reader panicked")??;
        if timed_out {
            return Err(format!(
                "native capture exceeded fixture deadline: {}",
                String::from_utf8_lossy(&stderr)
            )
            .into());
        }
        Ok(Output {
            status: status?,
            stdout,
            stderr,
        })
    })
}
fn report(output: &Output, success: bool) -> Test<String> {
    assert_eq!(
        output.status.success(),
        success,
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout.clone())?)
}
fn field<'a>(report: &'a str, key: &str) -> Test<&'a str> {
    report
        .lines()
        .filter_map(|line| line.split_once('='))
        .find_map(|(name, value)| (name == key).then_some(value))
        .ok_or_else(|| format!("missing {key}: {report}").into())
}
fn set(args: &mut [OsString], flag: &str, value: &str) -> Test {
    let index = args
        .iter()
        .position(|arg| arg == flag)
        .ok_or("missing fixture flag")?;
    *args
        .get_mut(index + 1)
        .ok_or("missing fixture flag value")? = value.into();
    Ok(())
}
fn args(root: &Path, peer: SocketAddr) -> Vec<OsString> {
    let mut args = vec!["capture-rtp".into(), "--root".into(), root.into()];
    for (key, value) in [
        ("--site", SITE),
        ("--sensor", SENSOR),
        ("--profile", PROFILE),
        ("--authority", AUTHORITY),
        ("--url", URL),
        ("--control-root", ROOT_URI),
        ("--media-index", "1"),
        ("--ingress", "18446744073709551633"),
        ("--stream-generation", "3"),
        ("--ssrc", "42"),
        ("--payload-type", "107"),
        ("--receive-origin-ns", "1700000000000000000"),
        ("--owner-authorized", "yes"),
        ("--plaintext", "yes"),
        ("--retain-source", "yes"),
        ("--capture-ms", "5000"),
        ("--timeout-ms", "15000"),
        ("--max-documents", "1"),
    ] {
        args.extend([OsString::from(key), OsString::from(value)]);
    }
    args.extend([
        "--peer".into(),
        peer.to_string().into(),
        "--device-generation".into(),
        ContentDigest::sha256(b"fixture-camera-generation")
            .to_text()
            .into(),
        "--profile-generation".into(),
        ContentDigest::sha256(b"fixture-profile-generation")
            .to_text()
            .into(),
    ]);
    args
}
fn cold(root: &Path, operation: &str, identity: &str, publication: &str) -> Vec<OsString> {
    vec![
        operation.into(),
        "--root".into(),
        root.into(),
        "--site".into(),
        SITE.into(),
        "--import-id".into(),
        identity.into(),
        "--expected-root".into(),
        publication.into(),
    ]
}
fn listener() -> Test<TcpListener> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

#[derive(Clone, Copy)]
enum Behavior {
    Complete,
    Challenge,
    MissingMarker,
    TruncatedWire,
}
struct Transcript {
    methods: Vec<String>,
    challenge: Option<ContentDigest>,
    packets: Vec<Vec<u8>>,
    teardown: bool,
}
fn request(peer: &mut TcpStream, deadline: Instant) -> Test<Option<(String, u32)>> {
    let mut bytes = Vec::new();
    while bytes.len() < 8192 && Instant::now() < deadline {
        let mut byte = [0];
        match peer.read(&mut byte) {
            Ok(0) if bytes.is_empty() => return Ok(None),
            Ok(0) => return Err("client closed inside RTSP request".into()),
            Ok(_) => bytes.push(byte[0]),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        }
        if bytes.ends_with(b"\r\n\r\n") {
            let text = String::from_utf8(bytes)?;
            assert!(
                !text.to_ascii_lowercase().contains("authorization:"),
                "capture without credentials sent Authorization"
            );
            let method = text
                .split_ascii_whitespace()
                .next()
                .ok_or("empty request")?
                .to_owned();
            let cseq = text
                .split("\r\n")
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("cseq").then_some(value.trim())
                })
                .ok_or("request has no CSeq")?
                .parse()?;
            return Ok(Some((method, cseq)));
        }
    }
    Err("RTSP request exceeded byte or lifetime bound".into())
}
fn response(peer: &mut TcpStream, cseq: u32, headers: &str, body: &str) -> Test {
    peer.write_all(
        format!(
            "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )?;
    Ok(())
}
fn packet(sequence: u16, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, 107 | if marker { 0x80 } else { 0 }];
    bytes.extend(sequence.to_be_bytes());
    bytes.extend(u32::from(sequence).to_be_bytes());
    bytes.extend(42_u32.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
fn wire(packet: &[u8]) -> Test<Vec<u8>> {
    let mut bytes = vec![b'$', 0];
    bytes.extend(u16::try_from(packet.len())?.to_be_bytes());
    bytes.extend_from_slice(packet);
    Ok(bytes)
}
fn serve(listener: TcpListener, behavior: Behavior) -> Test<Transcript> {
    let deadline = Instant::now() + Duration::from_secs(18);
    let mut peer = loop {
        match listener.accept() {
            Ok((peer, _)) => break peer,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(2))
            }
            Err(error) => return Err(error.into()),
        }
    };
    peer.set_read_timeout(Some(Duration::from_millis(200)))?;
    peer.set_write_timeout(Some(Duration::from_secs(2)))?;
    peer.set_nodelay(true)?;
    let mut transcript = Transcript {
        methods: Vec::new(),
        challenge: None,
        packets: Vec::new(),
        teardown: false,
    };
    let (method, cseq) = request(&mut peer, deadline)?.ok_or("missing DESCRIBE")?;
    assert_eq!(method, "DESCRIBE");
    transcript.methods.push(method);
    if matches!(behavior, Behavior::Challenge) {
        let challenge = format!(
            "RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\nWWW-Authenticate: Digest realm=\"owner-approved-anonymous\", nonce=\"{NONCE}\", algorithm=SHA-256, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n"
        );
        transcript.challenge = Some(ContentDigest::sha256(challenge.as_bytes()));
        peer.write_all(challenge.as_bytes())?;
        assert!(
            request(&mut peer, deadline)?.is_none(),
            "capture retried a challenge without credentials"
        );
        return Ok(transcript);
    }
    response(&mut peer, cseq, "Content-Type: application/sdp\r\n", SDP)?;
    let (method, cseq) = request(&mut peer, deadline)?.ok_or("missing SETUP")?;
    assert_eq!(method, "SETUP");
    transcript.methods.push(method);
    response(
        &mut peer,
        cseq,
        &format!(
            "Session: {SESSION};timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=0000002a\r\n"
        ),
        "",
    )?;
    let (method, cseq) = request(&mut peer, deadline)?.ok_or("missing PLAY")?;
    assert_eq!(method, "PLAY");
    transcript.methods.push(method);
    response(&mut peer, cseq, &format!("Session: {SESSION}\r\n"), "")?;
    transcript.packets = vec![
        packet(100, false, b"unknown-prefix"),
        packet(101, true, b"preceding-marker"),
    ];
    if !matches!(behavior, Behavior::TruncatedWire) {
        transcript
            .packets
            .push(packet(102, matches!(behavior, Behavior::Complete), XML));
    }
    let mut bytes = Vec::new();
    for packet in &transcript.packets {
        bytes.extend(wire(packet)?);
    }
    if matches!(behavior, Behavior::TruncatedWire) {
        // A seven-byte terminal suffix can never be reconstructed as a complete datagram.
        bytes.extend([b'$', 0, 0, 20, 0x80, 107, 0]);
    }
    peer.write_all(&bytes)?;
    if matches!(behavior, Behavior::MissingMarker | Behavior::TruncatedWire) {
        peer.shutdown(Shutdown::Write)?;
        // The server's source closes only in explicit failure cases, so success requires
        // the client's actual finite-target TEARDOWN and correlated response.
        assert!(
            request(&mut peer, deadline)?.is_none(),
            "EOF caused an unexpected command"
        );
        return Ok(transcript);
    }
    for _ in 0..8 {
        let (method, cseq) =
            request(&mut peer, deadline)?.ok_or("client closed before TEARDOWN")?;
        transcript.methods.push(method.clone());
        match method.as_str() {
            "TEARDOWN" => {
                response(&mut peer, cseq, &format!("Session: {SESSION}\r\n"), "")?;
                transcript.teardown = true;
                assert!(
                    request(&mut peer, deadline)?.is_none(),
                    "client sent requests after TEARDOWN"
                );
                return Ok(transcript);
            }
            "GET_PARAMETER" | "OPTIONS" => {
                response(&mut peer, cseq, &format!("Session: {SESSION}\r\n"), "")?
            }
            _ => return Err("unexpected method after PLAY".into()),
        }
    }
    Err("RTSP server request bound exceeded".into())
}
fn captured(
    listener: TcpListener,
    args: &[OsString],
    behavior: Behavior,
) -> Test<(Output, Transcript)> {
    thread::scope(|scope| {
        let server = scope.spawn(move || serve(listener, behavior));
        let output = run(args);
        let server = server.join().map_err(|_| "loopback server panicked")?;
        match (output, server) {
            (Ok(output), Ok(transcript)) => Ok((output, transcript)),
            (Ok(output), Err(error)) => Err(format!(
                "loopback failure: {error}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into()),
            (Err(error), _) => Err(error),
        }
    })
}
fn original(root: &Path, digest: &str) -> Test<(NativeMetadataSource, Vec<u8>)> {
    let expected = ContentDigest::parse(digest)?;
    let path = root.join("objects/spool/objects").join(
        digest
            .strip_prefix("sha256:")
            .ok_or("source is not SHA-256")?,
    );
    let bytes = fs::read(path)?;
    assert_eq!(ContentDigest::sha256(&bytes), expected);
    Ok((NativeMetadataSource::decode(&bytes)?, bytes))
}
fn private_report(output: &Output) {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for secret in [
        SENSOR,
        PROFILE,
        AUTHORITY,
        SESSION,
        NONCE,
        "PRIVATE_NATIVE_SDP_CANARY",
        "PRIVATE_NATIVE_MODULE_CANARY",
    ] {
        assert!(!text.contains(secret), "private value leaked: {secret}");
    }
}

#[test]
fn successful_native_capture_tears_down_and_cold_verifies_original_packet_custody() -> Test {
    let directory = Directory::new("complete")?;
    let listener = listener()?;
    let args = args(&directory.root(), listener.local_addr()?);
    let (output, transcript) = captured(listener, &args, Behavior::Complete)?;
    let captured = report(&output, true)?;
    private_report(&output);
    assert_eq!(
        transcript.methods,
        ["DESCRIBE", "SETUP", "PLAY", "TEARDOWN"]
    );
    assert!(transcript.teardown);
    for (key, expected) in [
        ("operation", "capture-rtp"),
        ("source_mode", "native_rtsp_tcp"),
        ("final_source_published", "true"),
        ("durable_publication", "true"),
        ("acquisition_stop", "target_reached"),
        ("teardown_acknowledged", "true"),
        ("remote_session_may_exist", "false"),
        ("processing_complete", "true"),
        ("complete_documents", "1"),
        ("usable_documents", "1"),
        ("native_frame_count", "3"),
        ("native_control_count", "4"),
        ("native_unprocessed_wire_bytes", "0"),
        ("native_omitted_observations", "0"),
    ] {
        assert_eq!(field(&captured, key)?, expected, "{key}");
    }
    let (source, bytes) = original(&directory.root(), field(&captured, "native_source_sha256")?)?;
    assert_eq!(
        source.description().ok_or("missing SDP")?.bytes(),
        SDP.as_bytes()
    );
    assert_eq!(source.records().len(), transcript.packets.len());
    for (actual, expected) in source.records().iter().zip(transcript.packets) {
        assert_eq!(actual.bytes(), expected);
    }
    assert!(
        !bytes
            .windows(SESSION.len())
            .any(|part| part == SESSION.as_bytes())
    );
    for operation in ["inspect-rtp", "verify-rtp"] {
        let output = run(&cold(
            &directory.root(),
            operation,
            field(&captured, "import_identity")?,
            field(&captured, "publication_root")?,
        ))?;
        let verified = report(&output, true)?;
        private_report(&output);
        for key in [
            "import_identity",
            "publication_root",
            "native_source_sha256",
            "source_sha256",
            "replay_report_sha256",
            "native_started_ns",
            "native_ended_ns",
            "processing_complete",
        ] {
            assert_eq!(field(&verified, key)?, field(&captured, key)?, "{key}");
        }
    }
    Ok(())
}

#[test]
fn challenge_without_credentials_is_not_answered_and_retains_its_exact_control_hash() -> Test {
    let directory = Directory::new("challenge")?;
    let listener = listener()?;
    let args = args(&directory.root(), listener.local_addr()?);
    let (output, transcript) = captured(listener, &args, Behavior::Challenge)?;
    let captured = report(&output, false)?;
    private_report(&output);
    assert_eq!(transcript.methods, ["DESCRIBE"]);
    assert_eq!(field(&captured, "final_source_published")?, "true");
    assert_eq!(field(&captured, "acquisition_stop")?, "authentication");
    assert_eq!(field(&captured, "native_control_count")?, "1");
    assert_eq!(field(&captured, "native_frame_count")?, "0");
    assert_eq!(field(&captured, "native_unprocessed_wire_bytes")?, "0");
    assert_eq!(field(&captured, "processing_complete")?, "false");
    let (source, bytes) = original(&directory.root(), field(&captured, "native_source_sha256")?)?;
    assert_eq!(source.controls().len(), 1);
    assert_eq!(source.controls()[0].status(), 401);
    assert_eq!(
        Some(source.controls()[0].wire_digest()),
        transcript.challenge
    );
    assert!(source.controls()[0].progress().is_none());
    assert!(
        !bytes
            .windows(NONCE.len())
            .any(|part| part == NONCE.as_bytes())
    );
    let verified = report(
        &run(&cold(
            &directory.root(),
            "verify-rtp",
            field(&captured, "import_identity")?,
            field(&captured, "publication_root")?,
        ))?,
        true,
    )?;
    assert_eq!(field(&verified, "processing_complete")?, "false");
    assert_eq!(field(&verified, "native_stop")?, "authentication");
    Ok(())
}

#[test]
fn peer_eof_retains_incomplete_xml_or_explicit_unframed_suffix_without_complete_claims() -> Test {
    for behavior in [Behavior::MissingMarker, Behavior::TruncatedWire] {
        let directory = Directory::new("eof")?;
        let listener = listener()?;
        let args = args(&directory.root(), listener.local_addr()?);
        let (output, transcript) = captured(listener, &args, behavior)?;
        let captured = report(&output, false)?;
        private_report(&output);
        assert!(!transcript.teardown);
        assert_eq!(field(&captured, "final_source_published")?, "true");
        assert_eq!(field(&captured, "teardown_acknowledged")?, "false");
        assert_eq!(field(&captured, "processing_complete")?, "false");
        assert_eq!(field(&captured, "usable_documents")?, "0");
        let (source, _) = original(&directory.root(), field(&captured, "native_source_sha256")?)?;
        assert_eq!(source.records().len(), transcript.packets.len());
        for (actual, expected) in source.records().iter().zip(transcript.packets) {
            assert_eq!(actual.bytes(), expected);
        }
        match behavior {
            Behavior::MissingMarker => assert_eq!(source.unprocessed_wire_bytes(), 0),
            Behavior::TruncatedWire => assert_eq!(source.unprocessed_wire_bytes(), 7),
            _ => return Err("unexpected failure fixture".into()),
        }
        let verified = report(
            &run(&cold(
                &directory.root(),
                "verify-rtp",
                field(&captured, "import_identity")?,
                field(&captured, "publication_root")?,
            ))?,
            true,
        )?;
        assert_eq!(field(&verified, "processing_complete")?, "false");
        assert_eq!(
            field(&verified, "native_source_sha256")?,
            field(&captured, "native_source_sha256")?
        );
    }
    Ok(())
}

#[test]
fn invalid_owner_or_stream_pins_refuse_before_socket_or_destination_creation() -> Test {
    for (key, value) in [
        ("--owner-authorized", "no"),
        ("--retain-source", "no"),
        ("--authority", "unapproved.example"),
        ("--payload-type", "95"),
        ("--stream-generation", "0"),
        ("--receive-origin-ns", "-1"),
    ] {
        let directory = Directory::new("invalid")?;
        let listener = listener()?;
        let mut args = args(&directory.root(), listener.local_addr()?);
        set(&mut args, key, value)?;
        let output = run(&args)?;
        assert_eq!(output.status.code(), Some(2), "{key}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("ERR-ONVIF-METADATA-ARGUMENT-001")
        );
        assert!(
            !directory.root().exists(),
            "invalid {key} created a destination"
        );
        match listener.accept() {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            _ => return Err(format!("invalid {key} opened a socket").into()),
        }
    }
    Ok(())
}
