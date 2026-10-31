#![forbid(unsafe_code)]
//! Real loopback RTSP → root-last original datagrams → cold native JPEG replay.
//! Only permission/clock callbacks are fixtures; transport, parsing, custody,
//! reconstruction and luma decoding execute the production implementations.

use std::cell::{Cell, RefCell};
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits, decode_luma};
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_publication::{LocalRootPublisher, NeverCancel};
use fss_reference::rtsp::datagram_archive::{DatagramArchive, DatagramPin};

use super::operation::{self, Effect, Owner, Report};
use super::plan::Options;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const JPEG: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../fss-codec-mjpeg/tests/fixtures/rtp_jpeg/422_32x24_q50_rst0.jpg"
));
const ORACLE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../fss-codec-mjpeg/tests/fixtures/rtp_jpeg/422_32x24_q50_rst0.ffmpeg.luma"
));
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        for _ in 0..256 {
            let path = std::env::temp_dir().join(format!(
                "fss-jpeg-cli-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("fixture directory bound".into())
    }
    fn source(&self) -> PathBuf {
        self.0.join("source")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct FixtureOwner {
    now: Cell<u64>,
    effects: RefCell<Vec<Effect>>,
    network: bool,
    deny: Option<Effect>,
}
impl FixtureOwner {
    fn new(network: bool) -> Self {
        Self {
            now: Cell::new(0),
            effects: RefCell::new(Vec::new()),
            network,
            deny: None,
        }
    }
}
impl Owner for FixtureOwner {
    fn checkpoint(&self, effect: Effect) -> Result<u64, &'static str> {
        self.effects.borrow_mut().push(effect);
        if self.deny == Some(effect)
            || effect == Effect::Secret
            || (effect == Effect::Network && !self.network)
        {
            return Err("ERR-CAPTURE-RTSP-AUTHORITY-001");
        }
        let now = self
            .now
            .get()
            .checked_add(100)
            .ok_or("fixture clock bound")?;
        self.now.set(now);
        Ok(now)
    }
    fn wait(&self, _: Option<u64>) -> Result<(), &'static str> {
        self.checkpoint(Effect::Clock)?;
        // A bounded real wait lets the actual peer run. The explicitly owned
        // virtual clock does not manufacture a media timeout while storage fsyncs.
        std::thread::sleep(Duration::from_millis(1));
        self.checkpoint(Effect::Clock)?;
        Ok(())
    }
}

fn arguments(root: &Path, peer: SocketAddr) -> Test<Vec<OsString>> {
    let mut args: Vec<OsString> = [
        "--root",
        root.to_str().ok_or("non-UTF8 fixture path")?,
        "--peer",
        &peer.to_string(),
        "--authority",
        "camera.test",
        "--presentation",
        "/live/",
        "--control-root",
        "/live",
        "--sensor-id",
        "sensor:jpeg-camera",
        "--stream-id",
        "stream:jpeg",
        "--generation",
        "8",
        "--ingress",
        "11",
        "--ssrc",
        "7",
        "--owner-authorized",
        "yes",
        "--plaintext",
        "yes",
        "--retain-originals",
        "yes",
        "--media-index",
        "1",
        "--read-bytes",
        "13",
        "--max-dimension",
        "64",
        "--max-datagrams",
        "32",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    for (key, value) in [
        ("--anchor", b"fixture source anchor".as_slice()),
        (
            "--receive-clock",
            b"fixture parser completion receive clock".as_slice(),
        ),
        (
            "--retention-evidence",
            b"fixture owner authorizes original RTP and RTCP".as_slice(),
        ),
    ] {
        set(&mut args, key, &ContentDigest::sha256(value).to_text());
    }
    Ok(args)
}
fn set(args: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(index) = args.iter().position(|arg| arg == key) {
        args[index + 1] = value.into();
    } else {
        args.push(key.into());
        args.push(value.into());
    }
}
fn approved(args: &[OsString]) -> Test<Options> {
    let mut options = Options::parse(args)?;
    options.approval = Some(options.digest()?);
    options.admit()?;
    Ok(options)
}
fn replay_arguments(
    args: &[OsString],
    pin: DatagramPin,
    configuration: ContentDigest,
) -> Vec<OsString> {
    let mut replay = vec![OsString::from("replay")];
    replay.extend_from_slice(args);
    for (key, value) in [
        ("--prefix-head", pin.head.to_text()),
        ("--prefix-datagrams", pin.datagrams.to_string()),
        ("--prefix-bytes", pin.payload_bytes.to_string()),
        ("--configuration-evidence", configuration.to_text()),
        ("--reduced-rtcp", "yes".to_owned()),
    ] {
        set(&mut replay, key, &value);
    }
    replay
}

// Assertions inspect the actual JSONL output, not private mutable report counters.
// These helpers extract only fixed test keys and unescaped SHA-256 strings.
fn row<'a>(output: &'a str, kind: &str) -> Test<&'a str> {
    let marker = format!("\"kind\":\"{kind}\"");
    let found = output
        .lines()
        .filter(|line| line.contains(&marker))
        .collect::<Vec<_>>();
    if found.len() != 1 {
        return Err(format!("expected one {kind} row, got {}", found.len()).into());
    }
    Ok(found[0])
}
fn quoted<'a>(row: &'a str, key: &str) -> Test<&'a str> {
    let marker = format!("\"{key}\":\"");
    row.split_once(&marker)
        .and_then(|(_, tail)| tail.split_once('"').map(|(value, _)| value))
        .ok_or_else(|| format!("missing quoted field {key}").into())
}
fn contains_field(row: &str, key: &str, value: &str) {
    assert!(
        row.contains(&format!("\"{key}\":{value}")),
        "missing {key}={value} in {row}"
    );
}
fn finished(report: &mut Report, output: &mut Vec<u8>) -> Test<String> {
    report.finish(output, "null".into(), false)?;
    Ok(std::str::from_utf8(output)?.to_owned())
}

#[test]
fn jpeg_plan_is_pure_exact_approval_is_required_and_every_cli_setting_is_bound() -> Test {
    let directory = Directory::new()?;
    let root = directory.source();
    let args = arguments(&root, "127.0.0.1:8554".parse()?)?;
    let options = Options::parse(&args)?;
    let digest = options.digest()?;
    let preview = options.preview()?;
    assert!(preview.contains(&digest.to_text()));
    assert!(!root.exists());
    let owner = FixtureOwner::new(false);
    let mut output = Vec::new();
    let refused = operation::run(&options, &owner, &mut output);
    assert_eq!(refused.result, Err("ERR-CAPTURE-RTSP-APPROVAL-001"));
    assert!(owner.effects.borrow().is_empty());
    assert!(output.is_empty());
    assert!(!root.exists());

    let different = ContentDigest::sha256(b"another fixture identity").to_text();
    let alternate_root = directory.0.join("other-source");
    for (key, value) in [
        ("--root", alternate_root.to_str().ok_or("fixture path")?),
        ("--peer", "127.0.0.2:8555"),
        ("--authority", "another-camera.test"),
        ("--presentation", "/live/other/"),
        ("--control-root", "/"),
        ("--principal", "principal:other-owner"),
        ("--sensor-id", "sensor:other-camera"),
        ("--stream-id", "stream:other"),
        ("--generation", "9"),
        ("--ingress", "12"),
        ("--ssrc", "8"),
        ("--anchor", different.as_str()),
        ("--receive-clock", different.as_str()),
        ("--retention-evidence", different.as_str()),
        ("--stop-after-pictures", "2"),
        ("--payload-type", "97"),
        ("--media-index", "0"),
        ("--rtp-channel", "6"),
        ("--timeout-ms", "60000"),
        ("--max-steps", "99999"),
        ("--max-source-bytes", "33554432"),
        ("--max-datagrams", "33"),
        ("--max-storage-bytes", "134217728"),
        ("--source-work", "999999999"),
        ("--decode-work", "9999999999"),
        ("--max-report-bytes", "65536"),
        ("--read-bytes", "14"),
        ("--max-io-calls", "999999"),
        ("--connect-timeout-ms", "4000"),
        ("--response-timeout-ms", "4000"),
        ("--max-frame-bytes", "65536"),
        ("--max-dimension", "72"),
        ("--max-fragments", "64"),
        ("--frame-timeout-ms", "1000"),
        ("--reorder-delay-ms", "50"),
        ("--max-cached-quantizers", "17"),
    ] {
        let mut changed = args.clone();
        set(&mut changed, key, value);
        set(&mut changed, "--approve", &digest.to_text());
        let changed = Options::parse(&changed)?;
        assert_ne!(changed.digest()?, digest, "unbound option {key}");
        assert_eq!(
            changed.admit(),
            Err("ERR-CAPTURE-RTSP-APPROVAL-001"),
            "{key}"
        );
    }
    let mut approved_args = args.clone();
    set(&mut approved_args, "--approve", &digest.to_text());
    assert_eq!(Options::parse(&approved_args)?.digest()?, digest);
    assert!(Options::parse(&approved_args)?.admit().is_ok());
    let reversed = approved_args
        .chunks_exact(2)
        .rev()
        .flat_map(|pair| pair.iter().cloned())
        .collect::<Vec<_>>();
    assert_eq!(Options::parse(&reversed)?.digest()?, digest);
    let mut changed = Options::parse(&args)?;
    changed.protocol.channels = (6, 7);
    assert_ne!(
        changed.digest()?,
        digest,
        "effective protocol channels cannot escape approval"
    );
    assert!(!root.exists());
    Ok(())
}

#[test]
fn jpeg_authentication_and_complete_replay_selection_are_pure_and_approval_bound() -> Test {
    let directory = Directory::new()?;
    let args = arguments(&directory.source(), "127.0.0.1:8554".parse()?)?;
    let mut auth = args.clone();
    let missing = directory.0.join("missing-private-file");
    set(
        &mut auth,
        "--credential-file",
        missing.to_str().ok_or("fixture path")?,
    );
    set(&mut auth, "--auth-realm", "private-fixture-realm");
    set(&mut auth, "--legacy-md5", "yes");
    let original = Options::parse(&auth)?;
    assert!(!original.preview()?.contains("private-fixture-realm"));
    assert!(!missing.exists());
    for (key, value) in [
        ("--credential-file", "/another/missing-private-file"),
        ("--auth-realm", "another-realm"),
        ("--legacy-md5", "no"),
        ("--legacy-no-qop", "yes"),
    ] {
        let mut changed = auth.clone();
        set(&mut changed, key, value);
        assert_ne!(
            Options::parse(&changed)?.digest()?,
            original.digest()?,
            "{key}"
        );
    }
    let capture = Options::parse(&args)?;
    let pin = DatagramPin {
        scope: capture.scope.digest()?,
        head: ContentDigest::sha256(b"independently saved prefix"),
        datagrams: 5,
        payload_bytes: 1000,
    };
    let replay = replay_arguments(&args, pin, ContentDigest::sha256(b"accepted original SDP"));
    let original = Options::parse(&replay)?;
    assert_ne!(original.digest()?, capture.digest()?);
    let different = ContentDigest::sha256(b"different replay interpretation").to_text();
    for (key, value) in [
        ("--prefix-head", different.as_str()),
        ("--prefix-datagrams", "4"),
        ("--prefix-bytes", "999"),
        ("--configuration-evidence", different.as_str()),
        ("--reduced-rtcp", "no"),
    ] {
        let mut changed = replay.clone();
        set(&mut changed, key, value);
        assert_ne!(
            Options::parse(&changed)?.digest()?,
            original.digest()?,
            "{key}"
        );
    }
    for key in [
        "--prefix-head",
        "--prefix-datagrams",
        "--prefix-bytes",
        "--configuration-evidence",
        "--reduced-rtcp",
    ] {
        let mut missing = replay.clone();
        let at = missing
            .iter()
            .position(|arg| arg == key)
            .ok_or("missing fixture option")?;
        missing.drain(at..at + 2);
        assert!(
            Options::parse(&missing).is_err(),
            "missing independent replay pin {key}"
        );
    }
    for (key, value) in [
        ("--stop-after-pictures", "1"),
        ("--credential-file", "/missing/private-file"),
    ] {
        let mut changed = replay.clone();
        set(&mut changed, key, value);
        assert!(Options::parse(&changed).is_err(), "{key}");
    }
    assert!(!directory.source().exists());
    Ok(())
}

#[test]
fn jpeg_invalid_routes_permissions_limits_and_option_forms_refuse_before_effects() -> Test {
    let directory = Directory::new()?;
    let args = arguments(&directory.source(), "127.0.0.1:8554".parse()?)?;
    for (key, value) in [
        ("--owner-authorized", "no"),
        ("--plaintext", "no"),
        ("--retain-originals", "no"),
        ("--root", "relative/path"),
        ("--root", "/owner/../escaped"),
        ("--peer", "camera.test:554"),
        ("--peer", "127.0.0.1:0"),
        ("--peer", "224.0.0.1:554"),
        ("--generation", "0"),
        ("--ingress", "0"),
        ("--ssrc", "0"),
        ("--rtp-channel", "255"),
        ("--read-bytes", "4097"),
        ("--max-datagrams", "65537"),
        ("--max-report-bytes", "8192"),
        ("--max-dimension", "2041"),
        ("--source-work", "0"),
        ("--decode-work", "0"),
        ("--legacy-md5", "yes"),
        ("--prefix-datagrams", "1"),
        ("--unknown-jpeg-option", "yes"),
    ] {
        let mut changed = args.clone();
        set(&mut changed, key, value);
        assert!(Options::parse(&changed).is_err(), "{key}={value}");
    }
    let mut duplicate = args.clone();
    duplicate.extend([OsString::from("--ssrc"), OsString::from("7")]);
    assert!(Options::parse(&duplicate).is_err());
    let mut odd = args;
    odd.push("--timeout-ms".into());
    assert!(Options::parse(&odd).is_err());
    assert!(!directory.source().exists());
    Ok(())
}

struct FailingOutput {
    flush: bool,
    written: usize,
}
impl Write for FailingOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.flush {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.written += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::BrokenPipe.into())
    }
}

#[test]
fn jpeg_broken_or_denied_initial_output_cannot_create_storage_or_contact_peer() -> Test {
    for flush in [false, true] {
        let directory = Directory::new()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let options = approved(&arguments(&directory.source(), listener.local_addr()?)?)?;
        let owner = FixtureOwner::new(true);
        let mut sink = FailingOutput { flush, written: 0 };
        let mut report = operation::run(&options, &owner, &mut sink);
        assert_eq!(report.result, Err(operation::OUTPUT));
        assert!(
            owner
                .effects
                .borrow()
                .iter()
                .all(|effect| *effect == Effect::Output)
        );
        assert!(!directory.source().exists());
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        let mut later = Vec::new();
        assert_eq!(
            report.finish(&mut later, "null".into(), false),
            Err(operation::OUTPUT)
        );
        assert!(
            later.is_empty(),
            "a partial output record must never be resumed as a fresh JSONL stream"
        );
    }
    let directory = Directory::new()?;
    let options = approved(&arguments(&directory.source(), "127.0.0.1:8554".parse()?)?)?;
    let mut owner = FixtureOwner::new(false);
    owner.deny = Some(Effect::Output);
    let mut output = Vec::new();
    assert_eq!(
        operation::run(&options, &owner, &mut output).result,
        Err("ERR-CAPTURE-RTSP-AUTHORITY-001")
    );
    assert!(output.is_empty());
    assert!(!directory.source().exists());
    Ok(())
}

// Fault injection mutates the actual retained object after cold recovery has
// succeeded, while the real publisher and runtime owner remain active.
struct CorruptAfterRecovery {
    bytes: Vec<u8>,
    head: PathBuf,
    corrupted: bool,
}
impl Write for CorruptAfterRecovery {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        const RECOVERED: &[u8] = b"\"kind\":\"source_recovered\"";
        if !self.corrupted
            && self
                .bytes
                .windows(RECOVERED.len())
                .any(|part| part == RECOVERED)
        {
            std::fs::write(
                &self.head,
                b"actual root invalidated after initial recovery",
            )?;
            self.corrupted = true;
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn scan() -> Test<&'static [u8]> {
    let mut at = 2;
    while at < JPEG.len() {
        let marker = JPEG.get(at..at + 4).ok_or("short fixture JPEG marker")?;
        let end = at + 2 + usize::from(u16::from_be_bytes([marker[2], marker[3]]));
        JPEG.get(at..end).ok_or("short fixture JPEG segment")?;
        if marker[1] == 0xda {
            return Ok(&JPEG[end..]);
        }
        at = end;
    }
    Err("fixture lacks JPEG scan".into())
}
fn packet(sequence: u16, range: std::ops::Range<usize>, marker: bool) -> Test<Vec<u8>> {
    let mut out = vec![0x80, 26 | if marker { 0x80 } else { 0 }];
    out.extend(sequence.to_be_bytes());
    out.extend(90_000_u32.to_be_bytes());
    out.extend(7_u32.to_be_bytes());
    out.extend([
        0,
        (range.start >> 16) as u8,
        (range.start >> 8) as u8,
        range.start as u8,
        0,
        50,
        4,
        3,
    ]);
    out.extend_from_slice(scan()?.get(range).ok_or("fixture scan range")?);
    Ok(out)
}
fn originals() -> Test<Vec<(u8, Vec<u8>)>> {
    let size = scan()?.len();
    let first = packet(11, 0..size / 2, false)?;
    let mut rtcp = vec![0x80, 201, 0, 1];
    rtcp.extend(7_u32.to_be_bytes());
    Ok(vec![
        (0, packet(10, 0..size, true)?),
        (0, first.clone()),
        (0, first),
        (1, rtcp),
        (0, packet(12, size / 2..size, true)?),
    ])
}
fn read_request(socket: &mut TcpStream) -> io::Result<String> {
    let mut bytes = Vec::new();
    for _ in 0..32_768 {
        let mut byte = [0];
        socket.read_exact(&mut byte)?;
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes).map_err(|_| io::ErrorKind::InvalidData.into());
        }
    }
    Err(io::ErrorKind::InvalidData.into())
}
fn accept_peer(listener: TcpListener) -> Result<TcpStream, String> {
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(error) => return Err(format!("fixture accept: {error}")),
        }
    };
    socket
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    socket
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    socket.set_nodelay(true).map_err(|e| e.to_string())?;
    Ok(socket)
}
fn peer_server(listener: TcpListener, originals: &[(u8, Vec<u8>)]) -> Result<(), String> {
    let mut socket = accept_peer(listener)?;
    let description = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=audio 0 RTP/AVP 0\r\na=control:audio\r\nm=video 0 RTP/AVP 26\r\na=control:jpeg\r\na=rtcp-rsize\r\n";
    for (method, headers, body) in [
        ("DESCRIBE", "Content-Type: application/sdp\r\n", description),
        (
            "SETUP",
            "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=00000007\r\n",
            "",
        ),
        ("PLAY", "Session: fixture\r\n", ""),
    ] {
        let request = read_request(&mut socket).map_err(|e| e.to_string())?;
        if !request.starts_with(&format!("{method} rtsp://camera.test/live"))
            || request.contains("Authorization:")
        {
            return Err(format!("unexpected {method} request"));
        }
        let cseq = request
            .lines()
            .find_map(|line| line.strip_prefix("CSeq: "))
            .ok_or("missing request CSeq")?;
        let response = format!(
            "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}",
            body.len()
        );
        for bytes in response.as_bytes().chunks(7) {
            socket.write_all(bytes).map_err(|e| e.to_string())?;
        }
    }
    for (channel, datagram) in originals {
        let mut frame = vec![b'$', *channel];
        frame.extend((datagram.len() as u16).to_be_bytes());
        frame.extend_from_slice(datagram);
        for bytes in frame.chunks(7) {
            socket.write_all(bytes).map_err(|e| e.to_string())?;
        }
    }
    // Keep the peer open: successful target completion must be an owner stop,
    // not an accidental socket EOF or a teardown request sent behind approval.
    let mut tail = [0];
    match socket.read(&mut tail) {
        Ok(0) => Ok(()),
        Ok(_) => Err("unapproved cleanup request after picture target".into()),
        Err(error) => Err(format!("fixture awaiting owner socket closure: {error}")),
    }
}

#[test]
fn jpeg_live_probation_duplicates_rtcp_and_fragmented_picture_survive_disk_and_exact_cold_replay()
-> Test {
    let directory = Directory::new()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let args = arguments(&directory.source(), listener.local_addr()?)?;
    let options = approved(&args)?;
    let originals = originals()?;
    let owner = FixtureOwner::new(true);
    let mut capture_output = Vec::new();
    let mut capture = std::thread::scope(|scope| -> Test<Report> {
        let server = scope.spawn(|| peer_server(listener, &originals));
        let capture = operation::run(&options, &owner, &mut capture_output);
        server
            .join()
            .map_err(|_| "fixture peer panicked")?
            .map_err(|e| format!("{e}; capture result {:?}", capture.result))?;
        Ok(capture)
    })?;
    assert_eq!(capture.result, Ok(()));
    let pin = capture.pin.ok_or("no durable source prefix")?;
    assert_eq!(pin.datagrams, 5);
    assert_eq!(
        pin.payload_bytes,
        originals
            .iter()
            .map(|(_, bytes)| bytes.len() as u64)
            .sum::<u64>()
    );
    assert!(capture.pending.is_none());
    let captured = finished(&mut capture, &mut capture_output)?;
    let picture = row(&captured, "picture_validated")?;
    contains_field(picture, "dimensions", "[32,24]");
    contains_field(picture, "sequence_interval", "[11,12]");
    contains_field(picture, "fragments", "2");
    contains_field(picture, "source_provenance", "null");
    contains_field(picture, "pixels_retained", "false");
    let terminal = row(&captured, "operation_finished")?;
    contains_field(terminal, "validated_pictures", "1");
    contains_field(terminal, "actual_socket_eof", "false");
    contains_field(terminal, "selected_prefix_exhausted", "false");
    contains_field(terminal, "coverage_asserted", "false");
    assert_eq!(
        captured
            .lines()
            .filter(|line| line.contains("\"kind\":\"source_published\""))
            .count(),
        5
    );
    assert!(captured.contains("NotAdmitted"));
    assert!(captured.contains("Duplicate"));
    contains_field(row(&captured, "rtcp_validated")?, "valid", "true");
    assert!(owner.effects.borrow().contains(&Effect::Network));
    assert!(!owner.effects.borrow().contains(&Effect::Secret));
    let configuration = ContentDigest::parse(quoted(
        row(&captured, "configuration_accepted")?,
        "configuration_evidence",
    )?)?;

    let expected = decode_luma(
        JPEG,
        ContentDigest::sha256(JPEG).bytes(),
        ComponentInterpretation::YCbCr,
        DecodeLimits::default(),
        &mut DecodeBudget::new(100_000_000),
    )?;
    assert_eq!(expected.pixels().len(), ORACLE.len());
    assert!(
        expected
            .pixels()
            .iter()
            .zip(ORACLE)
            .all(|(&actual, &reference)| actual.abs_diff(reference) <= 1)
    );
    assert_eq!(
        quoted(picture, "luma_digest")?,
        ContentDigest::sha256(expected.pixels()).to_text()
    );

    // Reopen through the real publisher and archive after the live socket and
    // write owner are gone. Every admitted/dropped datagram remains exact.
    let head_object = {
        let publisher = LocalRootPublisher::open(&options.root, options.storage)?;
        let mut work = WorkBudget::new(1_000_000_000);
        let archive = DatagramArchive::recover(
            &publisher,
            options.scope.clone(),
            options.archive,
            Some(pin),
            &NeverCancel,
            &mut work,
        )?;
        for (index, (channel, bytes)) in originals.iter().enumerate() {
            let source = archive.read(index as u64 + 1, &publisher, &NeverCancel, &mut work)?;
            assert_eq!(source.payload(), bytes);
            assert_eq!(source.record().channel, *channel);
        }
        publisher.spool().object_path(pin.head)
    };
    let replay_args = replay_arguments(&args, pin, configuration);
    let replay_options = approved(&replay_args)?;
    let cold = FixtureOwner::new(false);
    let mut replay_output = Vec::new();
    let mut replay = operation::run(&replay_options, &cold, &mut replay_output);
    assert_eq!(replay.result, Ok(()));
    assert_eq!(replay.pin, Some(pin));
    let replayed = finished(&mut replay, &mut replay_output)?;
    let replay_picture = row(&replayed, "picture_validated")?;
    for key in ["encoded_digest", "luma_digest", "decoder"] {
        assert_eq!(quoted(picture, key)?, quoted(replay_picture, key)?);
    }
    assert!(!replay_picture.contains("\"source_provenance\":null"));
    assert!(replay_picture.contains("\"ordinal\":2"));
    assert!(replay_picture.contains("\"ordinal\":5"));
    contains_field(
        row(&replayed, "operation_finished")?,
        "selected_prefix_exhausted",
        "true",
    );
    contains_field(
        row(&replayed, "operation_finished")?,
        "source_eof_asserted",
        "false",
    );
    contains_field(row(&replayed, "rtcp_replayed")?, "valid", "true");
    assert!(replayed.contains("NotAdmitted"));
    assert!(replayed.contains("Duplicate"));
    assert!(
        !cold
            .effects
            .borrow()
            .iter()
            .any(|effect| matches!(effect, Effect::Network | Effect::Secret))
    );

    // Run the same real cold replay under the production TaskCx owner as well.
    // This proves Process→Property→Sensor closure instead of inferring it from
    // the injectable permission/clock fixture used for effect-boundary failures.
    let mut owned_output = Vec::new();
    super::runtime::execute_with_output(&replay_options, &mut owned_output)?;
    let owned = std::str::from_utf8(&owned_output)?;
    let owned_picture = row(owned, "picture_validated")?;
    for key in ["encoded_digest", "luma_digest", "decoder"] {
        assert_eq!(quoted(picture, key)?, quoted(owned_picture, key)?);
    }
    let terminal = row(owned, "operation_finished")?;
    contains_field(terminal, "complete", "true");
    contains_field(terminal, "quiescent", "true");
    contains_field(terminal, "active_tasks", "0");
    contains_field(terminal, "pending_obligations", "[]");
    contains_field(terminal, "outcome", "\"success\"");
    contains_field(terminal, "network_bytes", "0");
    assert!(terminal.contains(&pin.head.to_text()));
    assert!(!terminal.contains("\"task_receipt\":null"));
    assert!(!terminal.contains("\"quiescence_proof\":null"));

    // Independently changed pin metadata cannot be repaired from storage aliases.
    let mut wrong = replay_args.clone();
    set(
        &mut wrong,
        "--prefix-bytes",
        &(pin.payload_bytes - 1).to_string(),
    );
    let mut refused_output = Vec::new();
    let refused = operation::run(
        &approved(&wrong)?,
        &FixtureOwner::new(false),
        &mut refused_output,
    );
    assert!(refused.result.is_err());
    assert!(!std::str::from_utf8(&refused_output)?.contains("\"kind\":\"picture_validated\""));

    // A previously recovered pin must not become a verified custody claim after
    // the actual source is invalidated during interpretation. Use the real TaskCx.
    let mut invalidated = CorruptAfterRecovery {
        bytes: Vec::new(),
        head: head_object,
        corrupted: false,
    };
    let invalidated_result = super::runtime::execute_with_output(&replay_options, &mut invalidated);
    assert!(invalidated.corrupted, "late source fault was not injected");
    assert!(invalidated_result.is_err());
    let failed_output = std::str::from_utf8(&invalidated.bytes)?;
    let failed = row(failed_output, "operation_finished")?;
    contains_field(failed, "complete", "false");
    contains_field(failed, "custody_state", "\"failed\"");
    contains_field(failed, "outcome", "\"failed\"");
    contains_field(failed, "quiescent", "true");
    assert!(
        failed.contains(&pin.head.to_text()),
        "failed proof must retain its independently pinned input"
    );
    assert!(!failed_output.contains("\"kind\":\"picture_validated\""));

    // The same real corruption must also refuse a fresh open before interpretation.
    let mut corrupted_output = Vec::new();
    let corrupted = operation::run(
        &replay_options,
        &FixtureOwner::new(false),
        &mut corrupted_output,
    );
    assert!(corrupted.result.is_err());
    assert!(!std::str::from_utf8(&corrupted_output)?.contains("\"kind\":\"picture_validated\""));
    Ok(())
}

#[test]
fn jpeg_real_unauthenticated_401_closes_without_credentials_retry_or_source_publication() -> Test {
    let directory = Directory::new()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let options = approved(&arguments(&directory.source(), listener.local_addr()?)?)?;
    let owner = FixtureOwner::new(true);
    let mut output = Vec::new();
    let mut report = std::thread::scope(|scope| -> Test<Report> {
        let peer = scope.spawn(|| -> Result<(), String> {
let mut socket = accept_peer(listener)?;
let request = read_request(&mut socket).map_err(|error| error.to_string())?;
if !request.starts_with("DESCRIBE rtsp://camera.test/live/")
|| request.contains("Authorization:")
{
return Err("unexpected initial unauthenticated request".into());
}
let cseq = request.lines().find_map(|line| line.strip_prefix("CSeq: "))
.ok_or("missing request CSeq")?;
let challenge = format!("RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\nWWW-Authenticate: Digest realm=\"unapproved-realm\", nonce=\"do-not-log-this-401-nonce\", algorithm=SHA-256, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n");
for part in challenge.as_bytes().chunks(5) {
socket.write_all(part).map_err(|error| error.to_string())?;
}
let mut further_request = [0];
match socket.read(&mut further_request) {
Ok(0) => Ok(()),
Ok(_) => Err("unauthorized authentication retry or cleanup request".into()),
Err(error) => Err(format!("unauthenticated socket did not retire: {error}")),
}
});
        let report = operation::run(&options, &owner, &mut output);
        peer.join().map_err(|_| "fixture peer panicked")??;
        Ok(report)
    })?;
    assert_eq!(report.result, Err(operation::SOURCE));
    let pin = report.pin.ok_or("empty source prefix missing")?;
    assert_eq!((pin.datagrams, pin.payload_bytes), (0, 0));
    assert!(!report.recovery_required());
    assert!(!owner.effects.borrow().contains(&Effect::Secret));
    assert_eq!(
        report.finish(&mut output, "null".into(), false),
        Err(operation::SOURCE)
    );
    let text = std::str::from_utf8(&output)?;
    assert!(!text.contains("do-not-log-this-401-nonce"));
    assert!(!text.contains("unapproved-realm"));
    assert!(!text.contains("\"kind\":\"source_published\""));
    assert!(!text.contains("\"kind\":\"picture_validated\""));
    contains_field(row(text, "operation_finished")?, "complete", "false");
    contains_field(row(text, "operation_finished")?, "validated_pictures", "0");
    Ok(())
}

#[test]
fn jpeg_replay_missing_source_never_creates_an_empty_archive_or_uses_network() -> Test {
    let directory = Directory::new()?;
    let args = arguments(&directory.source(), "127.0.0.1:8554".parse()?)?;
    let capture = Options::parse(&args)?;
    let pin = DatagramPin {
        scope: capture.scope.digest()?,
        head: ContentDigest::sha256(b"missing independently retained source"),
        datagrams: 1,
        payload_bytes: 100,
    };
    let options = approved(&replay_arguments(
        &args,
        pin,
        ContentDigest::sha256(b"accepted source description"),
    ))?;
    let owner = FixtureOwner::new(false);
    let mut output = Vec::new();
    let mut report = operation::run(&options, &owner, &mut output);
    assert_eq!(report.result, Err("ERR-CAPTURE-RTSP-ROOT-001"));
    assert!(!directory.source().exists());
    assert!(report.pin.is_none());
    assert!(
        !owner
            .effects
            .borrow()
            .iter()
            .any(|effect| matches!(effect, Effect::Network | Effect::Secret))
    );
    let terminal_result = report.finish(&mut output, "null".into(), false);
    assert_eq!(terminal_result, Err("ERR-CAPTURE-RTSP-ROOT-001"));
    let text = std::str::from_utf8(&output)?;
    let terminal = row(text, "operation_finished")?;
    contains_field(terminal, "complete", "false");
    contains_field(terminal, "validated_pictures", "0");
    contains_field(terminal, "source_eof_asserted", "false");
    contains_field(terminal, "coverage_asserted", "false");
    Ok(())
}
