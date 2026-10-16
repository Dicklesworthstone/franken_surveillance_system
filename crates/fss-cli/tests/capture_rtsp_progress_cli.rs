#![forbid(unsafe_code)]
//! Native process contracts for owner-observed recording stalls, not physical camera health.
//! Loopback sources stay open until the client closes. Fixtures never synthesize an EOF to
//! satisfy the watchdog. Capture, publication, retained import and decode are real binaries.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;

type Test<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const SENSOR: &str = "sensor:progress-fixture";
const STREAM: &str = "stream:progress-fixture";
const SITE: &str = "site:progress-fixture";
const OUTPUT_LIMIT: u64 = 2 * 1024 * 1024;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for ordinal in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-rtsp-progress-{}-{label}-{ordinal}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("fixture directory reservation exhausted".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn binary(name: &str) -> Test<PathBuf> {
    let (variable, compiled) = match name {
        "capture" => ("FSS_CAPTURE_RTSP_BIN", option_env!("CARGO_BIN_EXE_fss-capture-rtsp")),
        "import" => ("FSS_IMPORT_RTSP_BIN", option_env!("CARGO_BIN_EXE_fss-import-rtsp")),
        "file" => ("FSS_FILE_BIN", option_env!("CARGO_BIN_EXE_fss-file")),
        _ => return Err("unknown fixture binary".into()),
    };
    std::env::var_os(variable)
        .or_else(|| compiled.map(OsString::from))
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {name}; set {variable}").into())
}

fn run(directory: &Directory, name: &str, args: &[OsString]) -> Test<Output> {
    // File-backed output cannot deadlock capture on a pipe. Bound it while the child runs;
    // every new invocation owns an exclusively created pair rather than overwriting evidence.
    let mut outputs = None;
    for ordinal in 0..100 {
        let path = directory.0.join(format!("process-{ordinal}"));
        match fs::create_dir(&path) {
            Ok(()) => {
                outputs = Some(path);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    let outputs = outputs.ok_or("process reservation exhausted")?;
    let make = |name: &str| -> io::Result<File> {
        OpenOptions::new().write(true).create_new(true).open(outputs.join(name))
    };
    let out = make("stdout")?;
    let err = make("stderr")?;
    let mut process = Process(Command::new(binary(name)?)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()?);
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if Instant::now() >= deadline
            || fs::metadata(outputs.join("stdout"))?.len() > OUTPUT_LIMIT
            || fs::metadata(outputs.join("stderr"))?.len() > OUTPUT_LIMIT
        {
            return Err("native fixture process exceeded time/output bound".into());
        }
        if let Some(status) = process.0.try_wait()? {
            break status;
        }
        thread::sleep(Duration::from_millis(2));
    };
    let read = |name: &str| -> Test<Vec<u8>> {
        let mut bytes = Vec::new();
        File::open(outputs.join(name))?.take(OUTPUT_LIMIT + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > OUTPUT_LIMIT {
            return Err("native fixture output too large".into());
        }
        Ok(bytes)
    };
    Ok(Output { status, stdout: read("stdout")?, stderr: read("stderr")? })
}

fn field<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    value.object().and_then(|object| object.get(key)).ok_or_else(|| format!("missing {key}").into())
}
fn text<'a>(value: &'a Value, key: &str) -> Test<&'a str> {
    field(value, key)?.text().ok_or_else(|| format!("{key} is not text").into())
}
fn number(value: &Value, key: &str) -> Test<i128> {
    field(value, key)?.integer().ok_or_else(|| format!("{key} is not an integer").into())
}
fn flag(value: &Value, key: &str) -> Test<bool> {
    field(value, key)?.boolean().ok_or_else(|| format!("{key} is not boolean").into())
}
fn good(output: Output) -> Test<String> {
    assert!(output.status.success(), "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    Ok(String::from_utf8(output.stdout)?)
}
fn digest(label: &str) -> String {
    ContentDigest::sha256(label.as_bytes()).to_text()
}
fn set(args: &mut Vec<OsString>, key: &str, value: &str) {
    match args.iter().position(|argument| argument == key) {
        Some(at) => args[at + 1] = value.into(),
        None => args.extend([key.into(), value.into()]),
    }
}
fn args(directory: &Directory, address: SocketAddr, codec: Codec) -> Vec<OsString> {
    [
        ("--root", directory.0.join("capture").display().to_string()),
        ("--pins", directory.0.join("pins").display().to_string()),
        ("--peer", address.to_string()),
        ("--authority", address.to_string()),
        ("--presentation", "/live/".into()),
        ("--control-root", "/live".into()),
        ("--sensor-id", SENSOR.into()),
        ("--stream-id", STREAM.into()),
        ("--generation", "1".into()),
        ("--ingress", "71".into()),
        ("--ssrc", "7".into()),
        ("--anchor", digest("progress anchor")),
        ("--receive-clock", digest("progress receive clock")),
        ("--timing-evidence", digest("owner fixed cadence")),
        ("--journal-id", digest("progress journal")),
        ("--frame-duration-ticks", codec.cadence().to_string()),
        ("--stop-after-pictures", "2".into()),
        ("--owner-authorized", "yes".into()),
        ("--plaintext", "yes".into()),
        ("--retain-originals", "yes".into()),
        ("--timeout-ms", "30000".into()),
        ("--drain-timeout-ms", "5000".into()),
        ("--response-timeout-ms", "10000".into()),
        ("--max-report-bytes", "131072".into()),
        ("--max-window-pictures", "16".into()),
        ("--codec", codec.name().into()),
        ("--payload-type", codec.pt().to_string()),
        ("--progress-timeout-ms", "500".into()),
    ].into_iter().flat_map(|(key, value)| [key.into(), value.into()]).collect()
}
fn approve(directory: &Directory, args: &[OsString]) -> Test<Vec<OsString>> {
    let plan = parse(&good(run(directory, "capture", args)?)?)?;
    let mut approved = args.to_vec();
    approved.extend(["--approve".into(), text(&plan, "approval")?.into()]);
    Ok(approved)
}
fn listener() -> Test<TcpListener> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}
fn no_connection(listener: &TcpListener) -> Test {
    match listener.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Ok(_) => Err("unexpected successor connection".into()),
        Err(error) => Err(error.into()),
    }
}

#[derive(Clone, Copy)]
enum Codec { Avc, Hevc }
impl Codec {
    fn name(self) -> &'static str { match self { Self::Avc => "avc", Self::Hevc => "hevc" } }
    fn pt(self) -> u8 { match self { Self::Avc => 96, Self::Hevc => 98 } }
    fn cadence(self) -> u32 { match self { Self::Avc => 3600, Self::Hevc => 18_000 } }
    fn description(self) -> String {
        let mapping = match self {
            Self::Avc => concat!(
                "a=rtpmap:96 H264/90000\r\n",
                "a=fmtp:96 packetization-mode=1;sprop-parameter-sets=",
                "Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\n"),
            Self::Hevc => concat!(
                "a=rtpmap:98 H265/90000\r\n",
                "a=fmtp:98 sprop-vps=QAEMAf//AWAAAAMAkAAAAwAAAwAeugJA;",
                "sprop-sps=QgEBAWAAAAMAkAAAAwAAAwAeoCCDHVZbpKTC8BaAgAAAAwCAAAADAoQ=;",
                "sprop-pps=RAHAc8CJ\r\n"),
        };
        format!("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP {}\r\n{mapping}a=control:trackID=0\r\n", self.pt())
    }
}
fn avc_nals() -> Vec<&'static [u8]> {
    let bytes = include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264");
    let mut starts = Vec::new();
    let mut at = 0;
    while at + 3 <= bytes.len() {
        let prefix = if bytes.get(at..at + 4) == Some(&[0, 0, 0, 1]) { 4 }
            else if bytes[at..at + 3] == [0, 0, 1] { 3 } else { 0 };
        if prefix != 0 { starts.push((at, at + prefix)); at += prefix; } else { at += 1; }
    }
    starts.iter().enumerate().filter_map(|(index, (_, begin))| {
        let mut end = starts.get(index + 1).map_or(bytes.len(), |(at, _)| *at);
        while end > *begin && bytes[end - 1] == 0 { end -= 1; }
        (*begin < end).then_some(&bytes[*begin..end])
    }).collect()
}
fn hevc_nals() -> Test<Vec<Vec<u8>>> {
    include_str!("../../../tests/fixtures/media/hevc/remux_main8.nals.hex")
        .lines().filter(|line| !line.trim().is_empty()).map(|line| {
            if !line.is_ascii() || !line.len().is_multiple_of(2) {
                return Err("invalid pinned HEVC fixture".into());
            }
            (0..line.len()).step_by(2).map(|at| {
                u8::from_str_radix(&line[at..at + 2], 16).map_err(Into::into)
            }).collect()
        }).collect()
}
fn framed(codec: Codec, sequence: u16, timestamp: u32, nal: &[u8]) -> Test<Vec<u8>> {
    let mut packet = vec![0x80, codec.pt() | 128];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.extend_from_slice(&7_u32.to_be_bytes());
    packet.extend_from_slice(nal);
    let mut wire = vec![b'$', 0];
    wire.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
    wire.extend_from_slice(&packet);
    Ok(wire)
}
fn media(codec: Codec, target: bool, unclosed: bool) -> Test<Vec<Vec<u8>>> {
    match codec {
        Codec::Avc => {
            let nals = avc_nals();
            let mut out = vec![framed(codec, 0, 9000, nals.first().ok_or("missing AVC")?)?];
            let mut pictures = 0;
            for nal in nals {
                if pictures == if target { 2 } else { 1 } { break; }
                let kind = nal[0] & 31;
                if !matches!(kind, 1 | 5 | 6 | 7 | 8) { continue; }
                out.push(framed(codec, u16::try_from(out.len())?, 9000 + pictures * 3600, nal)?);
                if matches!(kind, 1 | 5) { pictures += 1; }
            }
            assert_eq!(pictures, if target { 2 } else { 1 });
            Ok(out)
        }
        Codec::Hevc => {
            let nals = hevc_nals()?;
            let count = if unclosed { 4 } else if target { 6 } else { 5 };
            assert_eq!(nals.iter().take(6).map(|n| (n[0] >> 1) & 63).collect::<Vec<_>>(), [32, 33, 34, 20, 1, 32]);
            let mut out = vec![framed(codec, 0, 0, nals.first().ok_or("missing HEVC")?)?];
            for (index, (nal, timestamp)) in nals.iter().zip([0, 0, 0, 0, 18_000, 36_000]).take(count).enumerate() {
                out.push(framed(codec, u16::try_from(index + 1)?, timestamp, nal)?);
            }
            Ok(out)
        }
    }
}
fn request(peer: &mut TcpStream) -> Test<Option<(String, u32)>> {
    let mut bytes = Vec::new();
    while bytes.len() < 8192 {
        let mut byte = [0];
        match peer.read(&mut byte) {
            Ok(0) if bytes.is_empty() => return Ok(None),
            Ok(0) => return Err("partial control request".into()),
            Ok(_) => bytes.push(byte[0]),
            Err(error) if bytes.is_empty() && closed(&error) => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        if bytes.ends_with(b"\r\n\r\n") {
            let text = String::from_utf8(bytes)?;
            assert!(!text.to_ascii_lowercase().contains("authorization:"));
            let method = text.split_ascii_whitespace().next().ok_or("missing method")?.to_owned();
            let cseq = text.split("\r\n").find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("cseq").then_some(value.trim())
            }).ok_or("missing cseq")?.parse()?;
            return Ok(Some((method, cseq)));
        }
    }
    Err("oversized fixture request".into())
}
fn closed(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted)
}
fn response(peer: &mut TcpStream, cseq: u32, headers: &str, body: &str) -> Test {
    peer.write_all(format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}", body.len()).as_bytes())?;
    Ok(())
}
#[derive(Clone, Copy)]
enum Camera { Silent, Prefix, Duplicate, Target, EofPrefix, Unclosed, Authentication, HeldControl, ExpiredControl }
fn serve(listener: &TcpListener, codec: Codec, camera: Camera) -> Test {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut peer = loop {
        match listener.accept() {
            Ok((peer, _)) => break peer,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error.into()),
        }
    };
    peer.set_read_timeout(Some(Duration::from_secs(15)))?;
    peer.set_write_timeout(Some(Duration::from_secs(15)))?;
    peer.set_nodelay(true)?;
    let (method, cseq) = request(&mut peer)?.ok_or("missing DESCRIBE")?;
    assert_eq!(method, "DESCRIBE");
    if matches!(camera, Camera::Authentication) {
        peer.write_all(format!("RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\nWWW-Authenticate: Digest realm=\"PROGRESS_SECRET_REALM\", nonce=\"PROGRESS_SECRET_NONCE\", qop=\"auth\"\r\nContent-Length: 0\r\n\r\n").as_bytes())?;
        assert!(request(&mut peer)?.is_none());
        return Ok(());
    }
    response(&mut peer, cseq, "Content-Type: application/sdp\r\n", &codec.description())?;
    let (method, cseq) = request(&mut peer)?.ok_or("missing SETUP")?;
    assert_eq!(method, "SETUP");
    // The held-control case must reach the progress boundary BEFORE lease expiry:
    // keepalive at two seconds < stall at three seconds < session expiry at four.
    // ExpiredControl deliberately reverses that ordering to exercise native refusal.
    let timeout = match camera {
        Camera::HeldControl => 4,
        Camera::ExpiredControl => 2,
        _ => 60,
    };
    response(&mut peer, cseq, &format!("Session: fixture;timeout={timeout}\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n"), "")?;
    let (method, cseq) = request(&mut peer)?.ok_or("missing PLAY")?;
    assert_eq!(method, "PLAY");
    response(&mut peer, cseq, "Session: fixture\r\n", "")?;
    if matches!(camera, Camera::HeldControl | Camera::ExpiredControl) {
        let (method, _) = request(&mut peer)?.ok_or("expected a keepalive before retirement")?;
        assert!(matches!(method.as_str(), "GET_PARAMETER" | "OPTIONS"));
        // Deliberately withhold its acknowledgement. Only socket retirement can report it.
        assert!(request(&mut peer)?.is_none());
        return Ok(());
    }
    let packets = if matches!(camera, Camera::Silent) { Vec::new() } else {
        media(codec, matches!(camera, Camera::Target), matches!(camera, Camera::Unclosed))?
    };
    for packet in &packets { peer.write_all(packet)?; }
    if matches!(camera, Camera::EofPrefix) { peer.shutdown(Shutdown::Write)?; }
    if matches!(camera, Camera::Duplicate) {
        let duplicate = packets.last().ok_or("missing duplicate")?;
        peer.set_read_timeout(Some(Duration::from_millis(20)))?;
        for _ in 0..1000 {
            match peer.write_all(duplicate) {
                Ok(()) => {}
                Err(error) if closed(&error) => return Ok(()),
                Err(error) => return Err(error.into()),
            }
            let mut byte = [0];
            match peer.read(&mut byte) {
                Ok(0) => return Ok(()),
                Ok(_) => return Err("unexpected early command in duplicate fixture".into()),
                Err(error) if closed(&error) => return Ok(()),
                Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
                Err(error) => return Err(error.into()),
            }
        }
        return Err("duplicates kept stalled capture alive".into());
    }
    // The fixture leaves its write side open unless EofPrefix explicitly selected it.
    for _ in 0..16 {
        let Some((method, cseq)) = request(&mut peer)? else { return Ok(()); };
        assert!(matches!(method.as_str(), "GET_PARAMETER" | "OPTIONS"));
        response(&mut peer, cseq, "Session: fixture\r\n", "")?;
    }
    Err("fixture control allowance exhausted".into())
}
fn capture(directory: &Directory, args: &[OsString], listener: &TcpListener, codec: Codec, cameras: &[Camera]) -> Test<Output> {
    thread::scope(|scope| {
        let server = scope.spawn(move || -> Test {
            for camera in cameras { serve(listener, codec, *camera)?; }
            Ok(())
        });
        let output = run(directory, "capture", args);
        let served = server.join().map_err(|_| "camera fixture panicked")?;
        let output = output?;
        if let Err(error) = served {
            return Err(format!("{error}; stdout={} stderr={}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)).into());
        }
        Ok(output)
    })
}
fn rows(output: &Output) -> Test<Vec<Value>> {
    let mut result = Vec::new();
    let (mut native, mut outer) = (0, 0);
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let row = parse(line)?;
        let expected = match text(&row, "schema")? {
            "fss.rtsp_capture_cli.v1" => {
                if text(&row, "kind")? == "started" { native = 0; }
                &mut native
            }
            "fss.rtsp_reconnect_cli.v1" => &mut outer,
            _ => return Err("unexpected capture schema".into()),
        };
        assert_eq!(number(&row, "sequence")?, *expected);
        *expected += 1;
        result.push(row);
    }
    assert!(!result.is_empty());
    Ok(result)
}
fn details<'a>(rows: &'a [Value], kind: &str) -> Test<Vec<&'a Value>> {
    rows.iter().filter(|row| text(row, "kind").ok() == Some(kind))
        .map(|row| field(row, "detail")).collect()
}
fn unique<'a>(rows: &'a [Value], kind: &str) -> Test<&'a Value> {
    let matches = details(rows, kind)?;
    assert_eq!(matches.len(), 1, "expected one {kind}; observed events: {:?}",
        rows.iter().filter_map(|row| text(row, "kind").ok()).collect::<Vec<_>>());
    Ok(matches[0])
}
fn assert_stall(rows: &[Value], pictures: i128) -> Test {
    let stall = unique(rows, "recording_stalled")?;
    assert_eq!(number(stall, "pictures_before_expiry")?, pictures);
    assert!(!flag(stall, "source_eof_asserted")?);
    assert!(!flag(stall, "camera_offline_asserted")?);
    assert!(!flag(stall, "absence_certifiable")?);
    let terminal = unique(rows, "terminal")?;
    assert_eq!(text(terminal, "error_id")?, "ERR-CAPTURE-RTSP-PROGRESS-001");
    assert!(!flag(terminal, "complete")?);
    assert!(!flag(terminal, "peer_eof")?);
    assert!(!flag(terminal, "input_end_observed")?);
    assert_eq!(number(terminal, "durable_pictures")?, pictures);
    assert_eq!(number(terminal, "collected_pictures")?, pictures);
    assert_eq!(number(terminal, "durable_windows")?, number(terminal, "indexed_windows")?);
    Ok(())
}

fn cold_decode_avc(directory: &Directory, rows: &[Value]) -> Test {
    let window = unique(rows, "window_durable")?;
    let deployment = directory.0.join("deployment");
    let archive = directory.0.join("capture");
    let mut input: Vec<OsString> = [
        ("--archive", archive.display().to_string()),
        ("--root", deployment.display().to_string()),
        ("--site", SITE.into()),
        ("--window-slot", text(window, "slot")?.into()),
        ("--window-root", text(window, "root")?.into()),
        ("--codec", "avc".into()),
        ("--sensor-id", SENSOR.into()),
        ("--stream-id", STREAM.into()),
        ("--generation", "1".into()),
        ("--anchor", digest("progress anchor")),
        ("--receive-clock", digest("progress receive clock")),
        ("--receive-time-ns", "5000000000".into()),
        ("--owner-authorized", "yes".into()),
        ("--read-originals", "yes".into()),
        ("--retain-originals", "yes".into()),
    ].into_iter().flat_map(|(key, value)| [key.into(), value.into()]).collect();
    let preview = parse(&good(run(directory, "import", &input)?)?)?;
    assert!(!deployment.exists());
    set(&mut input, "--approve", text(&preview, "approval_digest")?);
    let imported = parse(&good(run(directory, "import", &input)?)?)?;
    assert_eq!(number(&imported, "frames")?, 1);
    assert!(flag(&imported, "destination_contains_original_recording")?);
    let effects = fs::read(deployment.join("effects/journal.fssj"))?;
    fs::rename(archive, directory.0.join("offline-capture"))?;
    let decode: Vec<OsString> = [
        "decode", "--root", deployment.to_str().ok_or("deployment path")?,
        "--site", SITE, "--import-id", text(&imported, "import_identity")?,
        "--segment", "0", "--segment-count", "1", "--interpretation", "ycbcr",
        "--work-units", "1000000000",
    ].into_iter().map(OsString::from).collect();
    let decoded = good(run(directory, "file", &decode)?)?;
    assert!(decoded.lines().any(|line| line == "h264_frames_decoded=1"), "{decoded}");
    assert!(decoded.lines().any(|line| line == "decode_complete=true"), "{decoded}");
    assert_eq!(decoded.lines().filter(|line| line.starts_with("frame_luma_sha256=")).count(), 1);
    assert_eq!(fs::read(deployment.join("effects/journal.fssj"))?, effects);
    Ok(())
}

#[test]
fn a_silent_avc_or_hevc_socket_cannot_stand_in_for_collected_pictures() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        let directory = Directory::new(codec.name())?;
        let listener = listener()?;
        let input = approve(&directory, &args(&directory, listener.local_addr()?, codec))?;
        let output = capture(&directory, &input, &listener, codec, &[Camera::Silent])?;
        assert!(!output.status.success());
        assert_stall(&rows(&output)?, 0)?;
        assert!(directory.0.join("capture").is_dir());
        assert!(!directory.0.join("capture.attempt-0001").exists());
        no_connection(&listener)?;
    }
    Ok(())
}

#[test]
fn duplicate_rtp_cannot_renew_progress_and_the_stalled_prefix_cold_decodes() -> Test {
    let directory = Directory::new("duplicates")?;
    let listener = listener()?;
    let input = approve(&directory, &args(&directory, listener.local_addr()?, Codec::Avc))?;
    let output = capture(&directory, &input, &listener, Codec::Avc, &[Camera::Duplicate])?;
    let report = rows(&output)?;
    assert_stall(&report, 1)?;
    cold_decode_avc(&directory, &report)
}

#[test]
fn hevc_stall_retains_only_source_closed_pictures_not_marker_claims() -> Test {
    for (camera, pictures) in [(Camera::Prefix, 1), (Camera::Unclosed, 0)] {
        let directory = Directory::new("hevc-boundary")?;
        let listener = listener()?;
        let input = approve(&directory, &args(&directory, listener.local_addr()?, Codec::Hevc))?;
        let output = capture(&directory, &input, &listener, Codec::Hevc, &[camera])?;
        let report = rows(&output)?;
        assert_stall(&report, pictures)?;
        if pictures == 1 {
            assert!(number(unique(&report, "window_durable")?, "source_only_nals")? > 0);
        } else {
            assert!(details(&report, "window_durable")?.is_empty());
        }
    }
    Ok(())
}

#[test]
fn timely_targets_and_real_eof_keep_their_original_native_completion() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        for camera in [Camera::Target, Camera::EofPrefix] {
            let directory = Directory::new("completion")?;
            let listener = listener()?;
            let mut input = args(&directory, listener.local_addr()?, codec);
            set(&mut input, "--progress-timeout-ms", "5000");
            let input = approve(&directory, &input)?;
            let output = capture(&directory, &input, &listener, codec, &[camera])?;
            let report = rows(&output)?;
            assert!(details(&report, "recording_stalled")?.is_empty());
            let terminal = unique(&report, "terminal")?;
            if matches!(camera, Camera::Target) {
                assert!(output.status.success());
                assert!(flag(terminal, "complete")?);
                assert_eq!(number(terminal, "durable_pictures")?, 2);
                assert!(!flag(terminal, "peer_eof")?);
            } else {
                assert!(!output.status.success());
                assert_eq!(text(terminal, "error_id")?, "ERR-CAPTURE-RTSP-SHORTFALL-001");
                assert_eq!(number(terminal, "durable_pictures")?, 1);
                assert!(flag(terminal, "peer_eof")?);
            }
        }
    }
    Ok(())
}

fn reconnect(mut input: Vec<OsString>) -> Vec<OsString> {
    input.insert(0, "reconnect".into());
    set(&mut input, "--max-attempts", "2");
    set(&mut input, "--retry-delay-ms", "1");
    input
}

#[test]
fn a_drained_stall_reconnects_with_separate_epochs_and_both_archives_retained() -> Test {
    let directory = Directory::new("reconnect")?;
    let listener = listener()?;
    let input = approve(&directory, &reconnect(args(&directory, listener.local_addr()?, Codec::Avc)))?;
    let output = capture(&directory, &input, &listener, Codec::Avc, &[Camera::Prefix, Camera::Target])?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report = rows(&output)?;
    let terminals = details(&report, "terminal")?;
    assert_eq!(terminals.len(), 2);
    assert_eq!(text(terminals[0], "error_id")?, "ERR-CAPTURE-RTSP-PROGRESS-001");
    assert_eq!(number(terminals[0], "durable_pictures")?, 1);
    assert!(flag(terminals[1], "complete")?);
    assert_eq!(number(field(terminals[0], "source")?, "generation")?, 1);
    assert_eq!(number(field(terminals[1], "source")?, "generation")?, 2);
    assert_ne!(text(field(terminals[0], "source")?, "receive_clock")?, text(field(terminals[1], "source")?, "receive_clock")?);
    let attempts = details(&report, "attempt_finished")?;
    assert_eq!(attempts.len(), 2);
    assert_eq!(text(attempts[0], "retry_reason")?, "recording_progress_stalled");
    assert!(flag(attempts[0], "retrying")?);
    assert!(!flag(attempts[0], "recovery_required")?);
    assert_eq!(number(attempts[1], "durable_pictures_all_attempts")?, 3);
    assert!(!flag(attempts[1], "continuity_across_attempts")?);
    for path in ["capture.attempt-0001", "capture.attempt-0002", "pins.attempt-0001", "pins.attempt-0002"] {
        assert!(directory.0.join(path).is_dir());
    }
    Ok(())
}

#[test]
fn an_unacknowledged_keepalive_vetoes_reconnect_after_a_clean_empty_drain() -> Test {
    let directory = Directory::new("control")?;
    let listener = listener()?;
    let mut input = reconnect(args(&directory, listener.local_addr()?, Codec::Avc));
    set(&mut input, "--progress-timeout-ms", "3000");
    let input = approve(&directory, &input)?;
    let output = capture(&directory, &input, &listener, Codec::Avc, &[Camera::HeldControl])?;
    assert!(!output.status.success());
    let report = rows(&output)?;
    assert_stall(&report, 0)?;
    assert!(flag(unique(&report, "terminal")?, "unsettled_request")?);
    let attempt = unique(&report, "attempt_finished")?;
    assert!(!flag(attempt, "retrying")?);
    assert!(!flag(attempt, "recovery_required")?);
    assert!(!directory.0.join("capture.attempt-0002").exists());
    no_connection(&listener)
}

#[test]
fn authentication_refusal_never_becomes_a_retryable_recording_stall() -> Test {
    let directory = Directory::new("auth")?;
    let listener = listener()?;
    let input = approve(&directory, &reconnect(args(&directory, listener.local_addr()?, Codec::Avc)))?;
    let output = capture(&directory, &input, &listener, Codec::Avc, &[Camera::Authentication])?;
    assert!(!output.status.success());
    let report = rows(&output)?;
    assert!(details(&report, "recording_stalled")?.is_empty());
    assert!(!flag(unique(&report, "attempt_finished")?, "retrying")?);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PROGRESS_SECRET"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("PROGRESS_SECRET"));
    assert!(!directory.0.join("capture.attempt-0002").exists());
    no_connection(&listener)
}

#[test]
fn nested_approval_is_not_authority_and_preview_has_no_effects() -> Test {
    let directory = Directory::new("approval")?;
    let listener = listener()?;
    let mut input = args(&directory, listener.local_addr()?, Codec::Avc);
    let preview = parse(&good(run(&directory, "capture", &input)?)?)?;
    assert_eq!(text(&preview, "schema")?, "fss.rtsp_supervised_capture_cli.v1");
    let child = field(&preview, "capture")?;
    assert_eq!(Path::new(text(child, "root")?), directory.0.join("capture"));
    assert!(!directory.0.join("capture").exists());
    assert!(!directory.0.join("pins").exists());
    no_connection(&listener)?;
    set(&mut input, "--approve", text(child, "approval")?);
    assert!(!run(&directory, "capture", &input)?.status.success());
    assert!(!directory.0.join("capture").exists());
    set(&mut input, "--approve", text(&preview, "approval")?);
    set(&mut input, "--progress-timeout-ms", "501");
    assert!(!run(&directory, "capture", &input)?.status.success());
    assert!(!directory.0.join("pins").exists());
    no_connection(&listener)
}

#[test]
fn expired_remote_session_cannot_become_a_later_stall_or_timed_success() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        let directory = Directory::new("expired-control")?;
        let listener = listener()?;
        let mut input = args(&directory, listener.local_addr()?, codec);
        input.insert(0, "reconnect".into());
        // Keepalive becomes pending at one second; the unrenewed lease expires at two.
        // Neither the later four-second duration nor the five-second progress timeout
        // may erase that native protocol refusal or authorize another connection.
        set(&mut input, "--capture-duration-ms", "4000");
        set(&mut input, "--progress-timeout-ms", "5000");
        set(&mut input, "--max-attempts", "3");
        let input = approve(&directory, &input)?;
        let output = capture(&directory, &input, &listener, codec, &[Camera::ExpiredControl])?;
        assert!(!output.status.success());
        let rows = rows(&output)?;
        assert!(details(&rows, "recording_stalled")?.is_empty());
        assert!(details(&rows, "capture_duration_elapsed")?.is_empty());
        assert!(details(&rows, "capture_duration_complete")?.is_empty());
        let terminal = unique(&rows, "terminal")?;
        assert_eq!(text(terminal, "error_id")?, "ERR-CAPTURE-RTSP-SOURCE-001");
        assert!(!flag(terminal, "complete")?);
        assert!(!flag(terminal, "peer_eof")?);
        assert!(!flag(terminal, "input_end_observed")?);
        assert!(flag(terminal, "unsettled_request")?);
        let finished = unique(&rows, "attempt_finished")?;
        assert_eq!(field(finished, "retry_reason")?, &Value::Null);
        assert!(!flag(finished, "retrying")?);
        assert_eq!(number(unique(&rows, "reconnect_terminal")?, "attempts_used")?, 1);
        assert!(!directory.0.join("capture.attempt-0002").exists());
        assert!(!directory.0.join("pins.attempt-0002").exists());
        no_connection(&listener)?;
    }
    Ok(())
}
