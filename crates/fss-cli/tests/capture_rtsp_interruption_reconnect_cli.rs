#![forbid(unsafe_code)]
#![feature(tcp_linger)]
#![cfg(target_os = "linux")]
//! A real abortive TCP close followed by a separately approved native capture.
//! Reset synchronization uses the child's collected-picture report, never a guessed
//! delay or a fabricated native outcome. Reopen each original window after exit.

use fss_cli::json_input::{Value, parse};
use fss_core::{ContentDigest, SensorId, StreamId};
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::rtsp::recording::hevc::local::load_hevc_recording;
use fss_reference::rtsp::recording::{RecordingScope, local::load_recording};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

type Test<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const CONTROL: &str = "fss.rtsp_reconnect_cli.v1";
const NATIVE: &str = "fss.rtsp_capture_cli.v1";
const SDP: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\na=control:trackID=0\r\n";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for index in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-interruption-reconnect-{}-{label}-{index}",
                std::process::id()
            ));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory budget exhausted".into())
    }
    fn attempt(&self, prefix: &str, number: usize) -> PathBuf {
        self.0.join(format!("{prefix}.attempt-{number:04}"))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn read_output(reader: impl Read, exceeded: &AtomicBool) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    reader.take(1024 * 1024 + 1).read_to_end(&mut out)?;
    if out.len() > 1024 * 1024 {
        exceeded.store(true, Ordering::Release);
        return Err(io::Error::other("test output budget exceeded"));
    }
    Ok(out)
}
fn run(args: &[OsString]) -> Test<Output> {
    let binary = std::env::var_os("FSS_CAPTURE_RTSP_BIN")
        .or_else(|| option_env!("CARGO_BIN_EXE_fss-capture-rtsp").map(OsString::from))
        .ok_or("missing native capture binary; set FSS_CAPTURE_RTSP_BIN")?;
    let mut child = Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("stdout")?;
    let stderr = child.stderr.take().ok_or("stderr")?;
    let exceeded = AtomicBool::new(false);
    thread::scope(|scope| {
        let out = scope.spawn(|| read_output(stdout, &exceeded));
        let err = scope.spawn(|| read_output(stderr, &exceeded));
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if exceeded.load(Ordering::Acquire) || Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                break Err(io::Error::other(
                    "native reconnect process exceeded its test bound",
                ));
            }
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => thread::sleep(Duration::from_millis(2)),
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(e);
                }
            }
        };
        let stdout = out.join().map_err(|_| "stdout reader panicked")??;
        let stderr = err.join().map_err(|_| "stderr reader panicked")??;
        Ok(Output {
            status: status?,
            stdout,
            stderr,
        })
    })
}
fn field<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|fields| fields.get(key))
        .ok_or_else(|| format!("missing {key}").into())
}
fn text<'a>(value: &'a Value, key: &str) -> Test<&'a str> {
    field(value, key)?
        .text()
        .ok_or_else(|| format!("nontext {key}").into())
}
fn number(value: &Value, key: &str) -> Test<i128> {
    field(value, key)?
        .integer()
        .ok_or_else(|| format!("noninteger {key}").into())
}
fn flag(value: &Value, key: &str) -> Test<bool> {
    field(value, key)?
        .boolean()
        .ok_or_else(|| format!("nonboolean {key}").into())
}
fn args(directory: &Directory, peer: SocketAddr, codec: &str) -> Vec<OsString> {
    let digest = |label: &str| ContentDigest::sha256(label.as_bytes()).to_text();
    let mut args = vec![OsString::from("reconnect")];
    for (key, value) in [
        ("--root", directory.0.join("capture").display().to_string()),
        ("--pins", directory.0.join("pins").display().to_string()),
        ("--peer", peer.to_string()),
        ("--authority", peer.to_string()),
        ("--presentation", "/live/".into()),
        ("--control-root", "/live".into()),
        ("--sensor-id", "sensor:reconnect".into()),
        ("--stream-id", "stream:reconnect".into()),
        ("--generation", "7".into()),
        ("--ingress", "71".into()),
        ("--ssrc", "7".into()),
        ("--anchor", digest("owner anchor")),
        ("--receive-clock", digest("owner receive")),
        ("--timing-evidence", digest("25fps cadence")),
        ("--journal-id", digest("pin epoch")),
        ("--frame-duration-ticks", "3600".into()),
        ("--stop-after-pictures", "2".into()),
        ("--owner-authorized", "yes".into()),
        ("--plaintext", "yes".into()),
        ("--retain-originals", "yes".into()),
        ("--codec", codec.into()),
        ("--timeout-ms", "5000".into()),
        ("--drain-timeout-ms", "5000".into()),
        ("--connect-timeout-ms", "1000".into()),
        ("--response-timeout-ms", "1000".into()),
        ("--max-report-bytes", "131072".into()),
        ("--max-attempts", "3".into()),
        ("--retry-delay-ms", "5".into()),
        ("--retry-max-delay-ms", "10".into()),
    ] {
        args.extend([key.into(), value.into()]);
    }
    args
}
fn preview(args: &[OsString]) -> Test<Value> {
    let out = run(args)?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let preview = parse(std::str::from_utf8(&out.stdout)?)?;
    assert_eq!(text(&preview, "schema")?, CONTROL);
    Ok(preview)
}
fn approved(args: &[OsString]) -> Test<Vec<OsString>> {
    let plan = preview(args)?;
    let mut out = args.to_vec();
    out.extend(["--approve".into(), text(&plan, "approval")?.into()]);
    Ok(out)
}
fn listener() -> Test<TcpListener> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}
fn rows(output: &Output) -> Test<Vec<Value>> {
    let mut rows = Vec::new();
    let mut outer = 0;
    let mut native = 0;
    let mut native_open = false;
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let row = parse(line)?;
        let schema = text(&row, "schema")?;
        let kind = text(&row, "kind")?;
        let sequence = number(&row, "sequence")?;
        match schema {
            CONTROL => {
                assert_eq!(sequence, outer);
                outer += 1;
                if kind == "attempt_started" {
                    assert!(!native_open);
                }
                if kind == "attempt_finished" {
                    assert!(!native_open);
                }
            }
            NATIVE => {
                if kind == "started" {
                    assert!(!native_open);
                    native_open = true;
                    native = 0;
                }
                assert!(native_open);
                assert_eq!(sequence, native);
                native += 1;
                if kind == "terminal" {
                    native_open = false;
                }
            }
            _ => return Err("unexpected capture output schema".into()),
        }
        rows.push(row);
    }
    assert!(!native_open, "native attempt omitted its terminal report");
    Ok(rows)
}
fn details<'a>(rows: &'a [Value], schema: &str, kind: &str) -> Test<Vec<&'a Value>> {
    let mut out = Vec::new();
    for row in rows {
        if text(row, "schema")? == schema && text(row, "kind")? == kind {
            out.push(field(row, "detail")?);
        }
    }
    Ok(out)
}

fn request(peer: &mut TcpStream) -> Test<Option<(String, u32)>> {
    let mut bytes = Vec::new();
    while bytes.len() < 8192 {
        let mut byte = [0];
        match peer.read(&mut byte)? {
            0 if bytes.is_empty() => return Ok(None),
            0 => return Err("client closed mid-request".into()),
            _ => bytes.push(byte[0]),
        }
        if bytes.ends_with(b"\r\n\r\n") {
            let wire = String::from_utf8(bytes)?;
            assert!(!wire.to_ascii_lowercase().contains("authorization:"));
            let method = wire
                .split_ascii_whitespace()
                .next()
                .ok_or("method")?
                .to_owned();
            let cseq = wire
                .split("\r\n")
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("cseq").then_some(value.trim())
                })
                .ok_or("CSeq")?
                .parse()?;
            return Ok(Some((method, cseq)));
        }
    }
    Err("request budget exhausted".into())
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
fn video(pictures: usize) -> Test<Vec<u8>> {
    let bytes: &'static [u8] = include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264");
    let mut starts = Vec::new();
    let mut at = 0;
    while at + 3 <= bytes.len() {
        let prefix = if bytes.get(at..at + 4) == Some(&[0, 0, 0, 1]) {
            4
        } else if bytes[at..at + 3] == [0, 0, 1] {
            3
        } else {
            0
        };
        if prefix == 0 {
            at += 1;
        } else {
            starts.push((at, at + prefix));
            at += prefix;
        }
    }
    let mut out = Vec::new();
    let mut sequence = 1_u16;
    let mut count = 0;
    for (index, (_, start)) in starts.iter().enumerate() {
        if count == pictures {
            break;
        }
        let mut end = starts.get(index + 1).map_or(bytes.len(), |next| next.0);
        while end > *start && bytes[end - 1] == 0 {
            end -= 1;
        }
        let nal = &bytes[*start..end];
        let kind = nal.first().ok_or("empty fixture NAL")? & 31;
        if !matches!(kind, 1 | 5 | 6 | 7 | 8) {
            continue;
        }
        let picture = matches!(kind, 1 | 5);
        let mut packet = vec![0x80, 96 | if picture { 128 } else { 0 }];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&(9000_u32 + count as u32 * 3600).to_be_bytes());
        packet.extend_from_slice(&7_u32.to_be_bytes());
        packet.extend_from_slice(nal);
        out.extend_from_slice(&[b'$', 0]);
        out.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
        out.extend_from_slice(&packet);
        sequence += 1;
        count += usize::from(picture);
    }
    assert_eq!(count, pictures);
    Ok(out)
}

const SOURCE_ERROR: &str = "ERR-CAPTURE-RTSP-SOURCE-001";
const OUTPUT_BOUND: u64 = 1024 * 1024;

fn set(args: &mut Vec<OsString>, name: &str, value: &str) {
    match args.iter().position(|arg| arg == name) {
        Some(at) => args[at + 1] = value.into(),
        None => args.extend([name.into(), value.into()]),
    }
}

struct NativeChild {
    child: Child,
    stdout: PathBuf,
    stderr: PathBuf,
}
impl Drop for NativeChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl NativeChild {
    fn spawn(directory: &Directory, args: &[OsString]) -> Test<Self> {
        let binary = std::env::var_os("FSS_CAPTURE_RTSP_BIN")
            .or_else(|| option_env!("CARGO_BIN_EXE_fss-capture-rtsp").map(OsString::from))
            .ok_or("missing native capture binary")?;
        let stdout = directory.0.join("stdout.jsonl");
        let stderr = directory.0.join("stderr.txt");
        let create = |path: &PathBuf| {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
        };
        let child = Command::new(binary)
            .args(args)
            .stdin(Stdio::null())
            .stdout(create(&stdout)?)
            .stderr(create(&stderr)?)
            .spawn()?;
        Ok(Self {
            child,
            stdout,
            stderr,
        })
    }
    fn read(&self, path: &PathBuf) -> Test<Vec<u8>> {
        if fs::metadata(&self.stdout)?.len() > OUTPUT_BOUND
            || fs::metadata(&self.stderr)?.len() > OUTPUT_BOUND
        {
            return Err("child output bound exceeded".into());
        }
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(OUTPUT_BOUND + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > OUTPUT_BOUND {
            return Err("child output bound exceeded during read".into());
        }
        Ok(bytes)
    }
    fn observed_pictures(&mut self, minimum: usize) -> Test {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let bytes = self.read(&self.stdout)?;
            let mut count = 0;
            // A concurrently written final row is not yet an observation.
            for row in bytes.split_inclusive(|byte| *byte == b'\n') {
                if row.last() != Some(&b'\n') {
                    continue;
                }
                let row = parse(std::str::from_utf8(row)?)?;
                if text(&row, "schema")? == NATIVE && text(&row, "kind")? == "picture_collected" {
                    count += 1;
                }
            }
            if count >= minimum {
                return Ok(());
            }
            if self.child.try_wait()?.is_some() || Instant::now() >= deadline {
                return Err(format!(
                    "missing picture receipt; stdout={} stderr={}",
                    String::from_utf8_lossy(&bytes),
                    String::from_utf8_lossy(&self.read(&self.stderr)?)
                )
                .into());
            }
            thread::sleep(Duration::from_millis(2));
        }
    }
    fn finish(mut self) -> Test<Output> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let stdout = self.read(&self.stdout)?;
            let stderr = self.read(&self.stderr)?;
            if let Some(status) = self.child.try_wait()? {
                // Re-read after exit so the terminal report cannot be lost to a race.
                return Ok(Output {
                    status,
                    stdout: self.read(&self.stdout)?,
                    stderr: self.read(&self.stderr)?,
                });
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "child finish deadline; stdout={} stderr={}",
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr)
                )
                .into());
            }
            thread::sleep(Duration::from_millis(2));
        }
    }
}

fn hevc_video(pictures: usize) -> Test<Vec<u8>> {
    let nals = include_str!("../../../tests/fixtures/media/hevc/remux_main8.nals.hex")
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| -> Test<Vec<u8>> {
            if !line.is_ascii() || !line.len().is_multiple_of(2) {
                return Err("invalid fixture hex".into());
            }
            (0..line.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&line[at..at + 2], 16).map_err(Into::into))
                .collect()
        })
        .collect::<Test<Vec<_>>>()?;
    assert!((1..=2).contains(&pictures));
    let mut wire = Vec::new();
    // Probation VPS plus VPS/SPS/PPS/IDR/next-picture. For two pictures the
    // following VPS is the real source boundary. Markers never stand in for it.
    for (index, nal) in std::iter::once(&nals[0])
        .chain(nals.iter().take(if pictures == 1 { 5 } else { 6 }))
        .enumerate()
    {
        let timestamps = [0_u32, 0, 0, 0, 0, 18000, 36000];
        let mut packet = vec![0x80, 98 | 128];
        packet.extend_from_slice(&u16::try_from(index)?.to_be_bytes());
        packet.extend_from_slice(&timestamps[index].to_be_bytes());
        packet.extend_from_slice(&7_u32.to_be_bytes());
        packet.extend_from_slice(nal);
        wire.extend_from_slice(&[b'$', 0]);
        wire.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
        wire.extend_from_slice(&packet);
    }
    Ok(wire)
}

fn connect_camera(listener: &TcpListener, codec: &str, pending_control: bool) -> Test<TcpStream> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut peer = loop {
        match listener.accept() {
            Ok((peer, _)) => break peer,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error.into()),
        }
    };
    peer.set_read_timeout(Some(Duration::from_secs(10)))?;
    peer.set_write_timeout(Some(Duration::from_secs(10)))?;
    peer.set_nodelay(true)?;
    let hevc_sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 98\r\na=rtpmap:98 H265/90000\r\na=fmtp:98 sprop-vps=QAEMAf//AWAAAAMAkAAAAwAAAwAeugJA;sprop-sps=QgEBAWAAAAMAkAAAAwAAAwAeoCCDHVZbpKTC8BaAgAAAAwCAAAADAoQ=;sprop-pps=RAHAc8CJ\r\na=control:trackID=0\r\n";
    let setup = format!(
        "Session: fixture;timeout={}\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n",
        if pending_control { 1 } else { 60 }
    );
    for (expected, headers, body) in [
        (
            "DESCRIBE",
            "Content-Type: application/sdp\r\n",
            if codec == "hevc" { hevc_sdp } else { SDP },
        ),
        ("SETUP", setup.as_str(), ""),
        ("PLAY", "Session: fixture\r\n", ""),
    ] {
        let (method, cseq) = request(&mut peer)?.ok_or("missing control request")?;
        assert_eq!(method, expected);
        response(&mut peer, cseq, headers, body)?;
    }
    Ok(peer)
}

fn send_video(peer: &mut TcpStream, codec: &str, pictures: usize) -> Test {
    peer.write_all(&if codec == "hevc" {
        hevc_video(pictures)?
    } else {
        video(pictures)?
    })?;
    Ok(())
}

fn verify_windows(directory: &Directory, rows: &[Value], expected: &[usize], codec: &str) -> Test {
    let windows = details(rows, NATIVE, "window_durable")?;
    assert_eq!(windows.len(), expected.len());
    for (index, (window, pictures)) in windows.iter().zip(expected).enumerate() {
        let source = field(window, "source")?;
        let recording_scope = RecordingScope {
            sensor: SensorId::parse(text(source, "sensor_id")?)?,
            stream: StreamId::parse(text(source, "stream_id")?)?,
            generation: u64::try_from(number(source, "generation")?)?,
            anchor: ContentDigest::parse(text(source, "anchor")?)?,
            receive_clock: ContentDigest::parse(text(source, "receive_clock")?)?,
        };
        assert_eq!(recording_scope.generation, 7 + index as u64);
        let publisher = LocalRootPublisher::open(
            directory.attempt("capture", index + 1),
            LocalPublicationLimits::new(
                256,
                64,
                256,
                512,
                SpoolLimits::new(1024, 64 * 1024 * 1024, 16 * 1024 * 1024, 1024),
            ),
        )?;
        let slot = SlotName::parse(text(window, "slot")?)?;
        let root = ContentDigest::parse(text(window, "root")?)?;
        let (samples, retained_bytes) = if codec == "hevc" {
            let retained =
                load_hevc_recording(&publisher, &slot, root, &recording_scope, &NeverCancel)?;
            (retained.summary().samples, retained.objects().source.len())
        } else {
            let retained = load_recording(&publisher, &slot, root, &recording_scope, &NeverCancel)?;
            (retained.summary().samples, retained.objects().source.len())
        };
        assert_eq!(samples, *pictures);
        assert_eq!(
            i128::try_from(retained_bytes)?,
            number(window, "source_object_bytes")?
        );
        assert_eq!(number(window, "pictures")?, i128::try_from(*pictures)?);
        assert_eq!(text(window, "codec")?, codec);
    }
    Ok(())
}

fn exercise(codec: &str, enabled: bool, pending: bool, campaign: bool, exhausted: bool) -> Test {
    let directory = Directory::new(codec)?;
    let camera = listener()?;
    let mut input = args(&directory, camera.local_addr()?, codec);
    set(&mut input, "--max-attempts", "2");
    set(&mut input, "--timeout-ms", "15000");
    if codec == "hevc" {
        set(&mut input, "--payload-type", "98");
        set(&mut input, "--frame-duration-ticks", "18000");
    }
    if enabled {
        set(&mut input, "--retry-interrupted", "yes");
    }
    if campaign {
        set(&mut input, "--continue-after-success", "yes");
    }
    let approved = approved(&input)?;
    assert!(matches!(camera.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
    let mut child = NativeChild::spawn(&directory, &approved)?;
    let attempts = if enabled && !pending { 2 } else { 1 };
    for index in 0..attempts {
        let mut peer = connect_camera(&camera, codec, pending)?;
        let reset = index == 0 || exhausted;
        send_video(&mut peer, codec, if reset { 1 } else { 2 })?;
        if reset {
            child.observed_pictures(index + 1)?;
            if pending {
                let (method, _) = request(&mut peer)?.ok_or("missing keepalive")?;
                assert_eq!(method, "OPTIONS"); // deliberately do not answer
            }
            peer.set_linger(Some(Duration::ZERO))?;
            drop(peer);
        } else {
            // Keep the camera write side open until the native owner closes it.
            assert!(request(&mut peer)?.is_none());
        }
    }
    let output = child.finish()?;
    assert_eq!(
        output.status.success(),
        enabled && !pending && !campaign && !exhausted,
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(matches!(camera.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
    let all = rows(&output)?;
    let native = details(&all, NATIVE, "terminal")?;
    let finished = details(&all, CONTROL, "attempt_finished")?;
    assert_eq!(native.len(), attempts);
    assert_eq!(finished.len(), attempts);
    assert!(!flag(native[0], "complete")?);
    assert_eq!(text(native[0], "error_id")?, SOURCE_ERROR);
    assert!(!flag(native[0], "input_end_observed")?);
    assert!(!flag(native[0], "peer_eof")?);
    assert_eq!(flag(native[0], "unsettled_request")?, pending);
    assert_eq!(number(native[0], "durable_pictures")?, 1);
    assert_eq!(number(native[0], "collected_pictures")?, 1);
    assert_eq!(number(native[0], "durable_windows")?, 1);
    assert_eq!(number(native[0], "indexed_windows")?, 1);
    assert!(!matches!(field(native[0], "snapshot_digest")?, Value::Null));
    assert!(!flag(finished[0], "recovery_required")?);
    assert_eq!(flag(finished[0], "retrying")?, attempts == 2);
    if attempts == 2 {
        assert_eq!(
            text(finished[0], "retry_reason")?,
            "read_interrupted_after_verified_drain"
        );
        let started = details(&all, NATIVE, "started")?;
        for key in ["archive_namespace", "journal_id", "decode_clock"] {
            assert_ne!(text(started[0], key)?, text(started[1], key)?);
        }
        assert_ne!(
            text(field(started[0], "source")?, "receive_clock")?,
            text(field(started[1], "source")?, "receive_clock")?
        );
        assert_eq!(flag(native[1], "complete")?, !exhausted);
        assert_eq!(
            number(native[1], "durable_pictures")?,
            if exhausted { 1 } else { 2 }
        );
    }
    let terminal = details(&all, CONTROL, "reconnect_terminal")?;
    assert_eq!(terminal.len(), 1);
    assert_eq!(
        number(terminal[0], "attempts_used")?,
        i128::try_from(attempts)?
    );
    assert!(!flag(terminal[0], "continuity_across_attempts")?);
    assert!(!flag(terminal[0], "absence_certifiable")?);
    if campaign {
        assert_eq!(text(terminal[0], "first_error_id")?, SOURCE_ERROR);
        assert_eq!(number(terminal[0], "first_failed_attempt")?, 1);
    }
    if exhausted {
        assert!(flag(terminal[0], "attempt_limit_reached")?);
    }
    let expected = if attempts == 1 {
        vec![1]
    } else if exhausted {
        vec![1, 1]
    } else {
        vec![1, 2]
    };
    verify_windows(&directory, &all, &expected, codec)?;
    assert!(!directory.attempt("capture", attempts + 1).exists());
    assert!(!directory.attempt("pins", attempts + 1).exists());
    Ok(())
}

#[test]
fn real_reset_then_success_keeps_two_cold_verified_independent_archives() -> Test {
    for codec in ["avc", "hevc"] {
        exercise(codec, true, false, false, false)?;
    }
    Ok(())
}
#[test]
fn real_reset_without_new_approval_preserves_prefix_but_never_reconnects() -> Test {
    for codec in ["avc", "hevc"] {
        exercise(codec, false, false, false, false)?;
    }
    Ok(())
}
#[test]
fn real_reset_with_pending_control_cannot_reconnect_even_with_opt_in() -> Test {
    for codec in ["avc", "hevc"] {
        exercise(codec, true, true, false, false)?;
    }
    Ok(())
}
#[test]
fn real_interrupted_campaign_cannot_erase_failure_with_later_success() -> Test {
    for codec in ["avc", "hevc"] {
        exercise(codec, true, false, true, false)?;
    }
    Ok(())
}
#[test]
fn repeated_real_resets_exhaust_exactly_the_two_approved_attempts() -> Test {
    for codec in ["avc", "hevc"] {
        exercise(codec, true, false, false, true)?;
    }
    Ok(())
}
