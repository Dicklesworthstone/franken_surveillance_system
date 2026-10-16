#![forbid(unsafe_code)]
//! Real-process loopback keepalive contracts. No device discovery or external endpoint.
//! Retained windows remain subject to the existing codec, timing and publication owners.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;

type Test<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const OUTPUT_LIMIT: u64 = 2 * 1024 * 1024;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for ordinal in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-keepalive-{}-{label}-{ordinal}", std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("fixture directory bound".into())
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
fn run(directory: &Directory, args: &[OsString]) -> Test<Output> {
    let mut output_path = None;
    for index in 0..100 {
        let path = directory.0.join(format!("process-{index}"));
        match fs::create_dir(&path) {
            Ok(()) => { output_path = Some(path); break; }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    let path = output_path.ok_or("fixture process bound")?;
    let create = |name: &str| OpenOptions::new().write(true).create_new(true).open(path.join(name));
    let binary = std::env::var_os("FSS_CAPTURE_RTSP_BIN")
        .or_else(|| option_env!("CARGO_BIN_EXE_fss-capture-rtsp").map(OsString::from))
        .ok_or("capture executable unavailable")?;
    let mut child = Process(Command::new(binary).args(args).stdin(Stdio::null())
        .stdout(Stdio::from(create("stdout")?))
        .stderr(Stdio::from(create("stderr")?)).spawn()?);
    let until = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if Instant::now() >= until
            || fs::metadata(path.join("stdout"))?.len() > OUTPUT_LIMIT
            || fs::metadata(path.join("stderr"))?.len() > OUTPUT_LIMIT
        {
            return Err("capture fixture exceeded time/output allowance".into());
        }
        if let Some(status) = child.0.try_wait()? { break status; }
        thread::sleep(Duration::from_millis(2));
    };
    let read = |name: &str| -> Test<Vec<u8>> {
        let mut bytes = Vec::new();
        File::open(path.join(name))?.take(OUTPUT_LIMIT + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > OUTPUT_LIMIT { return Err("fixture output bound".into()); }
        Ok(bytes)
    };
    Ok(Output { status, stdout: read("stdout")?, stderr: read("stderr")? })
}
fn good(output: Output) -> Test<String> {
    assert!(output.status.success(), "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    Ok(String::from_utf8(output.stdout)?)
}
fn field<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    value.object().and_then(|object| object.get(key)).ok_or_else(|| format!("missing {key}").into())
}
fn text<'a>(value: &'a Value, key: &str) -> Test<&'a str> {
    field(value, key)?.text().ok_or_else(|| format!("{key} not text").into())
}
fn integer(value: &Value, key: &str) -> Test<i128> {
    field(value, key)?.integer().ok_or_else(|| format!("{key} not integer").into())
}
fn flag(value: &Value, key: &str) -> Test<bool> {
    field(value, key)?.boolean().ok_or_else(|| format!("{key} not boolean").into())
}
fn set(args: &mut Vec<OsString>, key: &str, value: &str) {
    match args.iter().position(|arg| arg == key) {
        Some(at) => args[at + 1] = value.into(),
        None => args.extend([key.into(), value.into()]),
    }
}
fn digest(label: &str) -> String { ContentDigest::sha256(label.as_bytes()).to_text() }
fn listener() -> Test<TcpListener> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}
fn no_connection(listener: &TcpListener) -> Test {
    match listener.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Ok(_) => Err("unexpected connection or retry".into()),
        Err(error) => Err(error.into()),
    }
}
#[derive(Clone, Copy)]
enum Codec { Avc, Hevc }
impl Codec {
    fn name(self) -> &'static str { match self { Self::Avc => "avc", Self::Hevc => "hevc" } }
    fn payload(self) -> u8 { match self { Self::Avc => 96, Self::Hevc => 98 } }
    fn cadence(self) -> u32 { match self { Self::Avc => 3600, Self::Hevc => 18_000 } }
    fn sdp(self) -> String {
        let mapping = match self {
            Self::Avc => concat!("a=rtpmap:96 H264/90000\r\n",
                "a=fmtp:96 packetization-mode=1;sprop-parameter-sets=",
                "Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\n"),
            Self::Hevc => concat!("a=rtpmap:98 H265/90000\r\n",
                "a=fmtp:98 sprop-vps=QAEMAf//AWAAAAMAkAAAAwAAAwAeugJA;",
                "sprop-sps=QgEBAWAAAAMAkAAAAwAAAwAeoCCDHVZbpKTC8BaAgAAAAwCAAAADAoQ=;",
                "sprop-pps=RAHAc8CJ\r\n"),
        };
        format!("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP {}\r\n{mapping}a=control:trackID=0\r\n", self.payload())
    }
}
fn arguments(directory: &Directory, address: SocketAddr, codec: Codec) -> Vec<OsString> {
    [
        ("--root", directory.0.join("capture").display().to_string()),
        ("--pins", directory.0.join("pins").display().to_string()),
        ("--peer", address.to_string()), ("--authority", address.to_string()),
        ("--presentation", "/live/".into()), ("--control-root", "/live".into()),
        ("--sensor-id", "sensor:keepalive-fixture".into()),
        ("--stream-id", "stream:keepalive-fixture".into()),
        ("--generation", "1".into()), ("--ingress", "71".into()), ("--ssrc", "7".into()),
        ("--anchor", digest("keepalive anchor")),
        ("--receive-clock", digest("keepalive receive clock")),
        ("--timing-evidence", digest("keepalive fixed cadence")),
        ("--journal-id", digest("keepalive independent journal")),
        ("--frame-duration-ticks", codec.cadence().to_string()),
        ("--stop-after-pictures", "2".into()), ("--owner-authorized", "yes".into()),
        ("--plaintext", "yes".into()), ("--retain-originals", "yes".into()),
        ("--timeout-ms", "10000".into()), ("--drain-timeout-ms", "5000".into()),
        ("--response-timeout-ms", "2000".into()), ("--max-report-bytes", "131072".into()),
        ("--max-window-pictures", "16".into()), ("--codec", codec.name().into()),
        ("--payload-type", codec.payload().to_string()),
    ].into_iter().flat_map(|(key, value)| [key.into(), value.into()]).collect()
}
fn preview(directory: &Directory, args: &[OsString]) -> Test<Value> {
    Ok(parse(&good(run(directory, args)?)?)?)
}
fn approve(directory: &Directory, args: &[OsString]) -> Test<Vec<OsString>> {
    let value = preview(directory, args)?;
    let mut args = args.to_vec();
    set(&mut args, "--approve", text(&value, "approval")?);
    Ok(args)
}
fn request(peer: &mut TcpStream) -> Test<Option<String>> {
    let until = Instant::now() + Duration::from_secs(8);
    let mut bytes = Vec::new();
    while bytes.len() < 8192 && Instant::now() < until {
        let mut byte = [0];
        match peer.read(&mut byte) {
            Ok(0) if bytes.is_empty() => return Ok(None),
            Ok(0) => return Err("partial fixture request".into()),
            Ok(_) => bytes.push(byte[0]),
            Err(error) if bytes.is_empty() && matches!(error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted) => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        if bytes.ends_with(b"\r\n\r\n") { return Ok(Some(String::from_utf8(bytes)?)); }
    }
    Err("fixture request length/time bound".into())
}
fn required_request(peer: &mut TcpStream, expected: &str) -> Test<(String, u32)> {
    let request = request(peer)?.ok_or("early socket closure")?;
    assert!(request.starts_with(&format!("{expected} ")), "unexpected fixture method");
    let cseq = request.lines().find_map(|line| line.strip_prefix("CSeq: "))
        .ok_or("fixture CSeq missing")?.parse()?;
    Ok((request, cseq))
}
fn response(peer: &mut TcpStream, cseq: u32, status: u16, headers: &str, body: &str) -> Test {
    peer.write_all(format!("RTSP/1.0 {status} Fixture\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}", body.len()).as_bytes())?;
    Ok(())
}
fn framed(codec: Codec, sequence: u16, timestamp: u32, nal: &[u8]) -> Test<Vec<u8>> {
    let mut packet = vec![0x80, codec.payload() | 128];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.extend_from_slice(&7_u32.to_be_bytes());
    packet.extend_from_slice(nal);
    let mut wire = vec![b'$', 0];
    wire.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
    wire.extend_from_slice(&packet);
    Ok(wire)
}
fn media(codec: Codec) -> Test<Vec<Vec<u8>>> {
    match codec {
        Codec::Avc => {
            let bytes = include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264");
            let mut starts = Vec::new();
            let mut at = 0;
            while at + 3 <= bytes.len() {
                let prefix = if bytes.get(at..at + 4) == Some(&[0, 0, 0, 1]) { 4 }
                    else if bytes[at..at + 3] == [0, 0, 1] { 3 } else { 0 };
                if prefix != 0 { starts.push((at, at + prefix)); at += prefix; } else { at += 1; }
            }
            let nals: Vec<_> = starts.iter().enumerate().filter_map(|(index, (_, begin))| {
                let mut end = starts.get(index + 1).map_or(bytes.len(), |(at, _)| *at);
                while end > *begin && bytes[end - 1] == 0 { end -= 1; }
                (*begin < end).then_some(&bytes[*begin..end])
            }).collect();
            let mut out = vec![framed(codec, 0, 9000, nals.first().ok_or("AVC fixture missing")?)?];
            let mut pictures = 0;
            for nal in nals {
                if pictures == 2 { break; }
                let kind = nal[0] & 31;
                if !matches!(kind, 1 | 5 | 6 | 7 | 8) { continue; }
                out.push(framed(codec, u16::try_from(out.len())?, 9000 + pictures * 3600, nal)?);
                if matches!(kind, 1 | 5) { pictures += 1; }
            }
            assert_eq!(pictures, 2);
            Ok(out)
        }
        Codec::Hevc => {
            let nals: Vec<Vec<u8>> = include_str!("../../../tests/fixtures/media/hevc/remux_main8.nals.hex")
                .lines().filter(|line| !line.trim().is_empty()).map(|line| -> Test<Vec<u8>> {
                    if !line.is_ascii() || !line.len().is_multiple_of(2) { return Err("HEVC fixture hex".into()); }
                    (0..line.len()).step_by(2).map(|at| u8::from_str_radix(&line[at..at + 2], 16)
                        .map_err(Into::into)).collect()
                }).collect::<Test<_>>()?;
            let mut out = vec![framed(codec, 0, 0, nals.first().ok_or("HEVC fixture missing")?)?];
            for (index, (nal, timestamp)) in nals.iter().zip([0, 0, 0, 0, 18_000, 36_000]).enumerate() {
                out.push(framed(codec, u16::try_from(index + 1)?, timestamp, nal)?);
            }
            assert_eq!(out.len(), 7); // final VPS witnesses the second picture boundary
            Ok(out)
        }
    }
}
#[derive(Clone, Copy)]
enum End { Record, Reject, WrongSession, Silent }
fn serve(listener: &TcpListener, codec: Codec, method: &str, end: End) -> Test {
    let until = Instant::now() + Duration::from_secs(10);
    let mut peer = loop {
        match listener.accept() {
            Ok((peer, _)) => break peer,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < until =>
                thread::sleep(Duration::from_millis(2)),
            Err(error) => return Err(error.into()),
        }
    };
    peer.set_read_timeout(Some(Duration::from_secs(8)))?;
    peer.set_write_timeout(Some(Duration::from_secs(3)))?;
    peer.set_nodelay(true)?;
    let (_, cseq) = required_request(&mut peer, "DESCRIBE")?;
    response(&mut peer, cseq, 200, "Content-Type: application/sdp\r\n", &codec.sdp())?;
    let (_, cseq) = required_request(&mut peer, "SETUP")?;
    // One-second session: actual owner-driven liveness is observable without synthetic clocks.
    response(&mut peer, cseq, 200,
        "Session: fixture;timeout=1\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n", "")?;
    let (_, cseq) = required_request(&mut peer, "PLAY")?;
    response(&mut peer, cseq, 200, "Session: fixture\r\n", "")?;
    let (wire, cseq) = required_request(&mut peer, method)?;
    let target = format!("rtsp://{}/live/", listener.local_addr()?);
    assert!(wire.starts_with(&format!("{method} {target} RTSP/1.0\r\n")));
    assert!(wire.contains("Session: fixture\r\n"));
    assert!(!wire.contains("Authorization:"));
    if method == "GET_PARAMETER" {
        assert_eq!(wire, format!("GET_PARAMETER {target} RTSP/1.0\r\nCSeq: {cseq}\r\nSession: fixture\r\nContent-Length: 0\r\n\r\n"));
    } else {
        assert!(!wire.contains("Content-Length:"));
    }
    match end {
        End::Reject => response(&mut peer, cseq, 405, "", "")?,
        End::WrongSession => response(&mut peer, cseq, 200, "Session: other\r\n", "")?,
        End::Silent => {}
        End::Record => {
            response(&mut peer, cseq, 200, "Session: fixture;timeout=10\r\n", "")?;
            for packet in media(codec)? { peer.write_all(&packet)?; }
        }
    }
    // No implicit OPTIONS fallback, automatic TEARDOWN or request replay is permitted.
    assert!(request(&mut peer)?.is_none(), "unexpected request after terminal fixture");
    Ok(())
}
fn capture(directory: &Directory, args: &[OsString], listener: &TcpListener, codec: Codec, method: &str, end: End) -> Test<Output> {
    thread::scope(|scope| {
        let server = scope.spawn(|| serve(listener, codec, method, end));
        let result = run(directory, args);
        let served = server.join().map_err(|_| "fixture server panicked")?;
        let result = result?;
        if let Err(error) = served {
            return Err(format!("{error}; stdout={} stderr={}",
                String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr)).into());
        }
        Ok(result)
    })
}
fn rows(output: &Output) -> Test<Vec<Value>> {
    std::str::from_utf8(&output.stdout)?.lines().map(|line| parse(line).map_err(Into::into)).collect()
}
fn details<'a>(rows: &'a [Value], kind: &str) -> Test<Vec<&'a Value>> {
    rows.iter().filter(|row| text(row, "kind").ok() == Some(kind))
        .map(|row| field(row, "detail")).collect()
}
fn terminal(rows: &[Value]) -> Test<&Value> {
    let matches = details(rows, "terminal")?;
    if matches.len() != 1 { return Err("expected one complete terminal report".into()); }
    Ok(matches[0])
}

#[test]
fn explicit_options_preserves_approval_and_get_parameter_changes_only_control_authority() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        let directory = Directory::new("approval")?;
        let listener = listener()?;
        let mut args = arguments(&directory, listener.local_addr()?, codec);
        let legacy = preview(&directory, &args)?;
        assert_eq!(text(&legacy, "keepalive_method")?, "OPTIONS");
        set(&mut args, "--keepalive-method", "options");
        let explicit = preview(&directory, &args)?;
        assert_eq!(text(&legacy, "approval")?, text(&explicit, "approval")?);
        set(&mut args, "--keepalive-method", "get-parameter");
        let selected = preview(&directory, &args)?;
        assert_ne!(text(&legacy, "approval")?, text(&selected, "approval")?);
        assert_eq!(text(&selected, "keepalive_method")?, "GET_PARAMETER");
        assert!(!flag(&selected, "keepalive_fallback")?);
        for key in ["decode_clock", "archive_namespace", "journal_id", "receive_clock", "policy"] {
            assert_eq!(text(&legacy, key)?, text(&selected, key)?);
        }
        assert!(!directory.0.join("capture").exists());
        assert!(!directory.0.join("pins").exists());
        no_connection(&listener)?;
    }
    Ok(())
}

#[test]
fn stale_approval_and_invalid_method_refuse_before_camera_or_directory_effects() -> Test {
    let directory = Directory::new("refused")?;
    let listener = listener()?;
    let args = arguments(&directory, listener.local_addr()?, Codec::Avc);
    let legacy = preview(&directory, &args)?;
    let mut changed = args.clone();
    set(&mut changed, "--keepalive-method", "get-parameter");
    set(&mut changed, "--approve", text(&legacy, "approval")?);
    assert!(!run(&directory, &changed)?.status.success());
    for method in ["auto", "GET_PARAMETER", "get_parameter", "set-parameter", "get-parameter\r\nX:Y"] {
        let mut invalid = args.clone();
        set(&mut invalid, "--keepalive-method", method);
        assert!(!run(&directory, &invalid)?.status.success());
    }
    let mut duplicate = args;
    duplicate.extend(["--keepalive-method".into(), "options".into(),
        "--keepalive-method".into(), "get-parameter".into()]);
    assert!(!run(&directory, &duplicate)?.status.success());
    assert!(!directory.0.join("capture").exists());
    assert!(!directory.0.join("pins").exists());
    no_connection(&listener)
}

#[test]
fn avc_and_hevc_publish_completed_recordings_after_the_selected_keepalive() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        for (option, method) in [("options", "OPTIONS"), ("get-parameter", "GET_PARAMETER")] {
            let directory = Directory::new("record")?;
            let listener = listener()?;
            let mut input = arguments(&directory, listener.local_addr()?, codec);
            set(&mut input, "--keepalive-method", option);
            let approved = approve(&directory, &input)?;
            let output = capture(&directory, &approved, &listener, codec, method, End::Record)?;
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
            let rows = rows(&output)?;
            let terminal = terminal(&rows)?;
            assert!(flag(terminal, "complete")?);
            assert!(!flag(terminal, "peer_eof")?);
            assert_eq!(integer(terminal, "durable_pictures")?, 2);
            assert_eq!(integer(terminal, "durable_windows")?, integer(terminal, "indexed_windows")?);
            assert!(!details(&rows, "window_durable")?.is_empty());
            assert!(!details(&rows, "catalog_published")?.is_empty());
            let keepalives: Vec<_> = details(&rows, "request_queued")?.into_iter()
                .filter(|row| text(row, "command").ok() == Some("KEEPALIVE")).collect();
            assert_eq!(keepalives.len(), 1);
            assert_eq!(text(keepalives[0], "method")?, method);
            no_connection(&listener)?;
        }
    }
    Ok(())
}

#[test]
fn rejected_wrong_session_and_missing_keepalive_replies_cannot_fall_back_or_certify_capture() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        for end in [End::Reject, End::WrongSession, End::Silent] {
            let directory = Directory::new("no-fallback")?;
            let listener = listener()?;
            let mut input = arguments(&directory, listener.local_addr()?, codec);
            set(&mut input, "--keepalive-method", "get-parameter");
            let approved = approve(&directory, &input)?;
            let output = capture(&directory, &approved, &listener, codec, "GET_PARAMETER", end)?;
            assert!(!output.status.success());
            let rows = rows(&output)?;
            let terminal = terminal(&rows)?;
            assert!(!flag(terminal, "complete")?);
            assert!(!flag(terminal, "peer_eof")?);
            assert_eq!(integer(terminal, "durable_pictures")?, 0);
            assert!(details(&rows, "window_durable")?.is_empty());
            let keepalives: Vec<_> = details(&rows, "request_queued")?.into_iter()
                .filter(|row| text(row, "command").ok() == Some("KEEPALIVE")).collect();
            assert_eq!(keepalives.len(), 1);
            assert_eq!(text(keepalives[0], "method")?, "GET_PARAMETER");
            no_connection(&listener)?;
        }
    }
    Ok(())
}

#[test]
fn reconnect_approval_binds_method_for_every_fresh_epoch_without_changing_clocks() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        let directory = Directory::new("reconnect")?;
        let listener = listener()?;
        let mut input = arguments(&directory, listener.local_addr()?, codec);
        input.insert(0, "reconnect".into());
        set(&mut input, "--max-attempts", "2");
        let legacy = preview(&directory, &input)?;
        set(&mut input, "--keepalive-method", "options");
        let explicit = preview(&directory, &input)?;
        assert_eq!(text(&legacy, "approval")?, text(&explicit, "approval")?);
        set(&mut input, "--keepalive-method", "get-parameter");
        let selected = preview(&directory, &input)?;
        assert_ne!(text(&legacy, "approval")?, text(&selected, "approval")?);
        // The complete preview contains every child plan, not just an unbound outer label.
        let rendered = good(run(&directory, &input)?)?;
        assert_eq!(rendered.matches("\"keepalive_method\":\"GET_PARAMETER\"").count(), 2);
        assert!(!directory.0.join("capture.attempt-0001").exists());
        no_connection(&listener)?;
    }
    Ok(())
}
