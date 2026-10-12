#![forbid(unsafe_code)]
//! Real native-process reconnects against an owned loopback camera. No mocked capture owner.

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
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
                "fss-rtsp-reconnect-{}-{label}-{index}", std::process::id()
            ));
            match fs::create_dir(&path) {
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
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
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
    let mut child = Command::new(binary).args(args).stdin(Stdio::null())
        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
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
                break Err(io::Error::other("native reconnect process exceeded its test bound"));
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
        Ok(Output { status: status?, stdout, stderr })
    })
}
fn field<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    value.object().and_then(|fields| fields.get(key)).ok_or_else(|| format!("missing {key}").into())
}
fn text<'a>(value: &'a Value, key: &str) -> Test<&'a str> {
    field(value, key)?.text().ok_or_else(|| format!("nontext {key}").into())
}
fn number(value: &Value, key: &str) -> Test<i128> {
    field(value, key)?.integer().ok_or_else(|| format!("noninteger {key}").into())
}
fn flag(value: &Value, key: &str) -> Test<bool> {
    field(value, key)?.boolean().ok_or_else(|| format!("nonboolean {key}").into())
}
fn args(directory: &Directory, peer: SocketAddr, codec: &str) -> Vec<OsString> {
    let digest = |label: &str| ContentDigest::sha256(label.as_bytes()).to_text();
    let mut args = vec![OsString::from("reconnect")];
    for (key, value) in [
        ("--root", directory.0.join("capture").display().to_string()),
        ("--pins", directory.0.join("pins").display().to_string()),
        ("--peer", peer.to_string()), ("--authority", peer.to_string()),
        ("--presentation", "/live/".into()), ("--control-root", "/live".into()),
        ("--sensor-id", "sensor:reconnect".into()), ("--stream-id", "stream:reconnect".into()),
        ("--generation", "7".into()), ("--ingress", "71".into()), ("--ssrc", "7".into()),
        ("--anchor", digest("owner anchor")), ("--receive-clock", digest("owner receive")),
        ("--timing-evidence", digest("25fps cadence")), ("--journal-id", digest("pin epoch")),
        ("--frame-duration-ticks", "3600".into()), ("--stop-after-pictures", "2".into()),
        ("--owner-authorized", "yes".into()), ("--plaintext", "yes".into()),
        ("--retain-originals", "yes".into()), ("--codec", codec.into()),
        ("--timeout-ms", "5000".into()), ("--drain-timeout-ms", "5000".into()),
        ("--connect-timeout-ms", "1000".into()), ("--response-timeout-ms", "1000".into()),
        ("--max-report-bytes", "131072".into()), ("--max-attempts", "3".into()),
        ("--retry-delay-ms", "5".into()), ("--retry-max-delay-ms", "10".into()),
    ] {
        args.extend([key.into(), value.into()]);
    }
    args
}
fn preview(args: &[OsString]) -> Test<Value> {
    let out = run(args)?;
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
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
                if kind == "attempt_started" { assert!(!native_open); }
                if kind == "attempt_finished" { assert!(!native_open); }
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
                if kind == "terminal" { native_open = false; }
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

#[derive(Clone, Copy)]
enum Behavior { Eof, Target, Authentication, Malformed }
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
            let method = wire.split_ascii_whitespace().next().ok_or("method")?.to_owned();
            let cseq = wire.split("\r\n").find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("cseq").then_some(value.trim())
            }).ok_or("CSeq")?.parse()?;
            return Ok(Some((method, cseq)));
        }
    }
    Err("request budget exhausted".into())
}
fn response(peer: &mut TcpStream, cseq: u32, headers: &str, body: &str) -> Test {
    peer.write_all(format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}", body.len()).as_bytes())?;
    Ok(())
}
fn video(pictures: usize) -> Test<Vec<u8>> {
    let bytes: &'static [u8] = include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264");
    let mut starts = Vec::new();
    let mut at = 0;
    while at + 3 <= bytes.len() {
        let prefix = if bytes.get(at..at + 4) == Some(&[0, 0, 0, 1]) { 4 }
            else if bytes[at..at + 3] == [0, 0, 1] { 3 } else { 0 };
        if prefix == 0 { at += 1; } else { starts.push((at, at + prefix)); at += prefix; }
    }
    let mut out = Vec::new();
    let mut sequence = 1_u16;
    let mut count = 0;
    for (index, (_, start)) in starts.iter().enumerate() {
        if count == pictures { break; }
        let mut end = starts.get(index + 1).map_or(bytes.len(), |next| next.0);
        while end > *start && bytes[end - 1] == 0 { end -= 1; }
        let nal = &bytes[*start..end];
        let kind = nal.first().ok_or("empty fixture NAL")? & 31;
        if !matches!(kind, 1 | 5 | 6 | 7 | 8) { continue; }
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
fn serve_one(listener: &TcpListener, behavior: Behavior) -> Test<Vec<String>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut peer = loop {
        match listener.accept() {
            Ok((peer, _)) => break peer,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
            Err(e) => return Err(e.into()),
        }
    };
    peer.set_read_timeout(Some(Duration::from_secs(10)))?;
    peer.set_write_timeout(Some(Duration::from_secs(10)))?;
    peer.set_nodelay(true)?;
    let mut methods = Vec::new();
    let (method, cseq) = request(&mut peer)?.ok_or("missing DESCRIBE")?;
    assert_eq!(method, "DESCRIBE"); methods.push(method);
    if matches!(behavior, Behavior::Authentication) {
        peer.write_all(format!("RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\nWWW-Authenticate: Digest realm=\"RECONNECT_SECRET_REALM\", nonce=\"RECONNECT_SECRET_NONCE\", qop=\"auth\"\r\nContent-Length: 0\r\n\r\n").as_bytes())?;
        peer.shutdown(Shutdown::Write)?;
        assert!(request(&mut peer)?.is_none());
        return Ok(methods);
    }
    response(&mut peer, cseq, "Content-Type: application/sdp\r\n", SDP)?;
    let (method, cseq) = request(&mut peer)?.ok_or("missing SETUP")?;
    assert_eq!(method, "SETUP"); methods.push(method);
    response(&mut peer, cseq, "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n", "")?;
    let (method, cseq) = request(&mut peer)?.ok_or("missing PLAY")?;
    assert_eq!(method, "PLAY"); methods.push(method);
    response(&mut peer, cseq, "Session: fixture\r\n", "")?;
    peer.write_all(&video(if matches!(behavior, Behavior::Target) { 2 } else { 1 })?)?;
    if matches!(behavior, Behavior::Eof) { peer.shutdown(Shutdown::Write)?; }
    if matches!(behavior, Behavior::Malformed) { peer.write_all(&[b'$', 0, 0, 4, 0x80, 96, 0, 9])?; }
    for _ in 0..16 {
        let Some((method, cseq)) = request(&mut peer)? else { return Ok(methods); };
        assert!(matches!(method.as_str(), "OPTIONS" | "GET_PARAMETER" | "TEARDOWN"));
        methods.push(method);
        response(&mut peer, cseq, "Session: fixture\r\n", "")?;
    }
    Err("server request budget exhausted".into())
}
fn captured(listener: TcpListener, args: &[OsString], behaviors: &[Behavior]) -> Test<(Output, Vec<Vec<String>>)> {
    thread::scope(|scope| {
        let server = scope.spawn(move || behaviors.iter().map(|behavior| serve_one(&listener, *behavior)).collect::<Test<Vec<_>>>());
        let output = run(args);
        let transcript = server.join().map_err(|_| "camera thread panicked")?;
        match (output, transcript) {
            (Ok(output), Ok(transcript)) => Ok((output, transcript)),
            (Ok(output), Err(error)) => Err(format!("{error}; stdout={} stderr={}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)).into()),
            (Err(error), _) => Err(error),
        }
    })
}

#[test]
fn reconnect_preview_is_pure_and_child_approval_does_not_authorize_effects() -> Test {
    for codec in ["avc", "hevc"] {
        let directory = Directory::new(codec)?;
        let listener = listener()?;
        let args = args(&directory, listener.local_addr()?, codec);
        let plan = preview(&args)?;
        let children = field(&plan, "attempts")?.array().ok_or("attempt array")?;
        assert_eq!(children.len(), 3);
        assert_ne!(text(&children[0], "receive_clock")?, text(&children[1], "receive_clock")?);
        assert_ne!(text(&children[0], "archive_namespace")?, text(&children[1], "archive_namespace")?);
        assert!(fs::read_dir(&directory.0)?.next().is_none());
        let mut wrong = args.clone();
        wrong.extend(["--approve".into(), text(&children[0], "approval")?.into()]);
        let result = run(&wrong)?;
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(fs::read_dir(&directory.0)?.next().is_none());
        assert!(matches!(listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
    }
    Ok(())
}

#[test]
fn real_eof_reconnects_with_new_generation_and_preserves_both_durable_archives() -> Test {
    let directory = Directory::new("eof")?;
    let listener = listener()?;
    let args = approved(&args(&directory, listener.local_addr()?, "avc"))?;
    let (output, transcript) = captured(listener, &args, &[Behavior::Eof, Behavior::Target])?;
    assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert_eq!(transcript.len(), 2);
    for methods in transcript { assert_eq!(&methods[..3], &["DESCRIBE", "SETUP", "PLAY"]); }
    let rows = rows(&output)?;
    let attempts = details(&rows, CONTROL, "attempt_started")?;
    assert_eq!(attempts.len(), 2);
    assert_eq!(number(attempts[0], "generation")?, 7);
    assert_eq!(number(attempts[1], "generation")?, 8);
    let ended = details(&rows, CONTROL, "attempt_finished")?;
    assert_eq!(text(ended[0], "retry_reason")?, "source_ended");
    assert!(flag(ended[0], "retrying")?);
    assert!(!flag(ended[0], "recovery_required")?);
    let windows = details(&rows, NATIVE, "window_durable")?;
    assert_eq!(windows.len(), 2);
    assert_ne!(text(windows[0], "archive_namespace")?, text(windows[1], "archive_namespace")?);
    assert_eq!(number(windows[0], "pictures")?, 1);
    assert_eq!(number(windows[1], "pictures")?, 2);
    let terminal = details(&rows, CONTROL, "reconnect_terminal")?;
    assert_eq!(terminal.len(), 1);
    assert!(flag(terminal[0], "complete")?);
    assert_eq!(number(terminal[0], "durable_pictures_all_attempts")?, 3);
    assert!(!flag(terminal[0], "continuity_across_attempts")?);
    for index in 1..=2 {
        assert!(directory.attempt("capture", index).is_dir());
        assert!(directory.attempt("pins", index).join("pins.journal").is_file());
    }
    assert!(!directory.attempt("capture", 3).exists());
    Ok(())
}

#[test]
fn unavailable_avc_and_hevc_peers_exhaust_exactly_the_approved_attempts() -> Test {
    for codec in ["avc", "hevc"] {
        let directory = Directory::new(&format!("refused-{codec}"))?;
        let reserved = listener()?;
        let peer = reserved.local_addr()?;
        let args = approved(&args(&directory, peer, codec))?;
        drop(reserved);
        let output = run(&args)?;
        assert!(!output.status.success());
        let rows = rows(&output)?;
        assert_eq!(details(&rows, CONTROL, "attempt_started")?.len(), 3, "{codec}");
        assert_eq!(details(&rows, CONTROL, "backoff")?.len(), 2);
        let terminal = details(&rows, CONTROL, "reconnect_terminal")?;
        assert!(flag(terminal[0], "attempt_limit_reached")?);
        assert!(!flag(terminal[0], "complete")?);
        assert!(!directory.attempt("capture", 4).exists());
    }
    Ok(())
}

#[test]
fn authentication_at_eof_and_malformed_rtp_never_trigger_reconnection() -> Test {
    for (codec, behavior) in [
        ("avc", Behavior::Authentication), ("hevc", Behavior::Authentication),
        ("avc", Behavior::Malformed),
    ] {
        let directory = Directory::new("fatal")?;
        let listener = listener()?;
        let args = approved(&args(&directory, listener.local_addr()?, codec))?;
        let (output, _) = captured(listener, &args, &[behavior])?;
        assert!(!output.status.success());
        let report = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        assert!(!report.contains("RECONNECT_SECRET_REALM"));
        assert!(!report.contains("RECONNECT_SECRET_NONCE"));
        let rows = rows(&output)?;
        assert_eq!(details(&rows, CONTROL, "attempt_started")?.len(), 1);
        assert!(details(&rows, CONTROL, "backoff")?.is_empty());
        assert!(!directory.attempt("capture", 2).exists());
    }
    Ok(())
}

#[test]
fn existing_attempt_custody_is_not_overwritten_or_skipped_to_another_attempt() -> Test {
    let directory = Directory::new("existing")?;
    let listener = listener()?;
    let args = approved(&args(&directory, listener.local_addr()?, "avc"))?;
    let existing = directory.attempt("capture", 1);
    fs::create_dir(&existing)?;
    fs::write(existing.join("preserved"), b"prior owner custody")?;
    let output = run(&args)?;
    assert!(!output.status.success());
    assert_eq!(fs::read(existing.join("preserved"))?, b"prior owner custody");
    assert!(!directory.attempt("capture", 2).exists());
    assert!(matches!(listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}
