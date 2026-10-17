#![forbid(unsafe_code)]
#![feature(tcp_linger)]
#![cfg(target_os = "linux")]
//! Actual abortive TCP closes exercise the native HEVC capture/publication pipeline.
//! The fixture waits for the client's first keepalive, not an arbitrary sleep, so
//! earlier source events have drained before the reset. No fixture synthesizes EOF.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;

type Test<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const OUTPUT_LIMIT: u64 = 2 * 1024 * 1024;
const SENSOR: &str = "sensor:interrupted-hevc";
const STREAM: &str = "stream:interrupted-hevc";
const SITE: &str = "site:interrupted-hevc";

struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        for ordinal in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-hevc-interruption-{}-{ordinal}", std::process::id()
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
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
}
fn binary(name: &str) -> Test<OsString> {
    let (variable, compiled) = match name {
        "capture" => ("FSS_CAPTURE_RTSP_BIN", option_env!("CARGO_BIN_EXE_fss-capture-rtsp")),
        "import" => ("FSS_IMPORT_RTSP_BIN", option_env!("CARGO_BIN_EXE_fss-import-rtsp")),
        "file" => ("FSS_FILE_BIN", option_env!("CARGO_BIN_EXE_fss-file")),
        _ => return Err("unknown fixture binary".into()),
    };
    std::env::var_os(variable).or_else(|| compiled.map(OsString::from))
        .ok_or_else(|| format!("missing {variable}").into())
}
fn run(directory: &Directory, name: &str, args: &[OsString]) -> Test<Output> {
    let mut outputs = None;
    for ordinal in 0..100 {
        let path = directory.0.join(format!("process-{ordinal}"));
        match fs::create_dir(&path) {
            Ok(()) => { outputs = Some(path); break; }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    let outputs = outputs.ok_or("output reservation exhausted")?;
    let make = |name: &str| -> io::Result<File> {
        OpenOptions::new().write(true).create_new(true).open(outputs.join(name))
    };
    let mut process = Process(Command::new(binary(name)?)
        .args(args).stdin(Stdio::null())
        .stdout(Stdio::from(make("stdout")?))
        .stderr(Stdio::from(make("stderr")?)).spawn()?);
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if Instant::now() >= deadline
            || fs::metadata(outputs.join("stdout"))?.len() > OUTPUT_LIMIT
            || fs::metadata(outputs.join("stderr"))?.len() > OUTPUT_LIMIT {
            return Err("fixture process exceeded time/output bounds".into());
        }
        if let Some(status) = process.0.try_wait()? { break status; }
        thread::sleep(Duration::from_millis(2));
    };
    let read = |name: &str| -> Test<Vec<u8>> {
        let mut bytes = Vec::new();
        File::open(outputs.join(name))?.take(OUTPUT_LIMIT + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > OUTPUT_LIMIT { return Err("oversized process output".into()); }
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
    field(value, key)?.integer().ok_or_else(|| format!("{key} is not integer").into())
}
fn flag(value: &Value, key: &str) -> Test<bool> {
    field(value, key)?.boolean().ok_or_else(|| format!("{key} is not boolean").into())
}
fn good(output: Output) -> Test<String> {
    assert!(output.status.success(), "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    Ok(String::from_utf8(output.stdout)?)
}
fn digest(label: &str) -> String { ContentDigest::sha256(label.as_bytes()).to_text() }
fn set(args: &mut Vec<OsString>, key: &str, value: &str) {
    match args.iter().position(|argument| argument == key) {
        Some(at) => args[at + 1] = value.into(),
        None => args.extend([key.into(), value.into()]),
    }
}
fn args(directory: &Directory, address: SocketAddr) -> Vec<OsString> {
    [
        ("--root", directory.0.join("capture").display().to_string()),
        ("--pins", directory.0.join("pins").display().to_string()),
        ("--peer", address.to_string()), ("--authority", address.to_string()),
        ("--presentation", "/live/".into()), ("--control-root", "/live".into()),
        ("--sensor-id", SENSOR.into()), ("--stream-id", STREAM.into()),
        ("--generation", "1".into()), ("--ingress", "71".into()), ("--ssrc", "7".into()),
        ("--anchor", digest("interruption anchor")),
        ("--receive-clock", digest("interruption receive clock")),
        ("--timing-evidence", digest("owner fixed cadence")),
        ("--journal-id", digest("interruption journal")),
        ("--frame-duration-ticks", "18000".into()), ("--stop-after-pictures", "8".into()),
        ("--owner-authorized", "yes".into()), ("--plaintext", "yes".into()),
        ("--retain-originals", "yes".into()), ("--timeout-ms", "30000".into()),
        ("--drain-timeout-ms", "5000".into()), ("--response-timeout-ms", "10000".into()),
        ("--max-report-bytes", "262144".into()), ("--max-window-pictures", "16".into()),
        ("--codec", "hevc".into()), ("--payload-type", "98".into()),
    ].into_iter().flat_map(|(key, value)| [key.into(), value.into()]).collect()
}
fn approve(directory: &Directory, input: &[OsString]) -> Test<Vec<OsString>> {
    let plan = parse(&good(run(directory, "capture", input)?)?)?;
    let mut approved = input.to_vec();
    set(&mut approved, "--approve", text(&plan, "approval")?);
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
        Err(error) => Err(error.into()),
        Ok(_) => Err("unexpected successor connection".into()),
    }
}
fn nals() -> Test<Vec<Vec<u8>>> {
    include_str!("../../../tests/fixtures/media/hevc/remux_main8.nals.hex")
        .lines().filter(|line| !line.trim().is_empty()).map(|line| {
            if !line.is_ascii() || !line.len().is_multiple_of(2) { return Err("invalid HEVC fixture".into()); }
            (0..line.len()).step_by(2).map(|at| {
                u8::from_str_radix(&line[at..at + 2], 16).map_err(Into::into)
            }).collect()
        }).collect()
}
fn framed(sequence: u16, timestamp: u32, nal: &[u8]) -> Test<Vec<u8>> {
    let mut packet = vec![0x80, 98 | 128];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.extend_from_slice(&7_u32.to_be_bytes());
    packet.extend_from_slice(nal);
    let mut wire = vec![b'$', 0];
    wire.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
    wire.extend_from_slice(&packet);
    Ok(wire)
}
fn request(peer: &mut TcpStream) -> Test<Option<(String, u32)>> {
    let mut bytes = Vec::new();
    while bytes.len() < 8192 {
        let mut byte = [0];
        match peer.read(&mut byte) {
            Ok(0) if bytes.is_empty() => return Ok(None),
            Ok(0) => return Err("partial control request".into()),
            Ok(_) => bytes.push(byte[0]),
            Err(error) if bytes.is_empty() && matches!(error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted) => return Ok(None),
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
    Err("oversized control request".into())
}
fn response(peer: &mut TcpStream, cseq: u32, headers: &str, body: &str) -> Test {
    peer.write_all(format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}", body.len()).as_bytes())?;
    Ok(())
}
#[derive(Clone, Copy)]
enum End { Reset, ProtocolFault }
fn serve(listener: &TcpListener, count: usize, end: End) -> Test {
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
    let description = concat!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=interruption\r\nt=0 0\r\na=control:*\r\n",
        "m=video 0 RTP/AVP 98\r\na=rtpmap:98 H265/90000\r\n",
        "a=fmtp:98 sprop-vps=QAEMAf//AWAAAAMAkAAAAwAAAwAeugJA;",
        "sprop-sps=QgEBAWAAAAMAkAAAAwAAAwAeoCCDHVZbpKTC8BaAgAAAAwCAAAADAoQ=;",
        "sprop-pps=RAHAc8CJ\r\na=control:trackID=0\r\n"
    );
    response(&mut peer, cseq, "Content-Type: application/sdp\r\n", description)?;
    let (method, cseq) = request(&mut peer)?.ok_or("missing SETUP")?;
    assert_eq!(method, "SETUP");
    response(&mut peer, cseq, "Session: fixture;timeout=4\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n", "")?;
    let (method, cseq) = request(&mut peer)?.ok_or("missing PLAY")?;
    assert_eq!(method, "PLAY");
    response(&mut peer, cseq, "Session: fixture\r\n", "")?;
    let nals = nals()?;
    assert_eq!(nals.iter().take(6).map(|n| (n[0] >> 1) & 63).collect::<Vec<_>>(), [32, 33, 34, 20, 1, 32]);
    if count != 0 { peer.write_all(&framed(0, 0, &nals[0])?)?; }
    for (index, (nal, timestamp)) in nals.iter().zip([0, 0, 0, 0, 18_000, 36_000]).take(count).enumerate() {
        peer.write_all(&framed(u16::try_from(index + 1)?, timestamp, nal)?)?;
    }
    // The native owner only prepares this request after earlier capture events
    // drained. Receiving its entire header also proves it is no longer a partial write.
    let (method, cseq) = request(&mut peer)?.ok_or("expected keepalive after source drain")?;
    assert!(matches!(method.as_str(), "OPTIONS" | "GET_PARAMETER"));
    match end {
        End::Reset => {
            peer.set_linger(Some(Duration::ZERO))?;
            drop(peer); // real TCP RST, not shutdown(Write)/EOF
        }
        End::ProtocolFault => {
            // Wrong CSeq is a native control fault, not a transport error eligible for sealing.
            response(&mut peer, cseq + 1, "Session: fixture\r\n", "")?;
            assert!(request(&mut peer)?.is_none());
        }
    }
    Ok(())
}
fn capture(directory: &Directory, input: &[OsString], listener: &TcpListener, count: usize, end: End) -> Test<Output> {
    thread::scope(|scope| {
        let server = scope.spawn(|| serve(listener, count, end));
        let output = run(directory, "capture", input);
        let served = server.join().map_err(|_| "camera fixture panicked")?;
        let output = output?;
        if let Err(error) = served {
            return Err(format!("{error}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)).into());
        }
        assert!(!output.status.success(), "an interrupted attempt must never succeed");
        no_connection(listener)?;
        Ok(output)
    })
}
fn rows(output: &Output) -> Test<Vec<Value>> {
    std::str::from_utf8(&output.stdout)?.lines().map(|line| parse(line).map_err(Into::into)).collect()
}
fn details<'a>(rows: &'a [Value], kind: &str) -> Test<Vec<&'a Value>> {
    rows.iter().filter(|row| text(row, "kind").ok() == Some(kind))
        .map(|row| field(row, "detail")).collect()
}
fn unique<'a>(rows: &'a [Value], kind: &str) -> Test<&'a Value> {
    let found = details(rows, kind)?;
    assert_eq!(found.len(), 1, "expected one {kind}; events={:?}",
        rows.iter().filter_map(|row| text(row, "kind").ok()).collect::<Vec<_>>());
    Ok(found[0])
}
fn assert_preserved(rows: &[Value], pictures: i128) -> Test {
    let interruption = unique(rows, "recording_interrupted")?;
    assert_eq!(text(interruption, "error_kind")?, "ConnectionReset");
    assert_eq!(text(interruption, "operation")?, "read");
    assert_eq!(number(interruption, "collected_pictures")?, pictures);
    assert!(!flag(interruption, "source_eof_asserted")?);
    assert!(!flag(interruption, "capture_complete")?);
    let terminal = unique(rows, "terminal")?;
    assert_eq!(text(terminal, "error_id")?, "ERR-CAPTURE-RTSP-SOURCE-001");
    for key in ["complete", "peer_eof", "input_end_observed", "capture_continuity", "coverage_certified"] {
        assert!(!flag(terminal, key)?, "{key}");
    }
    assert_eq!(number(terminal, "collected_pictures")?, pictures);
    assert_eq!(number(terminal, "durable_pictures")?, pictures);
    assert_eq!(number(terminal, "durable_windows")?, 1);
    assert_eq!(number(terminal, "indexed_windows")?, 1);
    assert_eq!(number(terminal, "unsealed_pictures")?, 0);
    assert!(number(terminal, "released_active_rtp_bytes")? > 0);
    assert!(flag(terminal, "unsettled_request")?);
    assert!(flag(terminal, "unpublished_receiver_state")?);
    assert_eq!(details(rows, "window_durable")?.len(), 1);
    assert_eq!(details(rows, "catalog_published")?.len(), 1);
    Ok(())
}
fn cold_decode(directory: &Directory, rows: &[Value], archive: &Path, pictures: i128) -> Test {
    let window = unique(rows, "window_durable")?;
    let deployment = directory.0.join("deployment");
    let mut input: Vec<OsString> = [
        ("--archive", archive.display().to_string()),
        ("--root", deployment.display().to_string()), ("--site", SITE.into()),
        ("--window-slot", text(window, "slot")?.into()), ("--window-root", text(window, "root")?.into()),
        ("--codec", "hevc".into()), ("--sensor-id", SENSOR.into()), ("--stream-id", STREAM.into()),
        ("--generation", "1".into()), ("--anchor", digest("interruption anchor")),
        ("--receive-clock", digest("interruption receive clock")), ("--receive-time-ns", "5000000000".into()),
        ("--owner-authorized", "yes".into()), ("--read-originals", "yes".into()), ("--retain-originals", "yes".into()),
    ].into_iter().flat_map(|(key, value)| [key.into(), value.into()]).collect();
    let preview = parse(&good(run(directory, "import", &input)?)?)?;
    assert!(!deployment.exists());
    set(&mut input, "--approve", text(&preview, "approval_digest")?);
    let imported = parse(&good(run(directory, "import", &input)?)?)?;
    assert_eq!(number(&imported, "frames")?, pictures);
    let effects = fs::read(deployment.join("effects/journal.fssj"))?;
    fs::rename(archive, directory.0.join("offline-capture"))?;
    // Retained HEVC segments are individual access units, not archive windows.
    // Select the entire imported prefix so a two-picture archive must cold-decode
    // both pictures rather than merely prove its leading IDR is readable.
    let segment_count = pictures.to_string();
    let decode: Vec<OsString> = [
        "decode", "--root", deployment.to_str().ok_or("deployment path")?, "--site", SITE,
        "--import-id", text(&imported, "import_identity")?, "--segment", "0", "--segment-count", &segment_count,
        "--interpretation", "ycbcr", "--work-units", "1000000000",
    ].into_iter().map(OsString::from).collect();
    let decoded = good(run(directory, "file", &decode)?)?;
    assert!(decoded.lines().any(|line| line == "decode_complete=true"), "{decoded}");
    assert_eq!(decoded.lines().filter(|line| line.starts_with("frame_luma_sha256=")).count(), usize::try_from(pictures)?, "{decoded}");
    assert_eq!(fs::read(deployment.join("effects/journal.fssj"))?, effects);
    Ok(())
}

#[test]
fn abrupt_reset_preserves_and_cold_decodes_only_the_source_closed_hevc_prefix() -> Test {
    for (count, pictures) in [(5, 1), (6, 2)] {
        let directory = Directory::new()?;
        let listener = listener()?;
        let input = approve(&directory, &args(&directory, listener.local_addr()?))?;
        let output = capture(&directory, &input, &listener, count, End::Reset)?;
        let rows = rows(&output)?;
        assert_preserved(&rows, pictures)?;
        cold_decode(&directory, &rows, &directory.0.join("capture"), pictures)?;
    }
    Ok(())
}
#[test]
fn reset_cannot_close_an_unverified_picture_or_create_an_empty_recording() -> Test {
    for count in [0, 4] {
        let directory = Directory::new()?;
        let listener = listener()?;
        let input = approve(&directory, &args(&directory, listener.local_addr()?))?;
        let output = capture(&directory, &input, &listener, count, End::Reset)?;
        let rows = rows(&output)?;
        for kind in ["recording_interrupted", "window_durable", "catalog_published"] {
            assert!(details(&rows, kind)?.is_empty(), "{kind}");
        }
        let terminal = unique(&rows, "terminal")?;
        assert_eq!(text(terminal, "error_id")?, "ERR-CAPTURE-RTSP-SOURCE-001");
        assert_eq!(number(terminal, "durable_pictures")?, 0);
        assert!(!flag(terminal, "complete")?);
        assert!(!flag(terminal, "peer_eof")?);
    }
    Ok(())
}
#[test]
fn a_control_protocol_fault_never_uses_the_read_failure_preservation_path() -> Test {
    let directory = Directory::new()?;
    let listener = listener()?;
    let input = approve(&directory, &args(&directory, listener.local_addr()?))?;
    let output = capture(&directory, &input, &listener, 5, End::ProtocolFault)?;
    let rows = rows(&output)?;
    assert!(details(&rows, "recording_interrupted")?.is_empty());
    assert!(details(&rows, "window_durable")?.is_empty());
    assert_eq!(number(unique(&rows, "terminal")?, "collected_pictures")?, 1);
    Ok(())
}
#[test]
fn an_interrupted_timed_campaign_does_not_retry_or_report_success_after_preservation() -> Test {
    let directory = Directory::new()?;
    let listener = listener()?;
    let mut input = args(&directory, listener.local_addr()?);
    input.insert(0, "reconnect".into());
    set(&mut input, "--max-attempts", "2");
    set(&mut input, "--retry-delay-ms", "1");
    set(&mut input, "--capture-duration-ms", "10000");
    set(&mut input, "--continue-after-success", "yes");
    let input = approve(&directory, &input)?;
    let output = capture(&directory, &input, &listener, 5, End::Reset)?;
    let rows = rows(&output)?;
    assert_preserved(&rows, 1)?;
    assert!(!flag(unique(&rows, "attempt_finished")?, "retrying")?);
    assert!(!flag(unique(&rows, "reconnect_terminal")?, "complete")?);
    assert!(directory.0.join("capture.attempt-0001").is_dir());
    assert!(!directory.0.join("capture.attempt-0002").exists());
    assert!(!directory.0.join("pins.attempt-0002").exists());
    Ok(())
}
