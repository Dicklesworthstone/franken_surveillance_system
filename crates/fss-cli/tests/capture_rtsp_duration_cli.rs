#![forbid(unsafe_code)]
//! Process-level duration contracts. Cameras keep their write side open until capture
//! retires the socket; a timer must never manufacture source EOF or archive durability.

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
    fn new() -> Test<Self> {
        for ordinal in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-rtsp-duration-{}-{ordinal}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("duration fixture directory reservation exhausted".into())
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
    let binary = std::env::var_os("FSS_CAPTURE_RTSP_BIN")
        .or_else(|| option_env!("CARGO_BIN_EXE_fss-capture-rtsp").map(OsString::from))
        .ok_or("missing native capture binary")?;
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
    let outputs = outputs.ok_or("process output reservation exhausted")?;
    let make = |name: &str| -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(outputs.join(name))
    };
    let mut process = Process(
        Command::new(binary)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(make("stdout")?))
            .stderr(Stdio::from(make("stderr")?))
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if Instant::now() >= deadline
            || fs::metadata(outputs.join("stdout"))?.len() > OUTPUT_LIMIT
            || fs::metadata(outputs.join("stderr"))?.len() > OUTPUT_LIMIT
        {
            return Err("capture fixture exceeded process time/output bound".into());
        }
        if let Some(status) = process.0.try_wait()? {
            break status;
        }
        thread::sleep(Duration::from_millis(2));
    };
    let read = |name: &str| -> Test<Vec<u8>> {
        let mut bytes = Vec::new();
        File::open(outputs.join(name))?
            .take(OUTPUT_LIMIT + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > OUTPUT_LIMIT {
            return Err("capture output exceeded bound".into());
        }
        Ok(bytes)
    };
    Ok(Output {
        status,
        stdout: read("stdout")?,
        stderr: read("stderr")?,
    })
}

fn field<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|object| object.get(key))
        .ok_or_else(|| format!("missing {key}").into())
}
fn text<'a>(value: &'a Value, key: &str) -> Test<&'a str> {
    field(value, key)?
        .text()
        .ok_or_else(|| format!("{key} is not text").into())
}
fn number(value: &Value, key: &str) -> Test<i128> {
    field(value, key)?
        .integer()
        .ok_or_else(|| format!("{key} is not an integer").into())
}
fn flag(value: &Value, key: &str) -> Test<bool> {
    field(value, key)?
        .boolean()
        .ok_or_else(|| format!("{key} is not boolean").into())
}
fn set(args: &mut Vec<OsString>, key: &str, value: &str) {
    match args.iter().position(|argument| argument == key) {
        Some(at) => args[at + 1] = value.into(),
        None => args.extend([key.into(), value.into()]),
    }
}
fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
fn rows(output: &Output) -> Test<Vec<Value>> {
    std::str::from_utf8(&output.stdout)?
        .lines()
        .map(|line| parse(line).map_err(Into::into))
        .collect()
}
fn details<'a>(rows: &'a [Value], kind: &str) -> Test<Vec<&'a Value>> {
    rows.iter()
        .filter(|row| text(row, "kind").ok() == Some(kind))
        .map(|row| field(row, "detail"))
        .collect()
}
fn unique<'a>(rows: &'a [Value], kind: &str) -> Test<&'a Value> {
    let found = details(rows, kind)?;
    assert_eq!(found.len(), 1, "expected exactly one {kind}");
    Ok(found[0])
}

#[derive(Clone, Copy)]
enum Codec {
    Avc,
    Hevc,
}
impl Codec {
    fn name(self) -> &'static str {
        match self {
            Self::Avc => "avc",
            Self::Hevc => "hevc",
        }
    }
    fn payload_type(self) -> u8 {
        match self {
            Self::Avc => 96,
            Self::Hevc => 98,
        }
    }
    fn cadence(self) -> u32 {
        match self {
            Self::Avc => 3600,
            Self::Hevc => 18_000,
        }
    }
    fn description(self) -> String {
        let mapping = match self {
            Self::Avc => concat!(
                "a=rtpmap:96 H264/90000\r\n",
                "a=fmtp:96 packetization-mode=1;sprop-parameter-sets=",
                "Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\n"
            ),
            Self::Hevc => concat!(
                "a=rtpmap:98 H265/90000\r\n",
                "a=fmtp:98 sprop-vps=QAEMAf//AWAAAAMAkAAAAwAAAwAeugJA;",
                "sprop-sps=QgEBAWAAAAMAkAAAAwAAAwAeoCCDHVZbpKTC8BaAgAAAAwCAAAADAoQ=;",
                "sprop-pps=RAHAc8CJ\r\n"
            ),
        };
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=duration\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP {}\r\n{mapping}a=control:trackID=0\r\n",
            self.payload_type()
        )
    }
}

fn args(directory: &Directory, address: SocketAddr, codec: Codec) -> Vec<OsString> {
    let digest = |label: &str| ContentDigest::sha256(label.as_bytes()).to_text();
    let mut out = vec![OsString::from("reconnect")];
    out.extend(
        [
            ("--root", directory.0.join("capture").display().to_string()),
            ("--pins", directory.0.join("pins").display().to_string()),
            ("--peer", address.to_string()),
            ("--authority", address.to_string()),
            ("--presentation", "/live/".into()),
            ("--control-root", "/live".into()),
            ("--sensor-id", "sensor:duration-fixture".into()),
            ("--stream-id", "stream:duration-fixture".into()),
            ("--generation", "1".into()),
            ("--ingress", "71".into()),
            ("--ssrc", "7".into()),
            ("--anchor", digest("duration anchor")),
            ("--receive-clock", digest("duration receive clock")),
            ("--timing-evidence", digest("owner fixed cadence")),
            ("--journal-id", digest("duration journal")),
            ("--frame-duration-ticks", codec.cadence().to_string()),
            ("--stop-after-pictures", "8".into()),
            ("--owner-authorized", "yes".into()),
            ("--plaintext", "yes".into()),
            ("--retain-originals", "yes".into()),
            ("--timeout-ms", "30000".into()),
            ("--drain-timeout-ms", "5000".into()),
            ("--response-timeout-ms", "10000".into()),
            ("--max-report-bytes", "262144".into()),
            ("--max-window-pictures", "16".into()),
            ("--codec", codec.name().into()),
            ("--payload-type", codec.payload_type().to_string()),
            ("--capture-duration-ms", "500".into()),
            ("--max-attempts", "1".into()),
            ("--retry-delay-ms", "1".into()),
            ("--retry-max-delay-ms", "1".into()),
        ]
        .into_iter()
        .flat_map(|(key, value)| [key.into(), value.into()]),
    );
    out
}
fn approve(directory: &Directory, args: &[OsString]) -> Test<Vec<OsString>> {
    let output = run(directory, args)?;
    assert_success(&output);
    let plan = parse(std::str::from_utf8(&output.stdout)?)?;
    let mut approved = args.to_vec();
    approved.extend([OsString::from("--approve"), text(&plan, "approval")?.into()]);
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
        Ok(_) => Err("unexpected additional camera connection".into()),
        Err(error) => Err(error.into()),
    }
}

fn framed(codec: Codec, sequence: u16, timestamp: u32, nal: &[u8]) -> Test<Vec<u8>> {
    let mut packet = vec![0x80, codec.payload_type() | 128];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.extend_from_slice(&7_u32.to_be_bytes());
    packet.extend_from_slice(nal);
    let mut wire = vec![b'$', 0];
    wire.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
    wire.extend_from_slice(&packet);
    Ok(wire)
}
fn prefix(codec: Codec) -> Test<Vec<Vec<u8>>> {
    match codec {
        Codec::Avc => {
            let bytes = include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264");
            let mut starts = Vec::new();
            let mut at = 0;
            while at + 3 <= bytes.len() {
                let width = if bytes.get(at..at + 4) == Some(&[0, 0, 0, 1]) {
                    4
                } else if bytes[at..at + 3] == [0, 0, 1] {
                    3
                } else {
                    0
                };
                if width != 0 {
                    starts.push((at, at + width));
                    at += width;
                } else {
                    at += 1;
                }
            }
            let mut nals = Vec::new();
            for (index, (_, start)) in starts.iter().enumerate() {
                let mut end = starts.get(index + 1).map_or(bytes.len(), |(at, _)| *at);
                while end > *start && bytes[end - 1] == 0 {
                    end -= 1;
                }
                if *start < end {
                    nals.push(&bytes[*start..end]);
                }
            }
            let mut out = vec![framed(codec, 0, 9000, nals.first().ok_or("missing AVC")?)?];
            for nal in nals {
                let kind = nal[0] & 31;
                if matches!(kind, 1 | 5 | 6 | 7 | 8) {
                    out.push(framed(codec, u16::try_from(out.len())?, 9000, nal)?);
                }
                if matches!(kind, 1 | 5) {
                    return Ok(out);
                }
            }
            Err("missing AVC picture".into())
        }
        Codec::Hevc => {
            let nals = include_str!("../../../tests/fixtures/media/hevc/remux_main8.nals.hex")
                .lines()
                .filter(|line| !line.trim().is_empty())
                .take(5)
                .map(|line| -> Test<Vec<u8>> {
                    if !line.is_ascii() || !line.len().is_multiple_of(2) {
                        return Err("invalid pinned HEVC fixture".into());
                    }
                    (0..line.len())
                        .step_by(2)
                        .map(|at| u8::from_str_radix(&line[at..at + 2], 16).map_err(Into::into))
                        .collect()
                })
                .collect::<Test<Vec<_>>>()?;
            assert_eq!(
                nals.iter().map(|nal| (nal[0] >> 1) & 63).collect::<Vec<_>>(),
                [32, 33, 34, 20, 1]
            );
            let mut out = vec![framed(codec, 0, 0, &nals[0])?];
            for (index, (nal, timestamp)) in nals.iter().zip([0, 0, 0, 0, 18_000]).enumerate() {
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
            Ok(0) => return Err("partial RTSP request".into()),
            Ok(_) => bytes.push(byte[0]),
            Err(error)
                if bytes.is_empty()
                    && matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                    ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        }
        if bytes.ends_with(b"\r\n\r\n") {
            let text = String::from_utf8(bytes)?;
            let method = text.split_ascii_whitespace().next().ok_or("missing method")?.to_owned();
            let cseq = text
                .split("\r\n")
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("cseq").then_some(value.trim())
                })
                .ok_or("missing CSeq")?
                .parse()?;
            return Ok(Some((method, cseq)));
        }
    }
    Err("oversized RTSP request".into())
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
fn serve(listener: &TcpListener, codec: Codec, silent: bool, delayed_play: bool) -> Test {
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
    response(&mut peer, cseq, "Content-Type: application/sdp\r\n", &codec.description())?;
    let (method, cseq) = request(&mut peer)?.ok_or("missing SETUP")?;
    assert_eq!(method, "SETUP");
    response(
        &mut peer,
        cseq,
        "Session: duration;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n",
        "",
    )?;
    let (method, cseq) = request(&mut peer)?.ok_or("missing PLAY")?;
    assert_eq!(method, "PLAY");
    if delayed_play {
        // Deliberately longer than the approved capture duration, but inside the original
        // response/network deadlines. Negotiation must not spend the PLAY-armed allowance.
        thread::sleep(Duration::from_millis(700));
    }
    response(&mut peer, cseq, "Session: duration\r\n", "")?;
    if !silent {
        for packet in prefix(codec)? {
            peer.write_all(&packet)?;
        }
    }
    // No shutdown(Write): only client retirement ends this otherwise live source.
    for _ in 0..16 {
        let Some((method, cseq)) = request(&mut peer)? else {
            return Ok(());
        };
        assert!(matches!(method.as_str(), "GET_PARAMETER" | "OPTIONS"));
        response(&mut peer, cseq, "Session: duration\r\n", "")?;
    }
    Err("camera control allowance exhausted".into())
}
fn capture(
    directory: &Directory,
    args: &[OsString],
    listener: &TcpListener,
    codec: Codec,
    sessions: usize,
    silent: bool,
    delayed_play: bool,
) -> Test<Output> {
    thread::scope(|scope| {
        let server = scope.spawn(move || -> Test {
            for _ in 0..sessions {
                serve(listener, codec, silent, delayed_play)?;
            }
            Ok(())
        });
        let output = run(directory, args);
        let served = server.join().map_err(|_| "camera fixture panicked")?;
        let output = output?;
        if let Err(error) = served {
            return Err(format!(
                "{error}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(output)
    })
}

#[test]
fn timed_avc_and_hevc_prefixes_are_published_without_source_eof() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        let directory = Directory::new()?;
        let listener = listener()?;
        let approved = approve(&directory, &args(&directory, listener.local_addr()?, codec))?;
        no_connection(&listener)?;
        let output = capture(&directory, &approved, &listener, codec, 1, false, false)?;
        assert_success(&output);
        let rows = rows(&output)?;
        let observed = unique(&rows, "capture_duration_elapsed")?;
        assert!(!flag(observed, "archive_drained")?);
        assert!(!flag(observed, "source_eof_asserted")?);
        let complete = unique(&rows, "capture_duration_complete")?;
        assert!(flag(complete, "archive_drained")?);
        assert!(!flag(complete, "picture_ceiling_reached")?);
        assert!(!flag(complete, "camera_time_asserted")?);
        assert!(!flag(complete, "absence_certifiable")?);
        let terminal = unique(&rows, "terminal")?;
        assert!(flag(terminal, "complete")?);
        assert!(!flag(terminal, "peer_eof")?);
        assert!(!flag(terminal, "input_end_observed")?);
        assert_eq!(number(terminal, "durable_pictures")?, 1);
        assert_eq!(number(terminal, "collected_pictures")?, 1);
        assert_eq!(number(terminal, "durable_windows")?, 1);
        assert_eq!(number(terminal, "indexed_windows")?, 1);
        assert!(!details(&rows, "checkpoint_durable")?.is_empty());
        assert_eq!(details(&rows, "catalog_published")?.len(), 1);
        assert_eq!(text(unique(&rows, "window_durable")?, "codec")?, codec.name());
        assert!(flag(unique(&rows, "reconnect_terminal")?, "complete")?);
        assert!(details(&rows, "recording_stalled")?.is_empty());
        no_connection(&listener)?;
    }
    Ok(())
}

#[test]
fn empty_duration_cannot_succeed_or_open_another_campaign_attempt() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        let directory = Directory::new()?;
        let listener = listener()?;
        let mut input = args(&directory, listener.local_addr()?, codec);
        set(&mut input, "--max-attempts", "3");
        set(&mut input, "--continue-after-success", "yes");
        let approved = approve(&directory, &input)?;
        let output = capture(&directory, &approved, &listener, codec, 1, true, false)?;
        assert!(!output.status.success());
        let rows = rows(&output)?;
        assert!(details(&rows, "capture_duration_complete")?.is_empty());
        let terminal = unique(&rows, "terminal")?;
        assert_eq!(text(terminal, "error_id")?, "ERR-CAPTURE-RTSP-EMPTY-DURATION-001");
        assert_eq!(number(terminal, "durable_pictures")?, 0);
        assert!(!flag(terminal, "peer_eof")?);
        assert_eq!(number(unique(&rows, "reconnect_terminal")?, "attempts_used")?, 1);
        assert!(!directory.0.join("capture.attempt-0002").exists());
        assert!(!directory.0.join("pins.attempt-0002").exists());
        no_connection(&listener)?;
    }
    Ok(())
}

#[test]
fn finite_timed_campaigns_publish_independent_generations() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        let directory = Directory::new()?;
        let listener = listener()?;
        let mut input = args(&directory, listener.local_addr()?, codec);
        set(&mut input, "--max-attempts", "2");
        set(&mut input, "--continue-after-success", "yes");
        let approved = approve(&directory, &input)?;
        let output = capture(&directory, &approved, &listener, codec, 2, false, false)?;
        assert_success(&output);
        let rows = rows(&output)?;
        assert_eq!(details(&rows, "capture_duration_complete")?.len(), 2);
        let attempts = details(&rows, "attempt_started")?;
        assert_eq!(attempts.len(), 2);
        assert_eq!(number(attempts[0], "generation")?, 1);
        assert_eq!(number(attempts[1], "generation")?, 2);
        assert_ne!(text(attempts[0], "root")?, text(attempts[1], "root")?);
        assert_ne!(text(attempts[0], "pins")?, text(attempts[1], "pins")?);
        for attempt in details(&rows, "attempt_finished")? {
            assert!(flag(attempt, "complete")?);
            assert!(flag(attempt, "settled_success")?);
            assert!(!flag(attempt, "picture_ceiling_reached")?);
        }
        let terminal = unique(&rows, "reconnect_terminal")?;
        assert!(flag(terminal, "complete")?);
        assert!(flag(terminal, "attempt_limit_reached")?);
        assert_eq!(number(terminal, "successful_attempts")?, 2);
        assert_eq!(number(terminal, "durable_pictures_all_attempts")?, 2);
        assert!(!flag(terminal, "continuity_across_attempts")?);
        no_connection(&listener)?;
    }
    Ok(())
}

#[test]
fn picture_ceiling_still_finishes_before_a_later_duration() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        let directory = Directory::new()?;
        let listener = listener()?;
        let mut input = args(&directory, listener.local_addr()?, codec);
        set(&mut input, "--stop-after-pictures", "1");
        set(&mut input, "--capture-duration-ms", "10000");
        let approved = approve(&directory, &input)?;
        let output = capture(&directory, &approved, &listener, codec, 1, false, false)?;
        assert_success(&output);
        let rows = rows(&output)?;
        assert!(details(&rows, "capture_duration_elapsed")?.is_empty());
        assert!(details(&rows, "capture_duration_complete")?.is_empty());
        assert!(flag(unique(&rows, "attempt_finished")?, "picture_ceiling_reached")?);
        no_connection(&listener)?;
    }
    Ok(())
}

#[test]
fn an_earlier_progress_stall_remains_a_failure() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        let directory = Directory::new()?;
        let listener = listener()?;
        let mut input = args(&directory, listener.local_addr()?, codec);
        set(&mut input, "--progress-timeout-ms", "50");
        let approved = approve(&directory, &input)?;
        let output = capture(&directory, &approved, &listener, codec, 1, true, false)?;
        assert!(!output.status.success());
        let rows = rows(&output)?;
        assert!(details(&rows, "capture_duration_complete")?.is_empty());
        assert_eq!(details(&rows, "recording_stalled")?.len(), 1);
        assert_eq!(text(unique(&rows, "terminal")?, "error_id")?, "ERR-CAPTURE-RTSP-PROGRESS-001");
        no_connection(&listener)?;
    }
    Ok(())
}

#[test]
fn negotiation_does_not_spend_the_play_armed_capture_duration() -> Test {
    let directory = Directory::new()?;
    let listener = listener()?;
    let approved = approve(&directory, &args(&directory, listener.local_addr()?, Codec::Avc))?;
    let output = capture(&directory, &approved, &listener, Codec::Avc, 1, false, true)?;
    assert_success(&output);
    assert_eq!(details(&rows(&output)?, "capture_duration_complete")?.len(), 1);
    no_connection(&listener)?;
    Ok(())
}

#[test]
fn changing_duration_invalidates_approval_before_camera_or_archive_effects() -> Test {
    let directory = Directory::new()?;
    let listener = listener()?;
    let mut approved = approve(&directory, &args(&directory, listener.local_addr()?, Codec::Avc))?;
    set(&mut approved, "--capture-duration-ms", "501");
    let output = run(&directory, &approved)?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ERR-CAPTURE-RTSP-APPROVAL-001"));
    assert!(output.stdout.is_empty());
    assert!(!directory.0.join("capture.attempt-0001").exists());
    assert!(!directory.0.join("pins.attempt-0001").exists());
    no_connection(&listener)?;
    Ok(())
}
