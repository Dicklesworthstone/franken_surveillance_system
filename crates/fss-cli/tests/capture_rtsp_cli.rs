#![forbid(unsafe_code)]
//! Real-process native RTSP capture through retained import and AVC decode.
//!
//! The camera is an owned loopback fixture serving checked-in AVC bytes. It never closes the
//! successful stream before the client stops, so reaching a picture target cannot masquerade
//! as source EOF. Failure tests preserve the distinction between a durable EOF prefix and an
//! explicitly unpublished malformed tail. These tests establish wiring and custody, not camera,
//! detector, authentication, calibration or deployment qualification.

#[path = "capture_rtsp_cli/runtime.rs"]
mod runtime;

#[cfg(target_os = "linux")]
#[path = "capture_rtsp_cli/preview.rs"]
mod preview;

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;

#[cfg(target_os = "linux")]
#[path = "capture_rtsp_cli/auth.rs"]
mod authentication;

#[cfg(target_os = "linux")]
#[path = "capture_rtsp_cli/onvif.rs"]
mod onvif;

#[path = "capture_rtsp_cli/campaign.rs"]
mod campaign;

#[path = "capture_rtsp_cli/hevc.rs"]
mod hevc;

#[path = "capture_rtsp_cli/reordered.rs"]
mod reordered;

type Test<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const SENSOR: &str = "sensor:rtsp-capture-cli";
const STREAM: &str = "stream:rtsp-capture-cli";
const SITE: &str = "site:rtsp-capture-cli";
const SECRET_REALM: &str = "CAPTURE_RTSP_SECRET_REALM_MARKER";
const SECRET_NONCE: &str = "CAPTURE_RTSP_SECRET_NONCE_MARKER";
const SDP: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\na=control:trackID=0\r\n";

struct Directory(PathBuf);

impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-capture-rtsp-cli-{}-{label}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("owned test-directory allowance exhausted".into())
    }

    fn root(&self) -> PathBuf {
        self.0.join("capture")
    }

    fn pins(&self) -> PathBuf {
        self.0.join("pins")
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// Explicit paths allow a constrained host to build only these three binaries and this test.
// Missing binaries are errors; qualification must never silently skip these process tests.
fn binary(name: &str) -> Test<PathBuf> {
    let (override_name, compiled) = match name {
        "capture" => (
            "FSS_CAPTURE_RTSP_BIN",
            option_env!("CARGO_BIN_EXE_fss-capture-rtsp"),
        ),
        "import" => (
            "FSS_IMPORT_RTSP_BIN",
            option_env!("CARGO_BIN_EXE_fss-import-rtsp"),
        ),
        "file" => ("FSS_FILE_BIN", option_env!("CARGO_BIN_EXE_fss-file")),
        "onvif" => ("FSS_ONVIF_BIN", option_env!("CARGO_BIN_EXE_fss-onvif")),
        "watch-campaign" => (
            "FSS_WATCH_RTSP_CAMPAIGN_BIN",
            option_env!("CARGO_BIN_EXE_fss-watch-rtsp-campaign"),
        ),
        "sentinel-campaign" => (
            "FSS_SENTINEL_RTSP_CAMPAIGN_BIN",
            option_env!("CARGO_BIN_EXE_fss-sentinel-rtsp-campaign"),
        ),
        "infer" => ("FSS_INFER_BIN", option_env!("CARGO_BIN_EXE_fss-infer")),
        "event" => ("FSS_EVENT_BIN", option_env!("CARGO_BIN_EXE_fss-event")),
        _ => return Err("unknown fixture binary".into()),
    };
    std::env::var_os(override_name)
        .or_else(|| compiled.map(OsString::from))
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {name} binary; set {override_name}").into())
}

fn output_bytes(reader: impl Read, output_limit: &AtomicBool) -> io::Result<Vec<u8>> {
    const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;
    let mut bytes = Vec::new();
    reader.take(MAX_OUTPUT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_OUTPUT_BYTES {
        output_limit.store(true, Ordering::Release);
        return Err(io::Error::other("fixture process output bound exceeded"));
    }
    Ok(bytes)
}

fn run(name: &str, args: &[OsString]) -> Test<Output> {
    run_with_timeout(name, args, Duration::from_secs(20))
}

fn run_with_timeout(name: &str, args: &[OsString], timeout: Duration) -> Test<Output> {
    let mut child = Command::new(binary(name)?)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("missing piped stdout")?;
    let stderr = child.stderr.take().ok_or("missing piped stderr")?;
    let output_limit = AtomicBool::new(false);
    thread::scope(|scope| {
        // Drain both pipes while waiting: native progress must not deadlock on pipe capacity.
        let limit = &output_limit;
        let stdout = scope.spawn(move || output_bytes(stdout, limit));
        let stderr = scope.spawn(move || output_bytes(stderr, limit));
        let deadline = Instant::now() + timeout;
        let mut timed_out = false;
        let status = loop {
            if output_limit.load(Ordering::Acquire) {
                let _ = child.kill();
                break child.wait();
            }
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(2));
                }
                Ok(None) => {
                    timed_out = true;
                    let _ = child.kill();
                    break child.wait();
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(error);
                }
            }
        };
        let stdout = stdout.join().map_err(|_| "stdout reader panicked")??;
        let stderr = stderr.join().map_err(|_| "stderr reader panicked")??;
        let output = Output {
            status: status?,
            stdout,
            stderr,
        };
        if timed_out {
            return Err(format!(
                "{name} process exceeded fixture deadline: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(output)
    })
}

fn good(output: Output) -> Test<String> {
    assert!(
        output.status.success(),
        "process failed; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

fn value<'a>(object: &'a Value, key: &str) -> Test<&'a Value> {
    object
        .object()
        .and_then(|fields| fields.get(key))
        .ok_or_else(|| format!("missing report field {key}").into())
}

fn text<'a>(object: &'a Value, key: &str) -> Test<&'a str> {
    value(object, key)?
        .text()
        .ok_or_else(|| format!("report field {key} is not text").into())
}

fn integer(object: &Value, key: &str) -> Test<i128> {
    value(object, key)?
        .integer()
        .ok_or_else(|| format!("report field {key} is not an exact integer").into())
}

fn boolean(object: &Value, key: &str) -> Test<bool> {
    value(object, key)?
        .boolean()
        .ok_or_else(|| format!("report field {key} is not boolean").into())
}

fn digest(label: &str) -> String {
    ContentDigest::sha256(label.as_bytes()).to_text()
}

fn args(directory: &Directory, peer: SocketAddr, pictures: u64) -> Vec<OsString> {
    let pairs = [
        ("--root", directory.root().display().to_string()),
        ("--pins", directory.pins().display().to_string()),
        ("--peer", peer.to_string()),
        ("--authority", peer.to_string()),
        ("--presentation", "/live/".to_owned()),
        ("--control-root", "/live".to_owned()),
        ("--sensor-id", SENSOR.to_owned()),
        ("--stream-id", STREAM.to_owned()),
        ("--generation", "1".to_owned()),
        ("--ingress", "71".to_owned()),
        ("--ssrc", "7".to_owned()),
        ("--anchor", digest("capture CLI authority anchor")),
        ("--receive-clock", digest("capture CLI receive clock")),
        (
            "--timing-evidence",
            digest("owner asserted fixed 25fps cadence"),
        ),
        ("--journal-id", digest("capture CLI independent pin epoch")),
        ("--frame-duration-ticks", "3600".to_owned()),
        ("--stop-after-pictures", pictures.to_string()),
        ("--owner-authorized", "yes".to_owned()),
        ("--plaintext", "yes".to_owned()),
        ("--retain-originals", "yes".to_owned()),
        ("--timeout-ms", "5000".to_owned()),
        ("--drain-timeout-ms", "5000".to_owned()),
        ("--connect-timeout-ms", "1000".to_owned()),
        ("--response-timeout-ms", "1000".to_owned()),
        ("--max-report-bytes", "131072".to_owned()),
        ("--max-window-pictures", "16".to_owned()),
    ];
    pairs
        .into_iter()
        .flat_map(|(key, value)| [OsString::from(key), OsString::from(value)])
        .collect()
}

fn replace(args: &mut [OsString], key: &str, replacement: &str) -> Test {
    let index = args
        .iter()
        .position(|arg| arg == key)
        .ok_or("missing option")?;
    *args.get_mut(index + 1).ok_or("missing option value")? = replacement.into();
    Ok(())
}

fn plan(args: &[OsString]) -> Test<(Value, String)> {
    let document = parse(&good(run("capture", args)?)?)?;
    assert_eq!(text(&document, "schema")?, "fss.rtsp_capture_cli.v1");
    assert_eq!(text(&document, "phase")?, "planned");
    let approval = text(&document, "approval")?.to_owned();
    ContentDigest::parse(&approval)?;
    Ok((document, approval))
}

fn approve(args: &[OsString]) -> Test<Vec<OsString>> {
    let (_, approval) = plan(args)?;
    let mut approved = args.to_vec();
    approved.extend(["--approve".into(), approval.into()]);
    Ok(approved)
}

fn no_connection(listener: &TcpListener) -> Test {
    match listener.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Ok(_) => Err("read-only plan/refusal connected to the camera".into()),
        Err(error) => Err(error.into()),
    }
}

fn listener() -> Test<TcpListener> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

#[derive(Clone, Copy)]
enum Behavior {
    Target,
    StaticTarget,
    EofAfterOne,
    MalformedAfterOne,
    WrongCadence,
    Payload97,
    TwoWindows,
    AuthenticationRequired,
}

#[derive(Debug)]
struct Transcript {
    methods: Vec<String>,
    pictures: usize,
    source_eof: bool,
}

fn request(peer: &mut TcpStream) -> Test<Option<(String, u32)>> {
    let mut bytes = Vec::new();
    while bytes.len() < 8192 {
        let mut byte = [0];
        match peer.read(&mut byte)? {
            0 if bytes.is_empty() => return Ok(None),
            0 => return Err("client closed inside a bounded RTSP request".into()),
            _ => bytes.push(byte[0]),
        }
        if bytes.ends_with(b"\r\n\r\n") {
            let request = String::from_utf8(bytes)?;
            assert!(
                !request.to_ascii_lowercase().contains("authorization:"),
                "no-auth capture dispatched an Authorization header"
            );
            let method = request
                .split_ascii_whitespace()
                .next()
                .ok_or("empty RTSP request")?
                .to_owned();
            let cseq = request
                .split("\r\n")
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("cseq").then_some(value.trim())
                })
                .ok_or("RTSP request has no CSeq")?
                .parse()?;
            return Ok(Some((method, cseq)));
        }
    }
    Err("RTSP request exceeded the fixture byte bound".into())
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

// Independent fixture splitter: one slice per picture in this pinned Baseline stream.
fn nals() -> Vec<&'static [u8]> {
    let bytes: &'static [u8] = include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264");
    let mut output = Vec::new();
    let mut start = None;
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
            continue;
        }
        if let Some(begin) = start {
            let mut end = at;
            while end > begin && bytes[end - 1] == 0 {
                end -= 1;
            }
            if begin < end {
                output.push(&bytes[begin..end]);
            }
        }
        start = Some(at + prefix);
        at += prefix;
    }
    if let Some(begin) = start
        && begin < bytes.len()
    {
        output.push(&bytes[begin..]);
    }
    output
}

fn video(
    pictures: usize,
    frame_duration: u32,
    payload_type: u8,
    two_windows: bool,
) -> Test<Vec<u8>> {
    let source = nals();
    let source = if two_windows {
        let mut completed = 0;
        let end = source
            .iter()
            .position(|nal| {
                if matches!(nal[0] & 31, 1 | 5) {
                    completed += 1;
                }
                completed == 2
            })
            .ok_or("fixture has no initial IDR/P pair")?;
        // Repeat a complete independently decodable pair, keeping RTP sequence and time rising.
        // The next packet-disjoint IDR lets the native collector cut a two-picture window.
        let pair = &source[..=end];
        pair.iter().copied().chain(pair.iter().copied()).collect()
    } else {
        source
    };
    video_nals(pictures, frame_duration, payload_type, source)
}

// Repeat the exact independently decodable first picture. Only native RTP coordinates rise;
// native AVC decode therefore sees identical images without an alternate codec/runtime.
fn static_video(pictures: usize, frame_duration: u32, payload_type: u8) -> Test<Vec<u8>> {
    let source = nals();
    let idr = source
        .iter()
        .position(|nal| nal[0] & 31 == 5)
        .ok_or("first fixture IDR")?;
    let source = std::iter::repeat_n(&source[..=idr], pictures)
        .flat_map(|picture| picture.iter().copied())
        .collect();
    video_nals(pictures, frame_duration, payload_type, source)
}

fn video_nals(
    pictures: usize,
    frame_duration: u32,
    payload_type: u8,
    source: Vec<&[u8]>,
) -> Test<Vec<u8>> {
    let mut result = Vec::new();
    let mut sequence = 1_u16;
    let mut count = 0_u32;
    for nal in source {
        if count as usize == pictures {
            break;
        }
        let kind = nal[0] & 31;
        let picture = matches!(kind, 1 | 5);
        if !matches!(kind, 1 | 5 | 6 | 7 | 8) {
            continue;
        }
        let mut packet = vec![0x80, payload_type | if picture { 128 } else { 0 }];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&(9_000 + count * frame_duration).to_be_bytes());
        packet.extend_from_slice(&7_u32.to_be_bytes());
        packet.extend_from_slice(nal);
        result.extend_from_slice(&[b'$', 0]);
        result.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
        result.extend_from_slice(&packet);
        sequence = sequence
            .checked_add(1)
            .ok_or("fixture RTP sequence overflow")?;
        if picture {
            count += 1;
        }
    }
    assert_eq!(count as usize, pictures, "pinned fixture picture count");
    Ok(result)
}

fn serve(listener: TcpListener, behavior: Behavior) -> Test<Transcript> {
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
    let mut transcript = Transcript {
        methods: Vec::new(),
        pictures: 0,
        source_eof: false,
    };
    let (method, cseq) = request(&mut peer)?.ok_or("client sent no DESCRIBE")?;
    assert_eq!(method, "DESCRIBE");
    transcript.methods.push(method);
    if matches!(behavior, Behavior::AuthenticationRequired) {
        peer.write_all(
            format!(
                "RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\nWWW-Authenticate: Digest realm=\"{SECRET_REALM}\", nonce=\"{SECRET_NONCE}\", qop=\"auth\"\r\nContent-Length: 0\r\n\r\n"
            )
            .as_bytes(),
        )?;
        assert!(
            request(&mut peer)?.is_none(),
            "no-auth capture retried a credential challenge"
        );
        return Ok(transcript);
    }
    let description = if matches!(behavior, Behavior::Payload97) {
        SDP.replace("RTP/AVP 96\r\n", "RTP/AVP 96 97\r\n").replace(
            "a=control:trackID=0\r\n",
            concat!(
                "a=rtpmap:97 H264/90000\r\n",
                "a=fmtp:97 packetization-mode=1;sprop-parameter-sets=",
                "Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\n",
                "a=control:trackID=0\r\n"
            ),
        )
    } else {
        SDP.to_owned()
    };
    response(
        &mut peer,
        cseq,
        "Content-Type: application/sdp\r\n",
        &description,
    )?;
    let (method, cseq) = request(&mut peer)?.ok_or("client sent no SETUP")?;
    assert_eq!(method, "SETUP");
    transcript.methods.push(method);
    response(
        &mut peer,
        cseq,
        "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n",
        "",
    )?;
    let (method, cseq) = request(&mut peer)?.ok_or("client sent no PLAY")?;
    assert_eq!(method, "PLAY");
    transcript.methods.push(method);
    response(&mut peer, cseq, "Session: fixture\r\n", "")?;
    transcript.pictures = match behavior {
        Behavior::Target
        | Behavior::StaticTarget
        | Behavior::WrongCadence
        | Behavior::Payload97 => 2,
        Behavior::TwoWindows => 4,
        _ => 1,
    };
    let cadence = if matches!(behavior, Behavior::WrongCadence) {
        4000
    } else {
        3600
    };
    let payload_type = if matches!(behavior, Behavior::Payload97) {
        97
    } else {
        96
    };
    let video = if matches!(behavior, Behavior::StaticTarget) {
        static_video(transcript.pictures, cadence, payload_type)?
    } else {
        video(
            transcript.pictures,
            cadence,
            payload_type,
            matches!(behavior, Behavior::TwoWindows),
        )?
    };
    peer.write_all(&video)?;
    if matches!(behavior, Behavior::MalformedAfterOne) {
        // Complete interleaved framing, deliberately truncated RTP header.
        peer.write_all(&[b'$', 0, 0, 4, 0x80, 96, 0, 9])?;
    }
    if matches!(behavior, Behavior::EofAfterOne) {
        peer.shutdown(Shutdown::Write)?;
        transcript.source_eof = true;
    }
    // A successful server never invents EOF: it waits for the client's close or teardown.
    for _ in 0..16 {
        let Some((method, cseq)) = request(&mut peer)? else {
            return Ok(transcript);
        };
        transcript.methods.push(method.clone());
        match method.as_str() {
            "TEARDOWN" | "GET_PARAMETER" | "OPTIONS" => {
                response(&mut peer, cseq, "Session: fixture\r\n", "")?;
            }
            _ => return Err("unexpected RTSP operation after PLAY".into()),
        }
    }
    Err("RTSP fixture exceeded the request bound".into())
}

fn captured(
    listener: TcpListener,
    args: &[OsString],
    behavior: Behavior,
) -> Test<(Output, Transcript)> {
    thread::scope(|scope| {
        let server = scope.spawn(move || serve(listener, behavior));
        let output = run("capture", args);
        let server = server.join().map_err(|_| "RTSP fixture thread panicked")?;
        match (output, server) {
            (Ok(output), Ok(transcript)) => Ok((output, transcript)),
            (Ok(output), Err(error)) => Err(format!(
                "RTSP fixture failed: {error}; child stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into()),
            (Err(error), _) => Err(error),
        }
    })
}

fn rows(output: &Output) -> Test<Vec<Value>> {
    let stdout = std::str::from_utf8(&output.stdout)?;
    let mut rows = Vec::new();
    let mut previous = None;
    for line in stdout.lines() {
        assert!(!line.is_empty(), "blank row in structured capture output");
        let row = parse(line)?;
        assert_eq!(text(&row, "schema")?, "fss.rtsp_capture_cli.v1");
        let sequence = integer(&row, "sequence")?;
        if let Some(previous) = previous {
            assert_eq!(sequence, previous + 1, "noncontiguous report sequence");
        }
        previous = Some(sequence);
        let _ = value(&row, "detail")?
            .object()
            .ok_or("capture detail is not an object")?;
        rows.push(row);
    }
    assert!(!rows.is_empty(), "capture produced no typed progress");
    Ok(rows)
}

fn detail<'a>(rows: &'a [Value], kind: &str) -> Test<&'a Value> {
    let mut matches = rows.iter().filter(|row| {
        row.object()
            .and_then(|fields| fields.get("kind"))
            .and_then(Value::text)
            == Some(kind)
    });
    let row = matches
        .next()
        .ok_or_else(|| format!("missing {kind} row"))?;
    assert!(matches.next().is_none(), "duplicate unique {kind} row");
    value(row, "detail")
}

fn import_and_decode(directory: &Directory, rows: &[Value], frames: i128) -> Test {
    import_selected_and_decode(directory, rows, frames, false)
}

fn import_selected_and_decode(
    directory: &Directory,
    rows: &[Value],
    frames: i128,
    whole_catalog: bool,
) -> Test {
    let selected = detail(
        rows,
        if whole_catalog {
            "catalog_published"
        } else {
            "window_durable"
        },
    )?;
    let (slot_option, root_option) = if whole_catalog {
        ("--catalog-slot", "--catalog-root")
    } else {
        ("--window-slot", "--window-root")
    };
    let root = directory.0.join("deployment");
    let mut args: Vec<OsString> = [
        "--archive",
        directory.root().to_str().ok_or("archive path")?,
        "--root",
        root.to_str().ok_or("deployment path")?,
        "--site",
        SITE,
        slot_option,
        text(selected, "slot")?,
        root_option,
        text(selected, "root")?,
        "--codec",
        "avc",
        "--sensor-id",
        SENSOR,
        "--stream-id",
        STREAM,
        "--generation",
        "1",
        "--anchor",
        &digest("capture CLI authority anchor"),
        "--receive-clock",
        &digest("capture CLI receive clock"),
        "--receive-time-ns",
        "5000000000",
        "--owner-authorized",
        "yes",
        "--read-originals",
        "yes",
        "--retain-originals",
        "yes",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    if whole_catalog {
        args.extend([
            OsString::from("--decode-clock"),
            OsString::from(text(selected, "decode_clock")?),
            OsString::from("--time-scale"),
            OsString::from(integer(selected, "time_scale")?.to_string()),
        ]);
    }
    let preview = parse(&good(run("import", &args)?)?)?;
    if whole_catalog {
        assert_eq!(
            text(&preview, "format")?,
            "fss.rtsp_catalog_import_operator.v1"
        );
        assert_eq!(text(&preview, "selection")?, "complete_catalog_page");
    }
    assert!(!root.exists(), "import preview created destination custody");
    args.extend([
        "--approve".into(),
        text(&preview, "approval_digest")?.into(),
    ]);
    let imported = parse(&good(run("import", &args)?)?)?;
    assert_eq!(integer(&imported, "frames")?, frames);
    assert_eq!(text(&imported, "capture_time_label")?, "unknown");
    assert!(boolean(
        &imported,
        "destination_contains_original_recording"
    )?);
    if whole_catalog {
        assert!(boolean(&imported, "destination_contains_complete_catalog")?);
        assert_eq!(
            integer(&imported, "windows")?,
            integer(selected, "windows")?
        );
    }
    assert!(!boolean(&imported, "reused")?);
    let identity = text(&imported, "import_identity")?.to_owned();
    let origin = text(&imported, "origin_proof")?.to_owned();
    ContentDigest::parse(&origin)?;
    let ledger = fs::read(root.join("ledger/journal.fssj"))?;
    let effects = fs::read(root.join("effects/journal.fssj"))?;
    let retried = parse(&good(run("import", &args)?)?)?;
    assert!(boolean(&retried, "reused")?);
    assert_eq!(text(&retried, "import_identity")?, identity);
    assert_eq!(text(&retried, "origin_proof")?, origin);
    assert_eq!(fs::read(root.join("ledger/journal.fssj"))?, ledger);
    assert_eq!(fs::read(root.join("effects/journal.fssj"))?, effects);

    // The retained import must decode with its original capture archive unavailable.
    fs::rename(directory.root(), directory.0.join("offline-capture"))?;
    let common: Vec<OsString> = [
        "--root",
        root.to_str().ok_or("root path")?,
        "--site",
        SITE,
        "--import-id",
        &identity,
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let mut verify = vec!["verify".into()];
    verify.extend(common.clone());
    let verified = good(run("file", &verify)?)?;
    assert!(verified.contains("media_format=mp4avc"), "{verified}");
    assert!(
        verified.contains(&format!("segment_count={frames}")),
        "{verified}"
    );
    assert!(
        verified.contains("capture_time_class=unknown"),
        "{verified}"
    );
    assert!(verified.contains("absence_certifiable=false"), "{verified}");
    let mut decode = vec!["decode".into()];
    decode.extend(common);
    decode.extend(
        [
            "--segment",
            "0",
            "--segment-count",
            &frames.to_string(),
            "--interpretation",
            "ycbcr",
            "--work-units",
            "1000000000",
        ]
        .into_iter()
        .map(OsString::from),
    );
    let decoded = good(run("file", &decode)?)?;
    assert!(
        decoded
            .lines()
            .any(|line| line == format!("h264_frames_decoded={frames}")),
        "native AVC decoder did not return the complete requested range: {decoded}"
    );
    assert!(
        decoded.lines().any(|line| line == "decode_complete=true"),
        "{decoded}"
    );
    assert_eq!(
        decoded
            .lines()
            .filter(|line| line.starts_with("frame_luma_sha256="))
            .count(),
        usize::try_from(frames)?,
        "each requested picture must produce a native decoded-frame digest"
    );
    assert_eq!(
        fs::read(root.join("effects/journal.fssj"))?,
        effects,
        "retained import or native decode dispatched an effect"
    );
    Ok(())
}

#[test]
fn planning_and_mismatched_approval_do_not_connect_or_create_stores() -> Test {
    let directory = Directory::new("approval")?;
    let listener = listener()?;
    let args = args(&directory, listener.local_addr()?, 2);
    let (_, approval) = plan(&args)?;
    assert!(!directory.root().exists());
    assert!(!directory.pins().exists());
    no_connection(&listener)?;

    let mut wrong = args.clone();
    wrong.extend(["--approve".into(), digest("wrong capture approval").into()]);
    assert!(!run("capture", &wrong)?.status.success());
    no_connection(&listener)?;
    assert!(!directory.root().exists());
    assert!(!directory.pins().exists());

    let mut changed = args;
    replace(&mut changed, "--stop-after-pictures", "3")?;
    changed.extend(["--approve".into(), approval.into()]);
    assert!(!run("capture", &changed)?.status.success());
    no_connection(&listener)?;
    assert!(!directory.root().exists());
    assert!(!directory.pins().exists());
    Ok(())
}

#[test]
fn approved_target_stop_retains_importable_native_avc_without_fabricated_eof() -> Test {
    let directory = Directory::new("target")?;
    let listener = listener()?;
    let args = approve(&args(&directory, listener.local_addr()?, 2))?;
    let (output, transcript) = captured(listener, &args, Behavior::Target)?;
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(&transcript.methods[..3], ["DESCRIBE", "SETUP", "PLAY"]);
    assert_eq!(transcript.pictures, 2);
    assert!(!transcript.source_eof);
    let rows = rows(&output)?;
    let started = detail(&rows, "started")?;
    assert_eq!(integer(started, "time_scale")?, 90_000);
    assert_eq!(text(started, "capture_time")?, "unknown");
    let terminal = detail(&rows, "terminal")?;
    assert!(boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "stop_cause")?, "owner_stopped");
    assert!(!boolean(terminal, "peer_eof")?);
    assert!(!boolean(terminal, "input_end_observed")?);
    assert_eq!(integer(terminal, "durable_pictures")?, 2);
    assert_eq!(integer(terminal, "indexed_windows")?, 1);
    assert_eq!(integer(terminal, "collected_pictures")?, 2);
    assert_eq!(integer(terminal, "durable_windows")?, 1);
    assert_eq!(value(terminal, "error_id")?, &Value::Null);
    // The final confirmed work pin is retained recovery metadata, even after completion.
    let confirmed = value(terminal, "confirmed_pin")?;
    ContentDigest::parse(text(confirmed, "root")?)?;
    ContentDigest::parse(text(confirmed, "retirement_digest")?)?;
    assert!(!text(confirmed, "slot")?.is_empty());
    assert!(directory.pins().is_dir());
    import_and_decode(&directory, &rows, 2)
}

#[test]
fn peer_eof_before_target_is_incomplete_but_completed_prefix_is_importable() -> Test {
    let directory = Directory::new("early-eof")?;
    let listener = listener()?;
    let args = approve(&args(&directory, listener.local_addr()?, 2))?;
    let (output, transcript) = captured(listener, &args, Behavior::EofAfterOne)?;
    assert!(
        !output.status.success(),
        "short source satisfied a two-picture target"
    );
    assert!(transcript.source_eof);
    assert_eq!(transcript.pictures, 1);
    let rows = rows(&output)?;
    let terminal = detail(&rows, "terminal")?;
    assert!(!boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "stop_cause")?, "input_ended_before_target");
    assert!(boolean(terminal, "peer_eof")?);
    assert!(boolean(terminal, "input_end_observed")?);
    assert_eq!(integer(terminal, "durable_pictures")?, 1);
    assert_eq!(integer(terminal, "indexed_windows")?, 1);
    assert_eq!(integer(terminal, "collected_pictures")?, 1);
    assert_eq!(integer(terminal, "durable_windows")?, 1);
    import_and_decode(&directory, &rows, 1)
}

#[test]
fn authentication_challenge_is_secret_free_and_never_retried() -> Test {
    let directory = Directory::new("authentication")?;
    let listener = listener()?;
    let args = approve(&args(&directory, listener.local_addr()?, 2))?;
    let (output, transcript) = captured(listener, &args, Behavior::AuthenticationRequired)?;
    assert!(!output.status.success());
    assert_eq!(transcript.methods, ["DESCRIBE"]);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for secret in [SECRET_REALM, SECRET_NONCE, "WWW-Authenticate"] {
        assert!(
            !combined.contains(secret),
            "challenge material leaked into output"
        );
    }
    let rows = rows(&output)?;
    let terminal = detail(&rows, "terminal")?;
    assert!(!boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "stop_cause")?, "authentication_required");
    assert_eq!(integer(terminal, "collected_pictures")?, 0);
    assert_eq!(integer(terminal, "durable_windows")?, 0);
    Ok(())
}

#[test]
fn malformed_tail_is_refused_without_publishing_an_incomplete_window() -> Test {
    let directory = Directory::new("malformed")?;
    let listener = listener()?;
    let args = approve(&args(&directory, listener.local_addr()?, 2))?;
    let (output, _) = captured(listener, &args, Behavior::MalformedAfterOne)?;
    assert!(!output.status.success());
    let rows = rows(&output)?;
    let terminal = detail(&rows, "terminal")?;
    assert!(!boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "stop_cause")?, "protocol_failure");
    assert_eq!(integer(terminal, "collected_pictures")?, 1);
    assert_eq!(integer(terminal, "durable_windows")?, 0);
    assert!(integer(terminal, "unsealed_rtp_bytes")? > 0);
    assert!(integer(terminal, "unsealed_pictures")? >= 1);
    assert!(value(terminal, "error_id")?.text().is_some());
    assert!(
        rows.iter()
            .all(|row| text(row, "kind").ok() != Some("window_durable")),
        "malformed tail acquired a durable-window claim"
    );
    Ok(())
}

#[test]
fn source_cadence_mismatch_is_refused_without_guessing_a_media_timeline() -> Test {
    let directory = Directory::new("cadence")?;
    let listener = listener()?;
    let args = approve(&args(&directory, listener.local_addr()?, 2))?;
    let (output, transcript) = captured(listener, &args, Behavior::WrongCadence)?;
    assert!(!output.status.success());
    assert_eq!(transcript.pictures, 2);
    assert!(!transcript.source_eof);
    let rows = rows(&output)?;
    let terminal = detail(&rows, "terminal")?;
    assert!(!boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "stop_cause")?, "timing_refused");
    assert_eq!(integer(terminal, "collected_pictures")?, 1);
    assert_eq!(integer(terminal, "durable_windows")?, 0);
    assert!(integer(terminal, "unsealed_rtp_bytes")? > 0);
    assert!(integer(terminal, "untimed_picture_bytes")? > 0);
    assert!(!boolean(terminal, "coverage_certified")?);
    assert_eq!(text(terminal, "capture_time")?, "unknown");
    Ok(())
}

#[cfg(unix)]
#[test]
fn approved_aliasing_parent_directories_are_refused_before_storage_or_connection() -> Test {
    use std::os::unix::fs::symlink;

    let directory = Directory::new("parent-alias")?;
    let actual_parent = directory.0.join("actual");
    let alias_parent = directory.0.join("alias");
    fs::create_dir(&actual_parent)?;
    symlink(&actual_parent, &alias_parent)?;
    let actual_root = actual_parent.join("capture");
    let alias_pins = alias_parent.join("capture");
    let listener = listener()?;
    let mut args = args(&directory, listener.local_addr()?, 2);
    replace(
        &mut args,
        "--root",
        actual_root.to_str().ok_or("actual root path")?,
    )?;
    replace(
        &mut args,
        "--pins",
        alias_pins.to_str().ok_or("aliased pin path")?,
    )?;
    // Pure planning is intentionally lexical. Filesystem resolution is approved runtime work.
    let approved = approve(&args)?;
    assert!(!actual_root.exists());
    no_connection(&listener)?;
    let output = run("capture", &approved)?;
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("ERR-CAPTURE-RTSP-ROOT-001"),
        "aliased destinations were not refused as a root conflict"
    );
    no_connection(&listener)?;
    assert!(!actual_root.exists());
    assert!(!alias_pins.exists());
    assert!(
        fs::symlink_metadata(&alias_parent)?
            .file_type()
            .is_symlink()
    );
    Ok(())
}

#[test]
fn selected_secondary_avc_payload_is_retained_and_cold_decoded() -> Test {
    let directory = Directory::new("payload97")?;
    let listener = listener()?;
    let mut args = args(&directory, listener.local_addr()?, 2);
    args.extend(["--payload-type".into(), "97".into()]);
    let (preview, approval) = plan(&args)?;
    assert_eq!(integer(value(&preview, "bounds")?, "payload_type")?, 97);
    args.extend(["--approve".into(), approval.into()]);
    let (output, transcript) = captured(listener, &args, Behavior::Payload97)?;
    assert!(
        output.status.success(),
        "selected PT97 capture failed; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(&transcript.methods[..3], ["DESCRIBE", "SETUP", "PLAY"]);
    assert_eq!(transcript.pictures, 2);
    assert!(!transcript.source_eof);
    let rows = rows(&output)?;
    let terminal = detail(&rows, "terminal")?;
    assert!(boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "stop_cause")?, "owner_stopped");
    assert!(!boolean(terminal, "peer_eof")?);
    assert_eq!(integer(terminal, "collected_pictures")?, 2);
    assert_eq!(integer(terminal, "durable_pictures")?, 2);
    assert_eq!(integer(terminal, "durable_windows")?, 1);
    assert_eq!(integer(terminal, "indexed_windows")?, 1);
    import_and_decode(&directory, &rows, 2)
}

#[test]
fn native_capture_catalog_imports_both_windows_and_cold_decodes_every_picture() -> Test {
    let directory = Directory::new("catalog")?;
    let listener = listener()?;
    let mut args = args(&directory, listener.local_addr()?, 4);
    replace(&mut args, "--max-window-pictures", "2")?;
    let (preview, approval) = plan(&args)?;
    args.extend(["--approve".into(), approval.into()]);
    let (output, transcript) = captured(listener, &args, Behavior::TwoWindows)?;
    assert!(
        output.status.success(),
        "multi-window capture failed; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(transcript.pictures, 4);
    assert!(!transcript.source_eof);
    let rows = rows(&output)?;
    let terminal = detail(&rows, "terminal")?;
    assert!(boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "stop_cause")?, "owner_stopped");
    assert!(!boolean(terminal, "peer_eof")?);
    assert_eq!(integer(terminal, "collected_pictures")?, 4);
    assert_eq!(integer(terminal, "durable_pictures")?, 4);
    assert_eq!(integer(terminal, "durable_windows")?, 2);
    assert_eq!(integer(terminal, "indexed_windows")?, 2);
    let mut windows = 0;
    for row in &rows {
        if text(row, "kind")? == "window_durable" {
            let window = value(row, "detail")?;
            assert_eq!(integer(window, "ordinal")?, windows);
            assert_eq!(integer(window, "pictures")?, 2);
            assert_eq!(integer(window, "decode_start")?, windows * 7200);
            assert_eq!(integer(window, "decode_end")?, (windows + 1) * 7200);
            windows += 1;
        }
    }
    assert_eq!(windows, 2);
    let catalog = detail(&rows, "catalog_published")?;
    assert_eq!(integer(catalog, "windows")?, 2);
    assert_eq!(integer(catalog, "time_scale")?, 90_000);
    assert_eq!(
        text(catalog, "decode_clock")?,
        text(&preview, "decode_clock")?
    );
    assert_eq!(text(catalog, "codec")?, "avc");
    assert_eq!(text(value(catalog, "source")?, "sensor_id")?, SENSOR);
    assert_eq!(text(value(catalog, "source")?, "stream_id")?, STREAM);
    let receipt = value(catalog, "receipt")?;
    assert_eq!(text(catalog, "slot")?, text(receipt, "slot")?);
    assert_eq!(text(catalog, "root")?, text(receipt, "root")?);
    import_selected_and_decode(&directory, &rows, 4, true)
}
