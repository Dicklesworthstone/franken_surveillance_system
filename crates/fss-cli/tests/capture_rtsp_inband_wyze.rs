#![forbid(unsafe_code)]
//! Deterministic loopback E2E tests for Wyze SmolRTSP interoperability (`fss-x4a.31.3.1`):
//! 1. In-band H.264 SPS/PPS acquisition (STAP-A, separate NAL, FU-A IDR) with explicit
//!    `parameter_set_origin = "inband_rtp"` and `pre_sync_discarded` provenance accounting.
//! 2. Multi-track companion audio SETUP on distinct interleaved channels (2-3) with packet
//!    draining (`companion_packets_discarded`) and clean `TEARDOWN` on stop.
//! 3. Bounded pre-roll budget exhaustion failing closed when SPS/PPS/IDR never arrives.
//! 4. Mid-stream SPS generation change fencing cleanly without mixing parameter sets.
//! 5. Non-UTF-8 / Latin-1 vendor RTSP headers (`Server: Cam\xe9ra/1.0`) parsed safely (`fss-0i0ue`).
//! 6. Strict default mode continuing to refuse SDP without `sprop-parameter-sets`.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;

type Test<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const SENSOR: &str = "sensor:wyze-cam-v4";
const STREAM: &str = "stream:wyze-main";
const SITE: &str = "site:wyze-lab";

const WYZE_SDP: &str = concat!(
    "v=0\r\n",
    "o=- 1 1 IN IP4 127.0.0.1\r\n",
    "s=SmolRTSP\r\n",
    "t=0 0\r\n",
    "a=control:*\r\n",
    "m=video 0 RTP/AVP 96\r\n",
    "a=rtpmap:96 H264/90000\r\n",
    "a=control:track1\r\n",
    "m=audio 0 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=control:track2\r\n",
);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Test<Self> {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-wyze-inband-{}-{label}-{attempt}",
                std::process::id()
            ));
            match builder.create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("could not allocate temporary test directory".into())
    }
    fn root(&self) -> PathBuf {
        self.0.join("archive")
    }
    fn pins(&self) -> PathBuf {
        self.0.join("pins")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn digest(label: &str) -> String {
    ContentDigest::sha256(label.as_bytes()).to_text()
}

fn bind_loopback() -> Test<(TcpListener, SocketAddr)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let addr = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    Ok((listener, addr))
}

fn run_bin(kind: &str, args: &[OsString]) -> Test<Output> {
    let bin = match kind {
        "capture" => env!("CARGO_BIN_EXE_fss-capture-rtsp"),
        "import" => env!("CARGO_BIN_EXE_fss-import-rtsp"),
        "file" => env!("CARGO_BIN_EXE_fss-file"),
        other => return Err(format!("unknown binary {other}").into()),
    };
    let output = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    Ok(output)
}

fn ok_stdout(output: Output) -> Test<String> {
    if !output.status.success() {
        return Err(format!(
            "command failed ({:?}): stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn value<'a>(node: &'a Value, key: &str) -> Test<&'a Value> {
    node.object()
        .and_then(|map| map.get(key))
        .ok_or_else(|| format!("missing JSON key {key}").into())
}

fn text<'a>(node: &'a Value, key: &str) -> Test<&'a str> {
    value(node, key)?
        .text()
        .ok_or_else(|| format!("JSON key {key} is not a string").into())
}

fn integer(node: &Value, key: &str) -> Test<i128> {
    value(node, key)?
        .integer()
        .ok_or_else(|| format!("JSON key {key} is not an integer").into())
}

fn boolean(node: &Value, key: &str) -> Test<bool> {
    value(node, key)?
        .boolean()
        .ok_or_else(|| format!("JSON key {key} is not a boolean").into())
}

fn parse_rows(output: &Output) -> Test<Vec<Value>> {
    let stdout = std::str::from_utf8(&output.stdout)?;
    let mut rows = Vec::new();
    for line in stdout.lines() {
        assert!(!line.is_empty());
        rows.push(parse(line)?);
    }
    assert!(!rows.is_empty(), "capture emitted no JSONL rows");
    Ok(rows)
}

fn row_detail<'a>(rows: &'a [Value], kind: &str) -> Test<&'a Value> {
    let row = rows
        .iter()
        .find(|row| {
            row.object()
                .and_then(|m| m.get("kind"))
                .and_then(Value::text)
                == Some(kind)
        })
        .ok_or_else(|| format!("missing row kind {kind}"))?;
    value(row, "detail")
}

fn base_capture_args(
    dir: &TempDir,
    addr: SocketAddr,
    ssrc: &str,
    stop_after: &str,
    extra: &[(&str, &str)],
) -> Test<Vec<OsString>> {
    let mut args: Vec<OsString> = [
        "--root",
        dir.root().to_str().ok_or("root path")?,
        "--pins",
        dir.pins().to_str().ok_or("pins path")?,
        "--peer",
        &addr.to_string(),
        "--authority",
        &addr.to_string(),
        "--presentation",
        "/stream1",
        "--control-root",
        "/",
        "--sensor-id",
        SENSOR,
        "--stream-id",
        STREAM,
        "--generation",
        "1",
        "--ingress",
        "1",
        "--ssrc",
        ssrc,
        "--anchor",
        &digest("wyze authority anchor"),
        "--receive-clock",
        &digest("wyze receive clock"),
        "--timing-evidence",
        &digest("wyze timing evidence"),
        "--journal-id",
        &digest("wyze journal id"),
        "--frame-duration-ticks",
        "3600",
        "--stop-after-pictures",
        stop_after,
        "--owner-authorized",
        "yes",
        "--plaintext",
        "yes",
        "--retain-originals",
        "yes",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    for (k, v) in extra {
        args.push(OsString::from(k));
        args.push(OsString::from(v));
    }
    let preview = parse(&ok_stdout(run_bin("capture", &args)?)?)?;
    args.push(OsString::from("--approve"));
    args.push(OsString::from(text(&preview, "approval")?));
    Ok(args)
}

type FixtureNals = (&'static [u8], &'static [u8], &'static [u8], &'static [u8]);

/// Extract real decodable SPS, PPS, IDR, and P-frame NALs from checked-in baseline.264.
fn fixture_nals() -> Test<FixtureNals> {
    let bytes: &'static [u8] = include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264");
    let mut nals = Vec::new();
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
                nals.push(&bytes[begin..end]);
            }
        }
        start = Some(at + prefix);
        at += prefix;
    }
    if let Some(begin) = start
        && begin < bytes.len()
    {
        nals.push(&bytes[begin..]);
    }
    let sps = *nals
        .iter()
        .find(|n| n[0] & 31 == 7)
        .ok_or("missing fixture SPS")?;
    let pps = *nals
        .iter()
        .find(|n| n[0] & 31 == 8)
        .ok_or("missing fixture PPS")?;
    let idr = *nals
        .iter()
        .find(|n| n[0] & 31 == 5)
        .ok_or("missing fixture IDR")?;
    let p_slice = *nals
        .iter()
        .find(|n| n[0] & 31 == 1)
        .ok_or("missing fixture P slice")?;
    Ok((sps, pps, idr, p_slice))
}

fn interleaved_rtp(
    channel: u8,
    seq: u16,
    ts: u32,
    marker: bool,
    ssrc: u32,
    pt: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(12 + payload.len());
    pkt.push(0x80);
    pkt.push(pt | if marker { 0x80 } else { 0 });
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&ts.to_be_bytes());
    pkt.extend_from_slice(&ssrc.to_be_bytes());
    pkt.extend_from_slice(payload);
    let mut framed = Vec::with_capacity(4 + pkt.len());
    framed.push(b'$');
    framed.push(channel);
    framed.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
    framed.extend_from_slice(&pkt);
    framed
}

fn stap_a(units: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![0x78]; // F=0, NRI=3, Type=24
    for unit in units {
        out.extend_from_slice(&(unit.len() as u16).to_be_bytes());
        out.extend_from_slice(unit);
    }
    out
}

fn read_rtsp_request(peer: &mut TcpStream) -> Test<Option<(String, String, u32, String)>> {
    let mut bytes = Vec::new();
    while bytes.len() < 8192 {
        let mut byte = [0];
        match peer.read(&mut byte) {
            Ok(0) if bytes.is_empty() => return Ok(None),
            Ok(0) => return Err("EOF mid-request".into()),
            Ok(_) => bytes.push(byte[0]),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        }
        if bytes.ends_with(b"\r\n\r\n") {
            let text = String::from_utf8(bytes)?;
            let first = text.split("\r\n").next().unwrap_or("");
            let mut parts = first.split_ascii_whitespace();
            let method = parts.next().ok_or("missing method")?.to_owned();
            let uri = parts.next().ok_or("missing uri")?.to_owned();
            let cseq = text
                .split("\r\n")
                .find_map(|line| {
                    let (k, v) = line.split_once(':')?;
                    k.eq_ignore_ascii_case("cseq").then_some(v.trim())
                })
                .ok_or("missing CSeq")?
                .parse()?;
            return Ok(Some((method, uri, cseq, text)));
        }
    }
    Err("RTSP request exceeded 8 KiB".into())
}

fn write_response_raw(peer: &mut TcpStream, cseq: u32, extra_headers: &[u8], body: &[u8]) -> Test {
    let mut out = Vec::new();
    out.extend_from_slice(
        format!(
            "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n",
            body.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(extra_headers);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    peer.write_all(&out)?;
    Ok(())
}

#[derive(Clone, Copy)]
enum Scenario {
    WyzeStapAWithCompanionAudio,
    SeparateSpsPpsAndFuAIdr,
    MissingSpsPpsBudgetExhausted,
    MidStreamSpsGenerationChange,
    Latin1VendorHeaders,
    StrictDefaultRejectsMissingSprop,
}

struct ServerTranscript {
    methods: Vec<String>,
    setup_uris: Vec<String>,
}

fn serve_wyze(listener: TcpListener, scenario: Scenario) -> Test<ServerTranscript> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut peer = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
            Err(e) => return Err(format!("accept timeout: {e}").into()),
        }
    };
    peer.set_nonblocking(false)?;
    peer.set_read_timeout(Some(Duration::from_secs(10)))?;
    peer.set_write_timeout(Some(Duration::from_secs(10)))?;
    peer.set_nodelay(true)?;

    let mut transcript = ServerTranscript {
        methods: Vec::new(),
        setup_uris: Vec::new(),
    };
    let latin1_header: &[u8] = if matches!(scenario, Scenario::Latin1VendorHeaders) {
        b"Server: Cam\xe9ra-SmolRTSP/1.0\r\nX-Vendor: caf\xe9\r\n"
    } else {
        b"Server: SmolRTSP/0.1\r\n"
    };

    // 1. DESCRIBE
    let Some((method, _, cseq, _)) = read_rtsp_request(&mut peer)? else {
        return Err("no DESCRIBE".into());
    };
    assert_eq!(method, "DESCRIBE");
    transcript.methods.push(method);
    let mut desc_hdrs = Vec::new();
    desc_hdrs.extend_from_slice(latin1_header);
    desc_hdrs.extend_from_slice(b"Content-Type: application/sdp\r\n");
    write_response_raw(&mut peer, cseq, &desc_hdrs, WYZE_SDP.as_bytes())?;

    if matches!(scenario, Scenario::StrictDefaultRejectsMissingSprop) {
        // Strict mode must reject DESCRIBE immediately without sending SETUP.
        assert!(read_rtsp_request(&mut peer)?.is_none());
        return Ok(transcript);
    }

    // 2. Video SETUP (track1, interleaved=0-1)
    let Some((method, uri, cseq, raw)) = read_rtsp_request(&mut peer)? else {
        return Err("no video SETUP".into());
    };
    assert_eq!(method, "SETUP");
    assert!(
        uri.ends_with("/track1"),
        "unexpected video SETUP URI: {uri}"
    );
    assert!(
        raw.contains("interleaved=0-1"),
        "missing 0-1 transport: {raw}"
    );
    transcript.methods.push(method);
    transcript.setup_uris.push(uri);
    let mut setup_v = Vec::new();
    setup_v.extend_from_slice(latin1_header);
    if matches!(scenario, Scenario::SeparateSpsPpsAndFuAIdr) {
        // Omit ssrc= so --ssrc auto learns SSRC from the first RTP packet during pre-roll!
        setup_v.extend_from_slice(
            b"Session: wyze-v4;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n",
        );
    } else {
        setup_v.extend_from_slice(
            b"Session: wyze-v4;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=00000007\r\n",
        );
    }
    write_response_raw(&mut peer, cseq, &setup_v, b"")?;

    // 3. Companion Audio SETUP (track2, interleaved=2-3) when companion tracks enabled
    let expects_companion = matches!(
        scenario,
        Scenario::WyzeStapAWithCompanionAudio | Scenario::Latin1VendorHeaders
    );
    if expects_companion {
        let Some((method, uri, cseq, raw)) = read_rtsp_request(&mut peer)? else {
            return Err("expected companion audio SETUP before PLAY".into());
        };
        assert_eq!(method, "SETUP");
        assert!(
            uri.ends_with("/track2"),
            "unexpected companion SETUP URI: {uri}"
        );
        assert!(
            raw.contains("Session: wyze-v4"),
            "companion SETUP must carry negotiated Session: {raw}"
        );
        assert!(
            raw.contains("interleaved=2-3"),
            "companion SETUP must use disjoint channels 2-3: {raw}"
        );
        transcript.methods.push(method);
        transcript.setup_uris.push(uri);
        let mut setup_a = Vec::new();
        setup_a.extend_from_slice(latin1_header);
        setup_a.extend_from_slice(
            b"Session: wyze-v4;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=2-3;ssrc=DEADBEEF\r\n",
        );
        write_response_raw(&mut peer, cseq, &setup_a, b"")?;
    }

    // 4. PLAY
    let Some((method, _, cseq, _)) = read_rtsp_request(&mut peer)? else {
        return Err("no PLAY".into());
    };
    assert_eq!(method, "PLAY");
    transcript.methods.push(method);
    let mut play_hdrs = Vec::new();
    play_hdrs.extend_from_slice(latin1_header);
    play_hdrs.extend_from_slice(b"Session: wyze-v4\r\n");
    write_response_raw(&mut peer, cseq, &play_hdrs, b"")?;

    // 5. Stream interleaved media according to scenario
    let (sps, pps, idr, p_slice) = fixture_nals()?;
    let mut media = Vec::new();
    match scenario {
        Scenario::WyzeStapAWithCompanionAudio | Scenario::Latin1VendorHeaders => {
            // 3 pre-sync P-frames + interleaved audio packets on channels 2 & 3
            for i in 0..3u16 {
                media.extend_from_slice(&interleaved_rtp(
                    0,
                    10 + i,
                    9000 + u32::from(i) * 3600,
                    true,
                    7,
                    96,
                    p_slice,
                ));
                media.extend_from_slice(&interleaved_rtp(
                    2,
                    100 + i,
                    8000 + u32::from(i) * 160,
                    false,
                    0xDEAD_BEEF,
                    0,
                    &[0x7f; 160],
                ));
            }
            // Interleaved audio RTCP on channel 3
            media.extend_from_slice(&[b'$', 3, 0, 8, 0x80, 0xc9, 0, 1, 0xde, 0xad, 0xbe, 0xef]);
            // Sync point: STAP-A(SPS + PPS + IDR) on seq 13
            let stap = stap_a(&[sps, pps, idr]);
            media.extend_from_slice(&interleaved_rtp(0, 13, 19800, true, 7, 96, &stap));
            // Another audio packet interleaved mid-stream
            media.extend_from_slice(&interleaved_rtp(
                2,
                103,
                8480,
                false,
                0xDEAD_BEEF,
                0,
                &[0x55; 160],
            ));
            // Second picture: P-frame on seq 14
            media.extend_from_slice(&interleaved_rtp(0, 14, 23400, true, 7, 96, p_slice));
        }
        Scenario::SeparateSpsPpsAndFuAIdr => {
            // 2 pre-sync P-frames (seq 1, 2)
            media.extend_from_slice(&interleaved_rtp(0, 1, 9000, true, 7, 96, p_slice));
            media.extend_from_slice(&interleaved_rtp(0, 2, 12600, true, 7, 96, p_slice));
            // Separate SPS (seq 3) and PPS (seq 4)
            media.extend_from_slice(&interleaved_rtp(0, 3, 16200, false, 7, 96, sps));
            media.extend_from_slice(&interleaved_rtp(0, 4, 16200, false, 7, 96, pps));
            // FU-A fragmented IDR across 2 packets (seq 5 start, seq 6 end+marker)
            let body = &idr[1..];
            let mid = body.len() / 2;
            let mut fu_start = vec![(idr[0] & 0xE0) | 28, 0x80 | 5];
            fu_start.extend_from_slice(&body[..mid]);
            let mut fu_end = vec![(idr[0] & 0xE0) | 28, 0x40 | 5];
            fu_end.extend_from_slice(&body[mid..]);
            media.extend_from_slice(&interleaved_rtp(0, 5, 16200, false, 7, 96, &fu_start));
            media.extend_from_slice(&interleaved_rtp(0, 6, 16200, true, 7, 96, &fu_end));
            // Second picture: P-frame on seq 7
            media.extend_from_slice(&interleaved_rtp(0, 7, 19800, true, 7, 96, p_slice));
        }
        Scenario::MissingSpsPpsBudgetExhausted => {
            // 260 P-frames with zero SPS/PPS -> exceeds 256-packet pre-roll budget!
            for i in 0..260u16 {
                media.extend_from_slice(&interleaved_rtp(
                    0,
                    1 + i,
                    9000 + u32::from(i) * 3600,
                    true,
                    7,
                    96,
                    p_slice,
                ));
            }
        }
        Scenario::MidStreamSpsGenerationChange => {
            // 1 pre-sync P-frame, then STAP-A(SPS1+PPS1+IDR1) + P1, then mutated SPS2!
            media.extend_from_slice(&interleaved_rtp(0, 1, 9000, true, 7, 96, p_slice));
            let stap1 = stap_a(&[sps, pps, idr]);
            media.extend_from_slice(&interleaved_rtp(0, 2, 12600, true, 7, 96, &stap1));
            media.extend_from_slice(&interleaved_rtp(0, 3, 16200, true, 7, 96, p_slice));
            // Valid H.264 SPS with changed level_idc (byte 3) -> distinct parameter-set generation!
            let mut mutated_sps = sps.to_vec();
            mutated_sps[3] = if mutated_sps[3] == 0x1e { 0x1f } else { 0x1e };
            let stap2 = stap_a(&[&mutated_sps, pps, idr]);
            media.extend_from_slice(&interleaved_rtp(0, 4, 19800, true, 7, 96, &stap2));
        }
        Scenario::StrictDefaultRejectsMissingSprop => unreachable!(),
    }
    let _ = peer.write_all(&media);

    // Wait cleanly for TEARDOWN or client disconnect.
    for _ in 0..8 {
        let Some((method, _, cseq, _)) = read_rtsp_request(&mut peer)? else {
            return Ok(transcript);
        };
        transcript.methods.push(method.clone());
        if method == "TEARDOWN" {
            let _ = write_response_raw(&mut peer, cseq, b"Session: wyze-v4\r\n", b"");
            return Ok(transcript);
        }
    }
    Ok(transcript)
}

fn run_capture(
    listener: TcpListener,
    args: &[OsString],
    scenario: Scenario,
) -> Test<(Output, ServerTranscript)> {
    thread::scope(|scope| {
        let server = scope.spawn(move || serve_wyze(listener, scenario));
        let output = run_bin("capture", args);
        let server = server.join().map_err(|_| "server thread panicked")?;
        Ok((output?, server?))
    })
}

fn import_and_decode(dir: &TempDir, rows: &[Value], expected_frames: i128) -> Test {
    let window = row_detail(rows, "window_durable")?;
    let deployment = dir.0.join("deployment");
    let mut args: Vec<OsString> = [
        "--archive",
        dir.root().to_str().ok_or("archive path")?,
        "--root",
        deployment.to_str().ok_or("deployment path")?,
        "--site",
        SITE,
        "--window-slot",
        text(window, "slot")?,
        "--window-root",
        text(window, "root")?,
        "--codec",
        "avc",
        "--sensor-id",
        SENSOR,
        "--stream-id",
        STREAM,
        "--generation",
        "1",
        "--anchor",
        &digest("wyze authority anchor"),
        "--receive-clock",
        &digest("wyze receive clock"),
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
    let preview = parse(&ok_stdout(run_bin("import", &args)?)?)?;
    args.push(OsString::from("--approve"));
    args.push(OsString::from(text(&preview, "approval_digest")?));
    let imported = parse(&ok_stdout(run_bin("import", &args)?)?)?;
    assert_eq!(integer(&imported, "frames")?, expected_frames);
    let import_id = text(&imported, "import_identity")?.to_owned();

    let common: Vec<OsString> = [
        "--root",
        deployment.to_str().ok_or("deployment path")?,
        "--site",
        SITE,
        "--import-id",
        &import_id,
    ]
    .into_iter()
    .map(OsString::from)
    .collect();

    let mut verify = vec![OsString::from("verify")];
    verify.extend(common.clone());
    let verified = ok_stdout(run_bin("file", &verify)?)?;
    assert!(verified.contains("media_format=mp4avc"), "{verified}");
    assert!(
        verified.contains(&format!("segment_count={expected_frames}")),
        "{verified}"
    );

    let mut decode = vec![OsString::from("decode")];
    decode.extend(common);
    decode.extend(
        [
            "--segment",
            "0",
            "--segment-count",
            &expected_frames.to_string(),
            "--interpretation",
            "ycbcr",
            "--work-units",
            "1000000000",
        ]
        .into_iter()
        .map(OsString::from),
    );
    let decoded = ok_stdout(run_bin("file", &decode)?)?;
    assert!(
        decoded
            .lines()
            .any(|line| line == format!("h264_frames_decoded={expected_frames}")),
        "{decoded}"
    );
    assert!(
        decoded.lines().any(|line| line == "decode_complete=true"),
        "{decoded}"
    );
    Ok(())
}

#[test]
fn wyze_smolrtsp_inband_stap_a_and_companion_audio_decodes_cleanly() -> Test {
    let dir = TempDir::new("stap-a-companion")?;
    let (listener, addr) = bind_loopback()?;
    let args = base_capture_args(
        &dir,
        addr,
        "7",
        "2",
        &[
            ("--allow-inband-parameter-sets", "yes"),
            ("--setup-companion-tracks", "yes"),
        ],
    )?;
    let (output, transcript) = run_capture(listener, &args, Scenario::WyzeStapAWithCompanionAudio)?;
    assert!(
        output.status.success(),
        "capture failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        transcript.methods,
        vec!["DESCRIBE", "SETUP", "SETUP", "PLAY", "TEARDOWN"]
    );
    assert_eq!(transcript.setup_uris.len(), 2);

    let rows = parse_rows(&output)?;
    let terminal = row_detail(&rows, "terminal")?;
    assert!(boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "parameter_set_origin")?, "inband_rtp");
    assert_eq!(integer(terminal, "pre_sync_discarded")?, 3);
    assert!(
        integer(terminal, "companion_packets_discarded")? >= 4,
        "expected companion audio packets drained: {terminal:?}"
    );
    assert_eq!(integer(terminal, "durable_pictures")?, 2);
    assert_eq!(integer(terminal, "durable_windows")?, 1);

    import_and_decode(&dir, &rows, 2)?;
    Ok(())
}

#[test]
fn wyze_inband_separate_sps_pps_and_fu_a_idr_decodes_cleanly() -> Test {
    let dir = TempDir::new("separate-fu-a")?;
    let (listener, addr) = bind_loopback()?;
    let args = base_capture_args(
        &dir,
        addr,
        "auto",
        "2",
        &[("--allow-inband-parameter-sets", "yes")],
    )?;
    let (output, _transcript) = run_capture(listener, &args, Scenario::SeparateSpsPpsAndFuAIdr)?;
    assert!(
        output.status.success(),
        "capture failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let rows = parse_rows(&output)?;
    let terminal = row_detail(&rows, "terminal")?;
    assert!(boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "parameter_set_origin")?, "inband_rtp");
    assert_eq!(integer(terminal, "pre_sync_discarded")?, 2);
    assert_eq!(integer(terminal, "durable_pictures")?, 2);
    assert_eq!(integer(terminal, "durable_windows")?, 1);

    import_and_decode(&dir, &rows, 2)?;
    Ok(())
}

#[test]
fn inband_missing_sps_pps_exhausts_budget_and_fails_closed() -> Test {
    let dir = TempDir::new("budget-exhausted")?;
    let (listener, addr) = bind_loopback()?;
    let args = base_capture_args(
        &dir,
        addr,
        "7",
        "2",
        &[("--allow-inband-parameter-sets", "yes")],
    )?;
    let (output, _transcript) =
        run_capture(listener, &args, Scenario::MissingSpsPpsBudgetExhausted)?;
    assert!(!output.status.success());
    let rows = parse_rows(&output)?;
    let terminal = row_detail(&rows, "terminal")?;
    assert!(!boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "error_id")?, "ERR-CAPTURE-RTSP-SOURCE-001");
    assert_eq!(integer(terminal, "durable_windows")?, 0);
    assert!(matches!(
        value(terminal, "parameter_set_origin")?,
        Value::Null
    ));
    assert_eq!(integer(terminal, "pre_sync_discarded")?, 256);
    Ok(())
}

#[test]
fn inband_mid_stream_sps_change_fences_generation_boundary() -> Test {
    let dir = TempDir::new("midstream-sps-change")?;
    let (listener, addr) = bind_loopback()?;
    let args = base_capture_args(
        &dir,
        addr,
        "7",
        "3",
        &[("--allow-inband-parameter-sets", "yes")],
    )?;
    let (output, _transcript) =
        run_capture(listener, &args, Scenario::MidStreamSpsGenerationChange)?;
    assert!(!output.status.success());
    let rows = parse_rows(&output)?;
    let terminal = row_detail(&rows, "terminal")?;
    assert!(!boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "error_id")?, "ERR-CAPTURE-RTSP-SOURCE-001");
    assert_eq!(text(terminal, "parameter_set_origin")?, "inband_rtp");
    assert_eq!(integer(terminal, "pre_sync_discarded")?, 1);
    assert!(integer(terminal, "durable_pictures")? < 3);
    Ok(())
}

#[test]
fn non_utf8_latin1_vendor_headers_parsed_safely() -> Test {
    let dir = TempDir::new("latin1-headers")?;
    let (listener, addr) = bind_loopback()?;
    let args = base_capture_args(
        &dir,
        addr,
        "7",
        "2",
        &[
            ("--allow-inband-parameter-sets", "yes"),
            ("--setup-companion-tracks", "yes"),
        ],
    )?;
    let (output, transcript) = run_capture(listener, &args, Scenario::Latin1VendorHeaders)?;
    assert!(
        output.status.success(),
        "Latin-1 header capture failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(transcript.methods.contains(&"TEARDOWN".to_owned()));
    let rows = parse_rows(&output)?;
    let terminal = row_detail(&rows, "terminal")?;
    assert!(boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "parameter_set_origin")?, "inband_rtp");
    import_and_decode(&dir, &rows, 2)?;
    Ok(())
}

#[test]
fn strict_default_mode_still_rejects_sdp_without_sprop_parameter_sets() -> Test {
    let dir = TempDir::new("strict-default")?;
    let (listener, addr) = bind_loopback()?;
    let args = base_capture_args(&dir, addr, "7", "2", &[])?;
    let (output, transcript) =
        run_capture(listener, &args, Scenario::StrictDefaultRejectsMissingSprop)?;
    assert!(!output.status.success());
    assert_eq!(transcript.methods, vec!["DESCRIBE"]);
    let rows = parse_rows(&output)?;
    let terminal = row_detail(&rows, "terminal")?;
    assert!(!boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "error_id")?, "ERR-CAPTURE-RTSP-SOURCE-001");
    assert_eq!(integer(terminal, "durable_windows")?, 0);
    Ok(())
}
