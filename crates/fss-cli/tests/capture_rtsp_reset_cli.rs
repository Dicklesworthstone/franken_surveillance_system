#![forbid(unsafe_code)]
#![feature(tcp_linger)]
//! Real capture process, real loopback RST, independent pins and cold source replay.

use fss_cli::json_input::{Value, parse};
use fss_core::{ContentDigest, SensorId, StreamId};
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::rtsp::recording::{RecordingScope, local::load_recording};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

type Test<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const SDP: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\na=control:trackID=0\r\n";
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        for _ in 0..256 {
            let path = std::env::temp_dir().join(format!(
                "fss-reset-cli-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory bound".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn field<'a>(object: &'a Value, name: &str) -> Test<&'a Value> {
    object
        .object()
        .and_then(|fields| fields.get(name))
        .ok_or_else(|| format!("missing {name}").into())
}
fn text<'a>(object: &'a Value, name: &str) -> Test<&'a str> {
    field(object, name)?
        .text()
        .ok_or_else(|| format!("non-text {name}").into())
}
fn request(peer: &mut TcpStream) -> Test<(String, u32)> {
    let mut bytes = Vec::new();
    for _ in 0..8192 {
        let mut byte = [0];
        peer.read_exact(&mut byte)?;
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            let request = String::from_utf8(bytes)?;
            assert!(!request.to_ascii_lowercase().contains("authorization:"));
            let method = request
                .split_ascii_whitespace()
                .next()
                .ok_or("method")?
                .to_owned();
            let cseq = request
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("CSeq").then_some(value.trim())
                })
                .ok_or("cseq")?
                .parse()?;
            return Ok((method, cseq));
        }
    }
    Err("request byte bound".into())
}
fn camera(listener: TcpListener, video: Vec<u8>) -> Test {
    let deadline = Instant::now() + Duration::from_secs(8);
    let (mut peer, _) = loop {
        match listener.accept() {
            Ok(peer) => break peer,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(e) => return Err(e.into()),
        }
    };
    peer.set_read_timeout(Some(Duration::from_secs(3)))?;
    peer.set_write_timeout(Some(Duration::from_secs(3)))?;
    peer.set_nodelay(true)?;
    for (expected, headers, body) in [
        ("DESCRIBE", "Content-Type: application/sdp\r\n", SDP),
        (
            "SETUP",
            "Session: reset;timeout=1\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n",
            "",
        ),
        ("PLAY", "Session: reset\r\n", ""),
    ] {
        let (method, cseq) = request(&mut peer)?;
        assert_eq!(method, expected);
        write!(
            peer,
            "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}",
            body.len()
        )?;
    }
    peer.write_all(&video)?;
    // Observe a real post-media keepalive rather than using a guessed delay to
    // race collection. Its unresolved remote outcome must not enable reconnect.
    assert_eq!(request(&mut peer)?.0, "OPTIONS");
    peer.set_linger(Some(Duration::ZERO))?;
    drop(peer);
    Ok(())
}
fn read_output(reader: impl Read) -> Test<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(262_145).read_to_end(&mut bytes)?;
    if bytes.len() > 262_144 {
        return Err("process output bound".into());
    }
    Ok(bytes)
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

// Independent packetizer; no recording or capture implementation participates in
// constructing the source sent to the child process.
fn reset_video(fragmented: bool) -> Test<Vec<u8>> {
    let source = nals();
    let sps = source.first().ok_or("fixture SPS")?;
    let mut output = Vec::new();
    let mut sequence = 0_u16;
    let mut append = |payload: &[u8], marker: bool| -> Test {
        let mut packet = vec![0x80, 96 | if marker { 128 } else { 0 }];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&90_000_u32.to_be_bytes());
        packet.extend_from_slice(&7_u32.to_be_bytes());
        packet.extend_from_slice(payload);
        output.extend_from_slice(&[b'$', 0]);
        output.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
        output.extend_from_slice(&packet);
        sequence = sequence.checked_add(1).ok_or("fixture sequence overflow")?;
        Ok(())
    };
    append(sps, false)?; // probation, not selected recording source
    for nal in source {
        let picture = matches!(nal[0] & 31, 1 | 5);
        if picture && fragmented {
            let third = (nal.len() - 1) / 3;
            for (i, body) in [
                &nal[1..1 + third],
                &nal[1 + third..1 + 2 * third],
                &nal[1 + 2 * third..],
            ]
            .into_iter()
            .enumerate()
            {
                let mut payload = vec![
                    (nal[0] & 0x60) | 28,
                    (nal[0] & 31)
                        | if i == 0 {
                            128
                        } else if i == 2 {
                            64
                        } else {
                            0
                        },
                ];
                payload.extend_from_slice(body);
                append(&payload, i == 2)?;
            }
        } else {
            append(nal, picture)?;
        }
        if picture {
            assert_eq!(nal[0] & 31, 5, "fixture must start at an IDR");
            return Ok(output);
        }
    }
    Err("fixture IDR missing".into())
}

#[test]
fn interrupted_capture_publishes_its_prefix_but_exits_unsuccessfully_without_retry() -> Test {
    for fragmented in [false, true] {
        let directory = Directory::new()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let peer = listener.local_addr()?;
        let root = directory.0.join("media");
        let pins = directory.0.join("pins");
        let digest = |s: &str| ContentDigest::sha256(s.as_bytes()).to_text();
        let mut args: Vec<OsString> = [
            ("--root", root.display().to_string()),
            ("--pins", pins.display().to_string()),
            ("--peer", peer.to_string()),
            ("--authority", peer.to_string()),
            ("--presentation", "/live/".into()),
            ("--control-root", "/live".into()),
            ("--sensor-id", "sensor:reset-cli".into()),
            ("--stream-id", "stream:reset-cli".into()),
            ("--generation", "1".into()),
            ("--ingress", "71".into()),
            ("--ssrc", "7".into()),
            ("--anchor", digest("reset authority")),
            ("--receive-clock", digest("reset receive clock")),
            ("--timing-evidence", digest("explicit reset cadence")),
            ("--journal-id", digest("reset pins")),
            ("--frame-duration-ticks", "3600".into()),
            ("--stop-after-pictures", "10".into()),
            ("--owner-authorized", "yes".into()),
            ("--plaintext", "yes".into()),
            ("--retain-originals", "yes".into()),
            ("--timeout-ms", "5000".into()),
            ("--drain-timeout-ms", "5000".into()),
            ("--response-timeout-ms", "1000".into()),
            ("--max-report-bytes", "131072".into()),
        ]
        .into_iter()
        .flat_map(|(k, v)| [OsString::from(k), OsString::from(v)])
        .collect();
        let binary = std::env::var_os("FSS_CAPTURE_RTSP_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_fss-capture-rtsp")));
        let plan = Command::new(&binary).args(&args).output()?;
        assert!(
            plan.status.success(),
            "{}",
            String::from_utf8_lossy(&plan.stderr)
        );
        let plan = parse(std::str::from_utf8(&plan.stdout)?)?;
        args.extend([
            OsString::from("--approve"),
            OsString::from(text(&plan, "approval")?),
        ]);
        let video = reset_video(fragmented)?;
        let (status, stdout, stderr) = std::thread::scope(|scope| -> Test<_> {
            let camera = scope.spawn(move || camera(listener, video));
            let mut child = Command::new(&binary)
                .args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            let out = child.stdout.take().ok_or("stdout")?;
            let err = child.stderr.take().ok_or("stderr")?;
            let out = scope.spawn(move || read_output(out));
            let err = scope.spawn(move || read_output(err));
            let deadline = Instant::now() + Duration::from_secs(12);
            let status = loop {
                if let Some(status) = child.try_wait()? {
                    break status;
                }
                if Instant::now() >= deadline {
                    child.kill()?;
                    child.wait()?;
                    return Err("capture process deadline".into());
                }
                std::thread::sleep(Duration::from_millis(2));
            };
            camera.join().map_err(|_| "camera fixture panicked")??;
            Ok((
                status,
                out.join().map_err(|_| "stdout reader panicked")??,
                err.join().map_err(|_| "stderr reader panicked")??,
            ))
        })?;
        assert!(!status.success());
        let stdout = std::str::from_utf8(&stdout)?;
        let rows: Vec<_> = stdout.lines().map(parse).collect::<Result<_, _>>()?;
        let find = |kind: &str| -> Test<&Value> {
            rows.iter()
                .find(|row| text(row, "kind").ok() == Some(kind))
                .ok_or_else(|| {
                    format!(
                        "missing {kind}: {stdout}; stderr={}",
                        String::from_utf8_lossy(&stderr)
                    )
                    .into()
                })
        };
        let interrupted = field(find("source_interrupted")?, "detail")?;
        assert_eq!(
            field(interrupted, "capture_complete")?.boolean(),
            Some(false)
        );
        let terminal = field(find("terminal")?, "detail")?;
        assert_eq!(text(terminal, "error_id")?, "ERR-CAPTURE-RTSP-SOURCE-001");
        for flag in ["complete", "peer_eof", "input_end_observed"] {
            assert_eq!(field(terminal, flag)?.boolean(), Some(false));
        }
        for counter in [
            "collected_pictures",
            "durable_pictures",
            "durable_windows",
            "indexed_windows",
        ] {
            assert_eq!(field(terminal, counter)?.integer(), Some(1));
        }
        // Media can be durable while the last remote command remains unresolved.
        // Preserve the existing terminal vocabulary rather than upgrading its outcome.
        assert_eq!(field(terminal, "unsettled_request")?.boolean(), Some(true));
        assert_eq!(field(terminal, "connections_retried")?.integer(), Some(0));
        assert_eq!(
            field(terminal, "unpublished_prepared_pictures")?.integer(),
            Some(0)
        );
        let _ = ContentDigest::parse(text(terminal, "snapshot_digest")?)?;
        let window = field(find("window_durable")?, "detail")?;
        let _ = find("catalog_published")?;
        let publisher = LocalRootPublisher::open(
            &root,
            LocalPublicationLimits::new(
                128,
                1024,
                128,
                1024,
                SpoolLimits::new(1024, 16 * 1024 * 1024, 2 * 1024 * 1024, 1024),
            ),
        )?;
        let recording = load_recording(
            &publisher,
            &SlotName::parse(text(window, "slot")?)?,
            ContentDigest::parse(text(window, "root")?)?,
            &RecordingScope {
                sensor: SensorId::parse("sensor:reset-cli")?,
                stream: StreamId::parse("stream:reset-cli")?,
                generation: 1,
                anchor: ContentDigest::sha256(b"reset authority"),
                receive_clock: ContentDigest::sha256(b"reset receive clock"),
            },
            &NeverCancel,
        )?;
        assert_eq!(recording.summary().samples, 1);
    }
    Ok(())
}
