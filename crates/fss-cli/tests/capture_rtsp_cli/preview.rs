#![forbid(unsafe_code)]
//! Real loopback viewers consume only durable native capture windows.
//!
//! The camera pauses at an explicit source boundary while clients inspect the
//! gateway. It resumes only after those checks, without closing its write side.
//! This tests native wiring and containment, not browser decoder qualification.

use super::*;
use fss_container::demux::{AvcMp4, DemuxLimits, VideoCodec};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::process::Child;
use std::sync::mpsc::{self, Receiver, SyncSender};

const OUTPUT_BOUND: u64 = 1024 * 1024;
const HTTP_BOUND: usize = 1024 * 1024;
const CAMERA_WAIT: Duration = Duration::from_secs(10);

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

    fn media_codec(self) -> VideoCodec {
        match self {
            Self::Avc => VideoCodec::Avc,
            Self::Hevc => VideoCodec::Hevc,
        }
    }

    fn description(self) -> String {
        match self {
            Self::Avc => SDP.to_owned(),
            Self::Hevc => concat!(
                "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\n",
                "m=video 0 RTP/AVP 98\r\na=rtpmap:98 H265/90000\r\n",
                "a=fmtp:98 sprop-vps=QAEMAf//AWAAAAMAkAAAAwAAAwAeugJA;",
                "sprop-sps=QgEBAWAAAAMAkAAAAwAAAwAeoCCDHVZbpKTC8BaAgAAAAwCAAAADAoQ=;",
                "sprop-pps=RAHAc8CJ\r\na=control:trackID=0\r\n"
            )
            .to_owned(),
        }
    }

    fn options(self, directory: &Directory, address: SocketAddr) -> Test<Vec<OsString>> {
        let mut options = args(directory, address, 4);
        replace(&mut options, "--max-window-pictures", "2")?;
        replace(&mut options, "--timeout-ms", "15000")?;
        if matches!(self, Self::Hevc) {
            replace(&mut options, "--frame-duration-ticks", "18000")?;
            replace(
                &mut options,
                "--timing-evidence",
                &digest("owner asserted fixed 5fps HEVC cadence"),
            )?;
            options.extend([
                "--codec".into(),
                "hevc".into(),
                "--payload-type".into(),
                "98".into(),
            ]);
        }
        options.extend([
            "--preview-port".into(),
            "0".into(),
            "--allow-local-unredacted-preview".into(),
            "yes".into(),
            "--preview-max-clients".into(),
            "3".into(),
            "--preview-max-bytes".into(),
            "4194304".into(),
            "--preview-max-fragment-bytes".into(),
            "1048576".into(),
            "--preview-max-output-bytes".into(),
            "4194304".into(),
            "--preview-max-age-ms".into(),
            "10000".into(),
        ]);
        approve(&options)
    }
}

struct Camera {
    codec: Codec,
    before_inspection: Vec<u8>,
    after_inspection: Vec<u8>,
}

fn interleaved(sequence: u16, timestamp: u32, nal: &[u8]) -> Test<Vec<u8>> {
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

fn hevc_nals() -> Test<Vec<Vec<u8>>> {
    include_str!("../../../../tests/fixtures/media/hevc/remux_main8.nals.hex")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            if !line.is_ascii() || line.len() % 2 != 0 {
                return Err("invalid pinned HEVC source fixture".into());
            }
            (0..line.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&line[at..at + 2], 16).map_err(Into::into))
                .collect()
        })
        .collect()
}

impl Camera {
    fn new(codec: Codec, publish: bool) -> Test<Self> {
        let malformed = vec![b'$', 0, 0, 4, 0x80, 96, 0, 99];
        let (before_inspection, after_inspection) = match codec {
            Codec::Avc if publish => {
                let wire = video(4, 3600, 96, true)?;
                let mut at = 0;
                let mut pictures = 0;
                while at < wire.len() && pictures < 3 {
                    let size = usize::from(u16::from_be_bytes([
                        *wire.get(at + 2).ok_or("missing RTP size")?,
                        *wire.get(at + 3).ok_or("missing RTP size")?,
                    ]));
                    let nal = *wire.get(at + 16).ok_or("missing AVC NAL")?;
                    pictures += usize::from(matches!(nal & 31, 1 | 5));
                    at = at.checked_add(4 + size).ok_or("fixture size overflow")?;
                }
                if pictures != 3 || at >= wire.len() {
                    return Err("missing staged AVC IDR boundary".into());
                }
                (wire[..at].to_vec(), wire[at..].to_vec())
            }
            Codec::Avc => (video(2, 3600, 96, false)?, malformed),
            Codec::Hevc => {
                let nals = hevc_nals()?;
                if nals.len() != 10 {
                    return Err("unexpected pinned HEVC picture groups".into());
                }
                // RTP probation is explicit and is not selected recording source.
                let mut before = interleaved(0, 0, &nals[0])?;
                let times = [0, 0, 0, 0, 18_000, 36_000, 36_000, 36_000, 36_000, 54_000];
                let count = if publish { 10 } else { 5 };
                for (index, (nal, time)) in nals.iter().zip(times).take(count).enumerate() {
                    before.extend(interleaved(u16::try_from(index + 1)?, time, nal)?);
                }
                // The final source EOS closes the last P picture. It is neither
                // transport EOF nor an invented marker-based picture boundary.
                let after = if publish {
                    interleaved(11, 54_000, &[0x48, 1, 0x80])?
                } else {
                    malformed
                };
                (before, after)
            }
        };
        Ok(Self {
            codec,
            before_inspection,
            after_inspection,
        })
    }

    fn serve(self, listener: TcpListener, ready: SyncSender<()>, resume: Receiver<()>) -> Test {
        let deadline = Instant::now() + CAMERA_WAIT;
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
        peer.set_read_timeout(Some(CAMERA_WAIT))?;
        peer.set_write_timeout(Some(CAMERA_WAIT))?;
        peer.set_nodelay(true)?;
        for expected in ["DESCRIBE", "SETUP", "PLAY"] {
            let (method, cseq) = request(&mut peer)?.ok_or("capture closed during negotiation")?;
            assert_eq!(method, expected);
            match expected {
                "DESCRIBE" => response(
                    &mut peer,
                    cseq,
                    "Content-Type: application/sdp\r\n",
                    &self.codec.description(),
                )?,
                "SETUP" => response(
                    &mut peer,
                    cseq,
                    "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n",
                    "",
                )?,
                _ => response(&mut peer, cseq, "Session: fixture\r\n", "")?,
            }
        }
        peer.write_all(&self.before_inspection)?;
        ready.send(())?;
        resume.recv_timeout(CAMERA_WAIT)?;
        peer.write_all(&self.after_inspection)?;
        for _ in 0..16 {
            let Some((method, cseq)) = request(&mut peer)? else {
                return Ok(());
            };
            if !matches!(method.as_str(), "TEARDOWN" | "GET_PARAMETER" | "OPTIONS") {
                return Err("unexpected native control after preview inspection".into());
            }
            response(&mut peer, cseq, "Session: fixture\r\n", "")?;
        }
        Err("preview camera control allowance exhausted".into())
    }
}

// Deliberately no Debug implementation: the short-lived preview credential
// must not enter test diagnostics, even when the native process fails.
struct Endpoint {
    address: SocketAddr,
    authority: String,
    token: String,
}

impl Endpoint {
    fn parse(line: &str) -> Test<Option<Self>> {
        let Some(url) = line.strip_prefix("FSS live preview: ") else {
            return Ok(None);
        };
        let url = url.trim_end_matches(['\r', '\n']);
        let (base, fragment) = url.split_once('#').ok_or("preview URL has no fragment")?;
        let authority = base
            .strip_prefix("http://")
            .and_then(|base| base.strip_suffix('/'))
            .ok_or("unexpected preview origin")?;
        let address: SocketAddr = authority.parse()?;
        if address.ip() != std::net::IpAddr::V4(Ipv4Addr::LOCALHOST) || address.port() == 0 {
            return Err("preview did not bind an assigned IPv4 loopback port".into());
        }
        let token = fragment;
        if token.len() != 32
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("preview credential is not the declared 128-bit session token".into());
        }
        Ok(Some(Self {
            address,
            authority: authority.to_owned(),
            token: token.to_owned(),
        }))
    }

    fn connect(&self) -> Test<TcpStream> {
        let stream = TcpStream::connect_timeout(&self.address, Duration::from_secs(2))?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        Ok(stream)
    }

    fn get(&self, path: &str, token: bool, read: bool, origin: Option<&str>) -> Test<Http> {
        let mut stream = self.connect()?;
        let mut request = format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            self.authority
        );
        if token {
            request.push_str(&format!("X-FSS-Preview: {}\r\n", self.token));
        }
        if read {
            request.push_str("X-FSS-Read: 1\r\n");
        }
        if let Some(origin) = origin {
            request.push_str(&format!("Origin: {origin}\r\n"));
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes())?;
        let mut bytes = Vec::new();
        stream
            .take(u64::try_from(HTTP_BOUND)? + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > HTTP_BOUND {
            return Err("preview HTTP response exceeded the fixture bound".into());
        }
        if bytes
            .windows(self.token.len())
            .any(|bytes| bytes == self.token.as_bytes())
        {
            return Err("preview HTTP response disclosed its session credential".into());
        }
        Http::parse(bytes)
    }

    fn manifest(&self) -> Test<Value> {
        let response = self.get("/api/manifest", true, true, None)?;
        assert_eq!(response.status, 200);
        parse(std::str::from_utf8(&response.body)?).map_err(Into::into)
    }
}

struct Http {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl Http {
    fn parse(bytes: Vec<u8>) -> Test<Self> {
        let boundary = bytes
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .ok_or("incomplete preview HTTP header")?;
        let header = std::str::from_utf8(&bytes[..boundary])?;
        let mut lines = header.split("\r\n");
        let status: u16 = lines
            .next()
            .and_then(|line| line.split_ascii_whitespace().nth(1))
            .ok_or("missing preview HTTP status")?
            .parse()?;
        let mut headers = BTreeMap::new();
        for line in lines {
            let (key, value) = line.split_once(':').ok_or("invalid preview HTTP field")?;
            if headers
                .insert(key.to_ascii_lowercase(), value.trim().to_owned())
                .is_some()
            {
                return Err("duplicate preview HTTP header".into());
            }
        }
        let body = bytes[boundary + 4..].to_vec();
        let declared: usize = headers
            .get("content-length")
            .ok_or("preview response has no exact length")?
            .parse()?;
        assert_eq!(declared, body.len());
        assert_eq!(
            headers.get("cache-control").map(String::as_str),
            Some("no-store")
        );
        Ok(Self {
            status,
            headers,
            body,
        })
    }
}

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn read_stderr(
    reader: impl Read,
    endpoint: SyncSender<Endpoint>,
    output_limit: &AtomicBool,
) -> Test<Vec<u8>> {
    let mut reader = BufReader::new(reader.take(OUTPUT_BOUND + 1));
    let mut bytes = Vec::new();
    let mut announcements = 0;
    loop {
        let start = bytes.len();
        let count = reader.read_until(b'\n', &mut bytes)?;
        if count == 0 {
            return Ok(bytes);
        }
        if bytes.len() as u64 > OUTPUT_BOUND {
            output_limit.store(true, Ordering::Release);
            return Err("preview process stderr exceeded its bound".into());
        }
        if let Some(parsed) = Endpoint::parse(std::str::from_utf8(&bytes[start..])?)? {
            announcements += 1;
            if announcements != 1 {
                return Err("preview session credential was announced repeatedly".into());
            }
            endpoint
                .try_send(parsed)
                .map_err(|_| "preview URL owner is unavailable")?;
        }
    }
}

fn while_capturing<T>(
    listener: TcpListener,
    options: &[OsString],
    camera: Camera,
    inspect: impl FnOnce(&Endpoint) -> Test<T>,
) -> Test<(Output, T)> {
    let output_limit = AtomicBool::new(false);
    thread::scope(|scope| {
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (resume_tx, resume_rx) = mpsc::sync_channel(1);
        let (endpoint_tx, endpoint_rx) = mpsc::sync_channel(1);
        let server = scope.spawn(move || camera.serve(listener, ready_tx, resume_rx));
        let mut child = OwnedChild(
            Command::new(binary("capture")?)
                .args(options)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?,
        );
        let stdout = child
            .0
            .stdout
            .take()
            .ok_or("missing preview child stdout")?;
        let stderr = child
            .0
            .stderr
            .take()
            .ok_or("missing preview child stderr")?;
        let limit = &output_limit;
        let stdout = scope.spawn(move || output_bytes(stdout, limit));
        let stderr = scope.spawn(move || read_stderr(stderr, endpoint_tx, limit));
        let endpoint = endpoint_rx.recv_timeout(CAMERA_WAIT)?;
        ready_rx.recv_timeout(CAMERA_WAIT)?;
        let inspected = inspect(&endpoint);
        // Always release the bounded camera even after an HTTP assertion returns
        // an error, then collect the process and both output owners.
        let resumed = resume_tx.send(());
        let deadline = Instant::now() + CAMERA_WAIT;
        let status = loop {
            if output_limit.load(Ordering::Acquire) {
                return Err("preview process output bound exceeded".into());
            }
            match child.0.try_wait()? {
                Some(status) => break status,
                None if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
                None => return Err("preview or partial client prevented native closure".into()),
            }
        };
        let stdout = stdout
            .join()
            .map_err(|_| "preview stdout owner panicked")??;
        let stderr = stderr
            .join()
            .map_err(|_| "preview stderr owner panicked")??;
        let served = server.join().map_err(|_| "preview camera owner panicked")?;
        let inspected = inspected?;
        resumed?;
        served?;
        assert!(
            !stdout
                .windows(endpoint.token.len())
                .any(|bytes| bytes == endpoint.token.as_bytes()),
            "preview credential entered JSONL"
        );
        assert!(
            TcpStream::connect_timeout(&endpoint.address, Duration::from_millis(250)).is_err(),
            "preview listener outlived the native capture task"
        );
        Ok((
            Output {
                status,
                stdout,
                stderr,
            },
            inspected,
        ))
    })
}

fn latest(manifest: &Value) -> Test<Option<&Value>> {
    assert_eq!(text(manifest, "schema")?, "fss.live-preview.v1");
    match value(manifest, "latest")? {
        Value::Null => {
            assert_eq!(text(manifest, "state")?, "waiting");
            Ok(None)
        }
        window => {
            assert_eq!(text(manifest, "state")?, "ready");
            if window.object().is_none() {
                return Err("preview latest window is not an object".into());
            }
            Ok(Some(window))
        }
    }
}

#[test]
fn authenticated_viewers_share_durable_native_fragments_without_blocking_capture() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        let directory = Directory::new(&format!("preview-{}", codec.name()))?;
        let listener = listener()?;
        let options = codec.options(&directory, listener.local_addr()?)?;
        let (output, root) =
            while_capturing(listener, &options, Camera::new(codec, true)?, |endpoint| {
                assert_eq!(
                    endpoint.get("/api/manifest", false, true, None)?.status,
                    403
                );
                assert_eq!(
                    endpoint.get("/api/manifest", true, false, None)?.status,
                    403
                );
                assert_eq!(
                    endpoint
                        .get(
                            "/api/manifest",
                            true,
                            true,
                            Some("https://untrusted.invalid")
                        )?
                        .status,
                    403
                );
                let mut wrong_token = endpoint.token.clone();
                wrong_token.replace_range(
                    ..1,
                    if endpoint.token.starts_with('0') {
                        "1"
                    } else {
                        "0"
                    },
                );
                let unauthorized = Endpoint {
                    address: endpoint.address,
                    authority: endpoint.authority.clone(),
                    token: wrong_token,
                };
                assert_eq!(
                    unauthorized.get("/api/manifest", true, true, None)?.status,
                    403
                );
                let deadline = Instant::now() + Duration::from_secs(5);
                let manifest = loop {
                    let manifest = endpoint.manifest()?;
                    if latest(&manifest)?.is_some() {
                        break manifest;
                    }
                    if Instant::now() >= deadline {
                        return Err("durable source window never reached live preview".into());
                    }
                    thread::sleep(Duration::from_millis(2));
                };
                let window = latest(&manifest)?.ok_or("missing preview window")?;
                let sequence = integer(window, "sequence")?;
                let root = ContentDigest::parse(text(window, "root")?)?;
                assert_eq!(text(window, "codec")?, codec.name());
                assert_eq!(integer(window, "samples")?, 2);
                assert_eq!(integer(window, "time_scale")?, 90_000);
                let initialization = usize::try_from(integer(window, "initialization_bytes")?)?;
                let media_bytes = usize::try_from(integer(window, "media_bytes")?)?;
                let initialization_digest =
                    ContentDigest::parse(text(window, "initialization_digest")?)?;
                let media_digest = ContentDigest::parse(text(window, "media_digest")?)?;
                let path = format!("/api/window/{sequence}");

                // Keep one HTTP request deliberately incomplete while both ordinary
                // viewers finish. Neither archive progress nor a peer may wait for it.
                let mut partial = endpoint.connect()?;
                partial.write_all(b"GET /api/manifest HTTP/1.1\r\nHost: ")?;
                assert_eq!(endpoint.get(&path, false, true, None)?.status, 403);
                let first = endpoint.get(&path, true, true, None)?;
                let origin = format!("http://{}", endpoint.authority);
                let second = endpoint.get(&path, true, true, Some(&origin))?;
                assert_eq!((first.status, second.status), (200, 200));
                assert_eq!(
                    first.headers.get("content-type").map(String::as_str),
                    Some("video/mp4")
                );
                assert_eq!(
                    first.headers.get("x-fss-recording-root"),
                    Some(&root.to_text())
                );
                assert_eq!(
                    first.headers.get("x-fss-window-sequence"),
                    Some(&sequence.to_string())
                );
                assert!(
                    first.body == second.body,
                    "viewers received different media bytes"
                );
                assert_eq!(first.body.len(), initialization + media_bytes);
                let (init, fragment) = first.body.split_at(initialization);
                assert_eq!(ContentDigest::sha256(init), initialization_digest);
                assert_eq!(ContentDigest::sha256(fragment), media_digest);
                let media = AvcMp4::parse(&first.body, None, DemuxLimits::default())?;
                assert_eq!(media.codec(), codec.media_codec());
                assert_eq!(media.samples().len(), 2);
                assert!(
                    media
                        .samples()
                        .first()
                        .ok_or("preview has no samples")?
                        .contains_idr
                );
                assert_eq!(media.timescale(), 90_000);
                // Keep this connection owned until after capture exits, proving it
                // cannot require a viewer to finish its headers before shutdown.
                Ok((root, partial))
            })?;
        let (root, _partial) = root;
        assert!(
            output.status.success(),
            "native capture failed with live viewers"
        );
        let report = rows(&output)?;
        let terminal = detail(&report, "terminal")?;
        assert!(boolean(terminal, "complete")?);
        assert!(!boolean(terminal, "input_end_observed")?);
        assert_eq!(integer(terminal, "durable_pictures")?, 4);
        assert_eq!(integer(terminal, "durable_windows")?, 2);
        assert!(boolean(value(terminal, "runtime")?, "quiescent")?);
        let root_text = root.to_text();
        assert!(
            report.iter().any(|row| {
                text(row, "kind").ok() == Some("window_durable")
                    && value(row, "detail")
                        .and_then(|detail| text(detail, "root"))
                        .ok()
                        == Some(root_text.as_str())
            }),
            "preview advertised a root absent from durable capture receipts"
        );
    }
    Ok(())
}

#[test]
fn incomplete_source_is_never_advertised_as_an_available_preview_window() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        let directory = Directory::new(&format!("preview-pending-{}", codec.name()))?;
        let listener = listener()?;
        let options = codec.options(&directory, listener.local_addr()?)?;
        let (output, ()) =
            while_capturing(listener, &options, Camera::new(codec, false)?, |endpoint| {
                let manifest = endpoint.manifest()?;
                assert!(latest(&manifest)?.is_none());
                let fragment = endpoint.get("/api/window/0", true, true, None)?;
                assert_eq!(fragment.status, 404);
                assert!(!fragment.body.windows(4).any(|bytes| bytes == b"ftyp"));
                Ok(())
            })?;
        assert!(!output.status.success());
        let report = rows(&output)?;
        let terminal = detail(&report, "terminal")?;
        assert!(integer(terminal, "collected_pictures")? > 0);
        assert_eq!(integer(terminal, "durable_windows")?, 0);
        assert!(integer(terminal, "unsealed_rtp_bytes")? > 0);
        let runtime = value(terminal, "runtime")?;
        assert_eq!(text(runtime, "custody_state")?, "pending");
        assert!(!boolean(runtime, "quiescent")?);
        assert!(
            report
                .iter()
                .all(|row| text(row, "kind").ok() != Some("window_durable"))
        );
    }
    Ok(())
}
