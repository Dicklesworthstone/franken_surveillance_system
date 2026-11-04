#![forbid(unsafe_code)]
//! Actual operator CLI probing against bounded, owned loopback RTSP cameras.
//!
//! The cameras serve checked-in AVC/HEVC media and keep successful streams open
//! until the client acknowledges TEARDOWN and closes. These are wiring, approval,
//! observation and cleanup tests, not physical camera, retained custody or codec
//! qualification. No production credentials or external network are used.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use fss_cli::json_output::string;
use fss_core::ContentDigest;
use fss_core::json_input::{self, Value};
use fss_reference::site::{parse_manifest, parse_probe_receipts};

type Test<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const USERNAME: &str = "FSS_SITE_PROBE_SYNTHETIC_USER_CANARY";
const PASSWORD: &str = "FSS_SITE_PROBE_SYNTHETIC_PASSWORD_CANARY";
const REALM: &str = "FSS_SITE_PROBE_SYNTHETIC_REALM_CANARY";
const NONCE: &str = "FSS_SITE_PROBE_SYNTHETIC_NONCE_CANARY";
const PRIVATE_SDP: &str = "FSS_SITE_PROBE_PRIVATE_SDP_CANARY";
const PRIVATE_SERVER: &str = "FSS_SITE_PROBE_PRIVATE_SERVER_CANARY";
const PRIVATE_ROUTE: &str = "private-camera-route-canary";
const AVC_SPS: &str = "Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=";
const AVC_PPS: &str = "aM4PLIA=";
const HEVC_VPS: &str = "QAEMAf//AWAAAAMAkAAAAwAAAwAeugJA";
const HEVC_SPS: &str = "QgEBAWAAAAMAkAAAAwAAAwAeoCCDHVZbpKTC8BaAgAAAAwCAAAADAoQ=";
const HEVC_PPS: &str = "RAHAc8CJ";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-site-probe-cli-{}-{label}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("fixture directory allowance exhausted".into())
    }
    fn write(&self, name: &str, bytes: impl AsRef<[u8]>) -> Test<PathBuf> {
        let path = self.0.join(name);
        fs::write(&path, bytes)?;
        Ok(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binary() -> Test<PathBuf> {
    std::env::var_os("FSS_BIN")
        .map(PathBuf::from)
        .or_else(|| option_env!("CARGO_BIN_EXE_fss").map(PathBuf::from))
        .ok_or_else(|| "required fss binary unavailable; set FSS_BIN".into())
}

fn bounded_output(reader: impl Read, exceeded: &AtomicBool) -> io::Result<Vec<u8>> {
    const MAX_OUTPUT: u64 = 1024 * 1024;
    let mut bytes = Vec::new();
    reader.take(MAX_OUTPUT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_OUTPUT {
        exceeded.store(true, Ordering::Release);
        return Err(io::Error::other("CLI fixture output ceiling exceeded"));
    }
    Ok(bytes)
}

fn run_binary(path: &Path, args: &[OsString]) -> Test<Output> {
    let mut child = Command::new(path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("missing stdout pipe")?;
    let stderr = child.stderr.take().ok_or("missing stderr pipe")?;
    let exceeded = AtomicBool::new(false);
    thread::scope(|scope| {
        let stdout = scope.spawn(|| bounded_output(stdout, &exceeded));
        let stderr = scope.spawn(|| bounded_output(stderr, &exceeded));
        let deadline = Instant::now() + Duration::from_secs(15);
        let status = loop {
            if exceeded.load(Ordering::Acquire) || Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err("CLI fixture exceeded time or output allowance".into());
            }
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => thread::sleep(Duration::from_millis(2)),
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error.into());
                }
            }
        };
        let stdout = stdout.join().map_err(|_| "stdout reader panicked")??;
        let stderr = stderr.join().map_err(|_| "stderr reader panicked")??;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    })
}

fn run(args: &[OsString]) -> Test<Output> {
    run_binary(&binary()?, args)
}
fn good(output: Output) -> Test<Value> {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(json_input::parse(std::str::from_utf8(&output.stdout)?)?)
}
fn field<'a>(value: &'a Value, name: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|fields| fields.get(name))
        .ok_or_else(|| format!("missing field {name}").into())
}
fn text<'a>(value: &'a Value, name: &str) -> Test<&'a str> {
    field(value, name)?
        .text()
        .ok_or_else(|| format!("not text: {name}").into())
}
fn boolean(value: &Value, name: &str) -> Test<bool> {
    field(value, name)?
        .boolean()
        .ok_or_else(|| format!("not boolean: {name}").into())
}
fn integer(value: &Value, name: &str) -> Test<i128> {
    field(value, name)?
        .integer()
        .ok_or_else(|| format!("not integer: {name}").into())
}
fn render(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.clone(),
        Value::Text(value) => string(value),
        Value::Array(values) => format!(
            "[{}]",
            values.iter().map(render).collect::<Vec<_>>().join(",")
        ),
        Value::Object(fields) => format!(
            "{{{}}}",
            fields
                .iter()
                .map(|(key, value)| format!("{}:{}", string(key), render(value)))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}
fn set(value: &mut Value, name: &str, replacement: Value) -> Test {
    let Value::Object(fields) = value else {
        return Err("fixture object required".into());
    };
    let _ = fields.insert(name.to_owned(), replacement);
    Ok(())
}
fn replace(args: &mut [OsString], name: &str, value: impl Into<OsString>) -> Test {
    let at = args
        .iter()
        .position(|arg| arg == name)
        .ok_or("missing fixture option")?;
    *args.get_mut(at + 1).ok_or("missing fixture option value")? = value.into();
    Ok(())
}

struct Fixture {
    directory: Directory,
    manifest: Value,
}
impl Fixture {
    fn new(label: &str, peer: SocketAddr) -> Test<Self> {
        let directory = Directory::new(label)?;
        let manifest = json_input::parse(&format!(
            r#"{{"schema":"fss.site_camera_manifest.v1","site_id":"site:probe-cli","generation":1,"network_route":"lan","sources":[{{"source_id":"source:front","generation":1,"kind":"rtsp","peer":{},"authority":{},"presentation":"/camera/front/main","control_root":"/camera/front","stream_role":"main","authentication":null,"retention_class":"ordinary","rights_verdict_ref":"fldt:rights:test-lease","zones":[],"payment_masks":[],"max_connections":1,"owner_authorized":true,"plaintext":true,"retain_originals":true}}]}}"#,
            string(&peer.to_string()),
            string(&format!("{PRIVATE_ROUTE}.test:{}", peer.port()))
        ))?;
        Ok(Self {
            directory,
            manifest,
        })
    }
    fn source(&mut self) -> Test<&mut Value> {
        let Value::Object(fields) = &mut self.manifest else {
            return Err("manifest object".into());
        };
        let Some(Value::Array(sources)) = fields.get_mut("sources") else {
            return Err("manifest sources".into());
        };
        sources
            .first_mut()
            .ok_or_else(|| "fixture source missing".into())
    }
    fn authentication(&mut self, path: &Path) -> Test {
        let value = json_input::parse(&format!(
            r#"{{"credential_file":{},"realm":{},"legacy_md5":false,"legacy_no_qop":false}}"#,
            string(path.to_str().ok_or("UTF-8 credential path")?),
            string(REALM)
        ))?;
        set(self.source()?, "authentication", value)
    }
    fn write(&self) -> Test<PathBuf> {
        self.directory
            .write("manifest.json", render(&self.manifest))
    }
    fn args(&self, codec: Codec) -> Vec<OsString> {
        vec![
            "site".into(),
            "probe".into(),
            "--manifest".into(),
            self.directory.0.join("manifest.json").into_os_string(),
            "--source".into(),
            "source:front".into(),
            "--codec".into(),
            codec.name().into(),
            "--media-index".into(),
            "0".into(),
            "--payload-type".into(),
            codec.payload().to_string().into(),
            "--rtp-channel".into(),
            codec.channel().to_string().into(),
            "--observe-frames".into(),
            "3".into(),
            "--timeout-ms".into(),
            "3000".into(),
            "--principal".into(),
            "principal:probe-test".into(),
            "--json".into(),
        ]
    }
    fn approved(&self, codec: Codec) -> Test<Vec<OsString>> {
        let mut args = self.args(codec);
        let preview = good(run(&args)?)?;
        assert_eq!(text(&preview, "schema")?, "fss.site_probe_plan.v1");
        args.extend(["--approve".into(), text(&preview, "approval")?.into()]);
        Ok(args)
    }
    fn plan_args(&self, probes: &Path) -> Vec<OsString> {
        vec![
            "site".into(),
            "plan".into(),
            "--manifest".into(),
            self.directory.0.join("manifest.json").into_os_string(),
            "--probes".into(),
            probes.as_os_str().to_owned(),
            "--archive-root".into(),
            self.directory
                .0
                .join("archive-not-created")
                .into_os_string(),
            "--pins-root".into(),
            self.directory.0.join("pins-not-created").into_os_string(),
            "--epoch".into(),
            "9".into(),
            "--stop-after-pictures".into(),
            "2".into(),
            "--json".into(),
        ]
    }
}

#[derive(Clone, Copy, Debug)]
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
    fn payload(self) -> u8 {
        match self {
            Self::Avc => 96,
            Self::Hevc => 98,
        }
    }
    fn channel(self) -> u8 {
        match self {
            Self::Avc => 0,
            Self::Hevc => 2,
        }
    }
    fn cadence(self) -> u32 {
        match self {
            Self::Avc => 3600,
            Self::Hevc => 18000,
        }
    }
    fn description(self) -> String {
        let pt = self.payload();
        let attributes = match self {
            Self::Avc => format!(
                "a=rtpmap:{pt} H264/90000\r\na=fmtp:{pt} packetization-mode=1;sprop-parameter-sets={AVC_SPS},{AVC_PPS}\r\n"
            ),
            Self::Hevc => format!(
                "a=rtpmap:{pt} H265/90000\r\na=fmtp:{pt} sprop-vps={HEVC_VPS};sprop-sps={HEVC_SPS};sprop-pps={HEVC_PPS}\r\n"
            ),
        };
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns={PRIVATE_SDP}\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP {pt}\r\n{attributes}a=control:trackID=0\r\n"
        )
    }
    fn nals(self) -> Test<Vec<Vec<u8>>> {
        match self {
            Self::Hevc => include_str!("../../../tests/fixtures/media/hevc/remux_main8.nals.hex")
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| {
                    if !line.is_ascii() || line.len() % 2 != 0 {
                        return Err("invalid HEVC fixture hex".into());
                    }
                    (0..line.len())
                        .step_by(2)
                        .map(|at| u8::from_str_radix(&line[at..at + 2], 16).map_err(Into::into))
                        .collect()
                })
                .collect(),
            Self::Avc => {
                let bytes = include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264");
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
                            nals.push(bytes[begin..end].to_vec());
                        }
                    }
                    start = Some(at + prefix);
                    at += prefix;
                }
                if let Some(begin) = start
                    && begin < bytes.len()
                {
                    nals.push(bytes[begin..].to_vec());
                }
                Ok(nals)
            }
        }
    }
    fn parameter_digests(self) -> Test<Vec<ContentDigest>> {
        Ok(self
            .nals()?
            .into_iter()
            .filter(|nal| match self {
                Self::Avc => matches!(nal[0] & 31, 7 | 8),
                Self::Hevc => matches!((nal[0] >> 1) & 63, 32..=34),
            })
            .take(match self {
                Self::Avc => 2,
                Self::Hevc => 3,
            })
            .map(|nal| ContentDigest::sha256(&nal))
            .collect())
    }
    fn picture(self) -> Test<Vec<u8>> {
        self.nals()?
            .into_iter()
            .find(|nal| match self {
                Self::Avc => nal[0] & 31 == 5,
                Self::Hevc => (nal[0] >> 1) & 63 == 20,
            })
            .ok_or_else(|| "pinned source contains no IDR picture".into())
    }
}

fn listener() -> Test<TcpListener> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}
fn no_connection(listener: &TcpListener) -> Test {
    match listener.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err("unapproved probe contacted the camera".into()),
    }
}

struct Request {
    method: String,
    target: String,
    cseq: u32,
    authorization: Option<String>,
}
fn request(peer: &mut TcpStream) -> Test<Option<Request>> {
    let mut bytes = Vec::new();
    while bytes.len() < 16 * 1024 {
        let mut byte = [0];
        match peer.read(&mut byte) {
            Ok(0) if bytes.is_empty() => return Ok(None),
            Ok(0) => return Err("client closed inside a request".into()),
            Ok(_) => bytes.push(byte[0]),
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset && bytes.is_empty() => {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        }
        if !bytes.ends_with(b"\r\n\r\n") {
            continue;
        }
        let wire = String::from_utf8(bytes)?;
        assert!(
            !wire.contains(PASSWORD),
            "plaintext password crossed the wire"
        );
        let mut lines = wire.split("\r\n");
        let mut start = lines
            .next()
            .ok_or("request start missing")?
            .split_ascii_whitespace();
        let method = start.next().ok_or("method missing")?.to_owned();
        let target = start.next().ok_or("target missing")?.to_owned();
        assert_eq!(start.next(), Some("RTSP/1.0"));
        assert!(start.next().is_none());
        let mut cseq = None;
        let mut authorization = None;
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').ok_or("malformed request header")?;
            if name.eq_ignore_ascii_case("cseq") {
                assert!(cseq.replace(value.trim().parse()?).is_none());
            }
            if name.eq_ignore_ascii_case("authorization") {
                assert!(authorization.replace(value.trim().to_owned()).is_none());
            }
        }
        return Ok(Some(Request {
            method,
            target,
            cseq: cseq.ok_or("CSeq missing")?,
            authorization,
        }));
    }
    Err("fixture request ceiling exceeded".into())
}
fn reply(peer: &mut TcpStream, cseq: u32, headers: &str, body: &str) -> Test {
    peer.write_all(
        format!(
            "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nServer: {PRIVATE_SERVER}\r\nContent-Length: {}\r\n{headers}\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )?;
    Ok(())
}
fn signed_request(request: &Request, count: u32) -> Test {
    let body = request
        .authorization
        .as_deref()
        .ok_or("Digest authorization missing")?
        .strip_prefix("Digest ")
        .ok_or("wrong authorization scheme")?;
    let mut fields = BTreeMap::new();
    for field in body.split(',') {
        let (key, value) = field
            .trim()
            .split_once('=')
            .ok_or("invalid Digest directive")?;
        assert!(fields.insert(key, value.trim_matches('"')).is_none());
    }
    let get = |key| fields.get(key).copied().ok_or("missing Digest directive");
    assert_eq!(get("username")?, USERNAME);
    assert_eq!(get("realm")?, REALM);
    assert_eq!(get("nonce")?, NONCE);
    assert_eq!(get("algorithm")?, "SHA-256");
    assert_eq!(get("qop")?, "auth");
    assert_eq!(get("uri")?, request.target);
    assert_eq!(get("nc")?, format!("{count:08x}"));
    let cnonce = get("cnonce")?;
    assert_eq!(cnonce.len(), 32);
    assert!(cnonce.bytes().all(|byte| byte.is_ascii_hexdigit()));
    // Independent response composition; never calls the production Digest generator.
    let hash = |text: &str| ContentDigest::sha256(text.as_bytes()).to_text()[7..].to_owned();
    let a1 = hash(&format!("{USERNAME}:{REALM}:{PASSWORD}"));
    let a2 = hash(&format!("{}:{}", request.method, request.target));
    assert_eq!(
        get("response")?,
        hash(&format!("{a1}:{NONCE}:{count:08x}:{cnonce}:auth:{a2}"))
    );
    Ok(())
}

#[derive(Clone, Debug)]
enum Behavior {
    Complete,
    LostTeardownAck,
    WrongCadence,
    WrongSender,
    MalformedRtp,
    MalformedSdp,
    EofBeforeTarget,
    ChallengeWithoutCredentials,
    Digest,
    RevokeCredentials(PathBuf),
}
#[derive(Default, Debug)]
struct Transcript {
    methods: Vec<String>,
    signed: u32,
    client_closed: bool,
}

fn media(codec: Codec, behavior: &Behavior) -> Test<Vec<u8>> {
    let mut wire = Vec::new();
    let nal = codec.picture()?;
    let count = if matches!(behavior, Behavior::EofBeforeTarget) {
        2
    } else {
        3
    };
    for index in 0..count {
        let mut timestamp = 9000 + index * codec.cadence();
        if index == 2 && matches!(behavior, Behavior::WrongCadence) {
            timestamp += 100;
        }
        let ssrc: u32 = if index == 1 && matches!(behavior, Behavior::WrongSender) {
            8
        } else {
            7
        };
        let mut packet = vec![0x80, codec.payload() | 0x80];
        packet.extend_from_slice(&u16::try_from(index + 1)?.to_be_bytes());
        packet.extend_from_slice(&timestamp.to_be_bytes());
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(&nal);
        if index == 1 && matches!(behavior, Behavior::MalformedRtp) {
            packet.truncate(4);
        }
        wire.extend_from_slice(&[b'$', codec.channel()]);
        wire.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
        wire.extend_from_slice(&packet);
    }
    Ok(wire)
}

fn serve(listener: TcpListener, codec: Codec, behavior: Behavior) -> Test<Transcript> {
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
    let mut transcript = Transcript::default();
    let mut challenged = false;
    for _ in 0..16 {
        let Some(request) = request(&mut peer)? else {
            transcript.client_closed = true;
            return Ok(transcript);
        };
        transcript.methods.push(request.method.clone());
        if !challenged
            && matches!(
                behavior,
                Behavior::Digest | Behavior::ChallengeWithoutCredentials
            )
        {
            assert_eq!(request.method, "OPTIONS");
            assert!(request.authorization.is_none());
            peer.write_all(format!(
                "RTSP/1.0 401 Unauthorized\r\nCSeq: {}\r\nWWW-Authenticate: Digest realm=\"{REALM}\", nonce=\"{NONCE}\", algorithm=SHA-256, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n",
                request.cseq
            ).as_bytes())?;
            challenged = true;
            continue;
        }
        if matches!(behavior, Behavior::Digest) {
            transcript.signed += 1;
            signed_request(&request, transcript.signed)?;
        } else {
            assert!(
                request.authorization.is_none(),
                "no-auth fixture received credentials"
            );
            assert!(
                !matches!(behavior, Behavior::ChallengeWithoutCredentials),
                "no-auth probe retried a challenge"
            );
        }
        match request.method.as_str() {
            "OPTIONS" => reply(
                &mut peer,
                request.cseq,
                "Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\n",
                "",
            )?,
            "DESCRIBE" => {
                let sdp = if matches!(behavior, Behavior::MalformedSdp) {
                    format!(
                        "v=0\r\n{PRIVATE_SDP}\r\na=control:rtsp://user:{PASSWORD}@foreign.invalid/escape\r\n"
                    )
                } else {
                    codec.description()
                };
                reply(
                    &mut peer,
                    request.cseq,
                    "Content-Type: application/sdp\r\n",
                    &sdp,
                )?;
            }
            "SETUP" => reply(
                &mut peer,
                request.cseq,
                &format!(
                    "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved={}-{};ssrc=7\r\n",
                    codec.channel(),
                    codec.channel() + 1
                ),
                "",
            )?,
            "PLAY" => {
                if let Behavior::RevokeCredentials(path) = &behavior {
                    fs::remove_file(path)?;
                    let _ = reply(&mut peer, request.cseq, "Session: fixture\r\n", "");
                    continue;
                }
                reply(&mut peer, request.cseq, "Session: fixture\r\n", "")?;
                peer.write_all(&media(codec, &behavior)?)?;
                if matches!(behavior, Behavior::EofBeforeTarget) {
                    peer.shutdown(Shutdown::Write)?;
                }
            }
            "TEARDOWN" => {
                if matches!(behavior, Behavior::LostTeardownAck) {
                    // The fixture accepts the close, but the response never reaches the client.
                    // TCP closure is deliberately not an RTSP acknowledgment.
                    peer.shutdown(Shutdown::Write)?;
                } else {
                    reply(&mut peer, request.cseq, "Session: fixture\r\n", "")?;
                }
            }
            _ => return Err("unexpected RTSP method in bounded probe".into()),
        }
    }
    Err("probe exceeded fixture request bound".into())
}

fn probed(
    listener: TcpListener,
    args: &[OsString],
    codec: Codec,
    behavior: Behavior,
) -> Test<(Output, Transcript)> {
    thread::scope(|scope| {
        let server = scope.spawn(move || serve(listener, codec, behavior));
        let output = run(args);
        let server = server.join().map_err(|_| "camera fixture panicked")?;
        match (output, server) {
            (Ok(output), Ok(transcript)) => Ok((output, transcript)),
            (Ok(output), Err(error)) => Err(format!(
                "fixture failed: {error}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into()),
            (Err(error), _) => Err(error),
        }
    })
}

fn no_secrets(output: &Output) {
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        for canary in [
            USERNAME,
            PASSWORD,
            REALM,
            NONCE,
            PRIVATE_SDP,
            PRIVATE_SERVER,
        ] {
            assert!(
                !text.contains(canary),
                "probe output disclosed a secret or source payload"
            );
        }
    }
}
fn diagnostic(output: Output, connection: bool, credentials: bool) -> Test<Value> {
    assert!(!output.status.success(), "probe unexpectedly succeeded");
    no_secrets(&output);
    for bytes in [&output.stdout, &output.stderr] {
        assert!(
            !String::from_utf8_lossy(bytes).contains(PRIVATE_ROUTE),
            "refusal leaked the route"
        );
    }
    let value = json_input::parse(std::str::from_utf8(&output.stdout)?)?;
    assert_eq!(text(&value, "schema")?, "fss.site_probe_diagnostic.v1");
    assert_eq!(
        output.status.code().map(i128::from),
        Some(integer(&value, "exit_code")?)
    );
    assert!(text(&value, "error_id")?.starts_with("ERR-SITE-PROBE-"));
    assert_eq!(boolean(&value, "connection_attempted")?, connection);
    assert_eq!(boolean(&value, "credential_access_attempted")?, credentials);
    for name in [
        "source_retained",
        "receipt_issued",
        "retry_automatically",
        "teardown_acknowledged",
    ] {
        assert!(!boolean(&value, name)?, "refusal misreported {name}");
    }
    Ok(value)
}

#[test]
fn preview_and_mismatched_approval_do_not_connect_or_resolve_credentials() -> Test {
    let listener = listener()?;
    let mut fixture = Fixture::new("preview", listener.local_addr()?)?;
    let credential = fixture.directory.0.join("PRIVATE_CREDENTIAL_PATH_CANARY");
    fixture.authentication(&credential)?;
    fixture.write()?;
    let args = fixture.args(Codec::Avc);
    let first = run(&args)?;
    let original = first.stdout.clone();
    no_secrets(&first);
    let preview = good(first)?;
    assert_eq!(text(&preview, "schema")?, "fss.site_probe_plan.v1");
    assert_eq!(text(&preview, "status")?, "requires_approval");
    for name in [
        "device_contacted",
        "credentials_read",
        "source_retained",
        "capture_authorized",
        "rights_verdict_verified",
    ] {
        assert!(!boolean(&preview, name)?);
    }
    assert!(boolean(&preview, "teardown_ack_required")?);
    assert_eq!(
        run(&args)?.stdout,
        original,
        "identical request changed approval bytes"
    );
    let mut wrong = args;
    wrong.extend([
        "--approve".into(),
        ContentDigest::sha256(b"not the inspected plan")
            .to_text()
            .into(),
    ]);
    let refusal = diagnostic(run(&wrong)?, false, false)?;
    assert_eq!(text(&refusal, "error_id")?, "ERR-SITE-PROBE-APPROVAL-001");
    assert!(!boolean(&refusal, "remote_session_may_exist")?);
    assert!(!credential.exists());
    no_connection(&listener)?;
    Ok(())
}

#[test]
fn approval_is_invalidated_by_manifest_source_and_every_observation_selection() -> Test {
    let listener = listener()?;
    let mut fixture = Fixture::new("approval-pins", listener.local_addr()?)?;
    let first_source = fixture.source()?.clone();
    let mut second_source = first_source;
    set(
        &mut second_source,
        "source_id",
        Value::Text("source:back".into()),
    )?;
    set(
        &mut second_source,
        "presentation",
        Value::Text("/camera/back/main".into()),
    )?;
    set(
        &mut second_source,
        "control_root",
        Value::Text("/camera/back".into()),
    )?;
    let Value::Object(fields) = &mut fixture.manifest else {
        return Err("manifest object".into());
    };
    let Some(Value::Array(sources)) = fields.get_mut("sources") else {
        return Err("manifest sources".into());
    };
    sources.push(second_source);
    fixture.write()?;
    let approved = fixture.approved(Codec::Avc)?;
    for (name, value) in [
        ("--source", "source:back"),
        ("--codec", "hevc"),
        ("--media-index", "1"),
        ("--payload-type", "97"),
        ("--rtp-channel", "2"),
        ("--observe-frames", "4"),
        ("--timeout-ms", "4000"),
        ("--principal", "principal:different-owner"),
    ] {
        let mut changed = approved.clone();
        replace(&mut changed, name, value)?;
        assert_eq!(
            text(&diagnostic(run(&changed)?, false, false)?, "error_id")?,
            "ERR-SITE-PROBE-APPROVAL-001",
            "{name}"
        );
    }
    set(fixture.source()?, "generation", Value::Number("2".into()))?;
    fixture.write()?;
    assert_eq!(
        text(&diagnostic(run(&approved)?, false, false)?, "error_id")?,
        "ERR-SITE-PROBE-APPROVAL-001"
    );
    no_connection(&listener)?;
    Ok(())
}

#[test]
fn avc_and_hevc_observed_receipts_feed_the_native_site_planner_after_teardown() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        let listener = listener()?;
        let fixture = Fixture::new(codec.name(), listener.local_addr()?)?;
        fixture.write()?;
        let approved = fixture.approved(codec)?;
        let (output, transcript) = probed(listener, &approved, codec, Behavior::Complete)?;
        no_secrets(&output);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let receipts = parse_probe_receipts(&output.stdout)?;
        assert_eq!(receipts.len(), 1);
        let receipt = &receipts[0];
        receipt.validate_for(&parse_manifest(render(&fixture.manifest).as_bytes())?)?;
        assert_eq!(receipt.codec.as_str(), codec.name());
        assert_eq!(receipt.payload_type, codec.payload());
        assert_eq!(receipt.rtp_channel, codec.channel());
        assert_eq!(receipt.rtcp_channel, codec.channel() + 1);
        assert_eq!(receipt.ssrc, 7);
        assert_eq!(receipt.observed_frames, 3);
        assert_eq!(receipt.frame_duration_ticks, codec.cadence());
        assert_eq!(receipt.first_rtp_timestamp, 9000);
        assert_eq!(receipt.last_rtp_timestamp, 9000 + 2 * codec.cadence());
        assert_eq!(
            receipt.sdp_digest,
            ContentDigest::sha256(codec.description().as_bytes())
        );
        assert_eq!(receipt.parameter_set_digests, codec.parameter_digests()?);
        assert_eq!(
            receipt.server_identity,
            format!(
                "server-header:{}",
                ContentDigest::sha256(PRIVATE_SERVER.as_bytes()).to_text()
            )
        );
        assert_eq!(
            transcript.methods,
            ["OPTIONS", "DESCRIBE", "SETUP", "PLAY", "TEARDOWN"]
        );
        assert!(
            transcript.client_closed,
            "client returned without closing its socket"
        );
        let probes = fixture.directory.write("probes.json", &output.stdout)?;
        let plan = good(run(&fixture.plan_args(&probes))?)?;
        assert_eq!(text(&plan, "schema")?, "fss.site_capture_plan.v1");
        assert!(!boolean(&plan, "effects_started")?);
        let sources = field(&plan, "sources")?
            .array()
            .ok_or("planned sources missing")?;
        assert_eq!(sources.len(), 1);
        assert_eq!(text(&sources[0], "source_id")?, "source:front");
        assert!(!fixture.directory.0.join("archive-not-created").exists());
        assert!(!fixture.directory.0.join("pins-not-created").exists());
        // The separate existing site_cli_contract lane requires the native binary.
        // When supplied here too, compare the exact preview bytes from that owner.
        if let Some(native) = std::env::var_os("FSS_CAPTURE_RTSP_BIN")
            .or_else(|| option_env!("CARGO_BIN_EXE_fss-capture-rtsp").map(OsString::from))
        {
            let args = field(&sources[0], "argv")?
                .array()
                .ok_or("native arguments missing")?
                .iter()
                .map(|value| {
                    value
                        .text()
                        .map(OsString::from)
                        .ok_or("native argument is not text")
                })
                .collect::<Result<Vec<_>, _>>()?;
            let native = good(run_binary(Path::new(&native), &args)?)?;
            assert_eq!(field(&sources[0], "native_plan")?, &native);
        }
    }
    Ok(())
}

#[test]
fn missing_teardown_ack_retains_remote_uncertainty_and_never_issues_a_receipt() -> Test {
    let listener = listener()?;
    let fixture = Fixture::new("lost-close-ack", listener.local_addr()?)?;
    fixture.write()?;
    let (output, transcript) = probed(
        listener,
        &fixture.approved(Codec::Avc)?,
        Codec::Avc,
        Behavior::LostTeardownAck,
    )?;
    let refusal = diagnostic(output, true, false)?;
    assert!(boolean(&refusal, "remote_session_may_exist")?);
    assert_eq!(
        transcript.methods,
        ["OPTIONS", "DESCRIBE", "SETUP", "PLAY", "TEARDOWN"]
    );
    assert!(transcript.client_closed);
    Ok(())
}

#[test]
fn malformed_source_sender_switch_cadence_drift_and_shortfall_never_make_receipts() -> Test {
    for (label, behavior) in [
        ("cadence", Behavior::WrongCadence),
        ("sender", Behavior::WrongSender),
        ("rtp", Behavior::MalformedRtp),
        ("shortfall", Behavior::EofBeforeTarget),
    ] {
        let listener = listener()?;
        let fixture = Fixture::new(label, listener.local_addr()?)?;
        fixture.write()?;
        let (output, transcript) = probed(
            listener,
            &fixture.approved(Codec::Avc)?,
            Codec::Avc,
            behavior,
        )?;
        let refusal = diagnostic(output, true, false)?;
        assert!(boolean(&refusal, "remote_session_may_exist")?);
        assert!(transcript.client_closed);
        assert_eq!(
            &transcript.methods[..4],
            ["OPTIONS", "DESCRIBE", "SETUP", "PLAY"]
        );
    }
    Ok(())
}

#[test]
fn malformed_sdp_and_unsolicited_digest_challenge_stop_before_remote_setup() -> Test {
    for (label, behavior) in [
        ("bad-description", Behavior::MalformedSdp),
        (
            "unrequested-authentication",
            Behavior::ChallengeWithoutCredentials,
        ),
    ] {
        let listener = listener()?;
        let fixture = Fixture::new(label, listener.local_addr()?)?;
        fixture.write()?;
        let (output, transcript) = probed(
            listener,
            &fixture.approved(Codec::Avc)?,
            Codec::Avc,
            behavior,
        )?;
        let refusal = diagnostic(output, true, false)?;
        assert!(!boolean(&refusal, "remote_session_may_exist")?);
        assert!(!transcript.methods.iter().any(|method| method == "SETUP"));
        assert!(transcript.client_closed);
    }
    Ok(())
}

#[test]
fn approved_missing_credentials_fail_before_connect_without_disclosing_the_path() -> Test {
    let listener = listener()?;
    let mut fixture = Fixture::new("missing-credential", listener.local_addr()?)?;
    let path = fixture.directory.0.join("PRIVATE_CREDENTIAL_PATH_CANARY");
    fixture.authentication(&path)?;
    fixture.write()?;
    let output = run(&fixture.approved(Codec::Avc)?)?;
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE_CREDENTIAL_PATH_CANARY"));
    let refusal = diagnostic(output, false, true)?;
    assert_eq!(text(&refusal, "error_id")?, "ERR-SITE-PROBE-CREDENTIAL-001");
    assert!(!boolean(&refusal, "remote_session_may_exist")?);
    no_connection(&listener)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn credentials(fixture: &mut Fixture) -> Test<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let path = fixture
        .directory
        .write("credential", format!("{USERNAME}\n{PASSWORD}\n"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    fixture.authentication(&path)?;
    Ok(path)
}

#[cfg(target_os = "linux")]
#[test]
fn private_digest_credentials_sign_exact_requests_without_entering_the_receipt() -> Test {
    let listener = listener()?;
    let mut fixture = Fixture::new("digest", listener.local_addr()?)?;
    credentials(&mut fixture)?;
    fixture.write()?;
    let (output, transcript) = probed(
        listener,
        &fixture.approved(Codec::Avc)?,
        Codec::Avc,
        Behavior::Digest,
    )?;
    no_secrets(&output);
    let receipts = good(output)?;
    assert_eq!(receipts.array().ok_or("receipt array missing")?.len(), 1);
    assert_eq!(transcript.signed, 5);
    assert_eq!(
        transcript.methods,
        [
            "OPTIONS", "OPTIONS", "DESCRIBE", "SETUP", "PLAY", "TEARDOWN"
        ]
    );
    assert!(transcript.client_closed);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn credential_revocation_after_play_closes_locally_and_preserves_remote_uncertainty() -> Test {
    let listener = listener()?;
    let mut fixture = Fixture::new("revoked-credential", listener.local_addr()?)?;
    let path = credentials(&mut fixture)?;
    fixture.write()?;
    let (output, transcript) = probed(
        listener,
        &fixture.approved(Codec::Avc)?,
        Codec::Avc,
        Behavior::RevokeCredentials(path),
    )?;
    let refusal = diagnostic(output, true, true)?;
    assert!(boolean(&refusal, "remote_session_may_exist")?);
    assert_eq!(transcript.methods, ["OPTIONS", "DESCRIBE", "SETUP", "PLAY"]);
    assert!(transcript.client_closed);
    Ok(())
}
