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
use fss_packet::{PacketLimits, RtpPacket};
use fss_reference::ingest::rtpdump::{RtpDumpKind, RtpDumpLimits, RtpDumpReader};
use fss_reference::rtsp::decode_base64;
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
const HEVC_VPS: &str = "QAEMAf//AWAAAAMAkAAAAwAAAwAekoCQ";
const HEVC_SPS: &str = "QgEBAWAAAAMAkAAAAwAAAwAeoCCBBZZKuTC8BaAgAAADACAAAAMBQQ==";
const HEVC_PPS: &str = "RAHBcaGkgA==";
const HEVC_FIELD_SPS: &str = "QgEBAWAAAAMAkAAAAwAAAwAeoCCBBZZKuTC8BaEgAAADACAAAAMBQQ==";
const FIRST_TIMESTAMP: u32 = 0xffff_f000;
const FRAME_TICKS: u32 = 3600;
const AVC_DESCRIPTION: &str = include_str!("../../../fixtures/site_probe/avc.describe.rtsp");
const HEVC_DESCRIPTION: &str = include_str!("../../../fixtures/site_probe/hevc.describe.rtsp");
const AVC_RTP: &[u8] = include_bytes!("../../../fixtures/site_probe/avc.rtpdump");
const HEVC_RTP: &[u8] = include_bytes!("../../../fixtures/site_probe/hevc.rtpdump");

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
    fn entries(&self) -> Test<Vec<OsString>> {
        let mut entries = fs::read_dir(&self.0)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort();
        Ok(entries)
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
    fn session_args(&self, codec: Codec) -> Test<Vec<OsString>> {
        let mut args = self.args(codec);
        args.extend(["--output".into(), "session".into()]);
        let preview = good(run(&args)?)?;
        assert_eq!(text(&preview, "schema")?, "fss.site_probe_plan.v1");
        args.extend(["--approve".into(), text(&preview, "approval")?.into()]);
        Ok(args)
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
        FRAME_TICKS
    }
    fn ssrc(self) -> u32 {
        match self {
            Self::Avc => 0x1122_3344,
            Self::Hevc => 0x5566_7788,
        }
    }
    fn description(self) -> String {
        let response = match self {
            Self::Avc => AVC_DESCRIPTION,
            Self::Hevc => HEVC_DESCRIPTION,
        };
        response
            .split_once("\r\n\r\n")
            .expect("checked-in DESCRIBE contains an SDP body")
            .1
            .to_owned()
    }
    fn parameter_digests(self) -> Test<Vec<ContentDigest>> {
        let parameters: &[&str] = match self {
            Self::Avc => &[AVC_SPS, AVC_PPS],
            Self::Hevc => &[HEVC_VPS, HEVC_SPS, HEVC_PPS],
        };
        parameters
            .iter()
            .map(|text| {
                let bytes = decode_base64(text)?;
                Ok(ContentDigest::sha256(&bytes))
            })
            .collect()
    }
    fn packets(self) -> Test<Vec<Vec<u8>>> {
        let bytes = match self {
            Self::Avc => AVC_RTP,
            Self::Hevc => HEVC_RTP,
        };
        let mut reader = RtpDumpReader::new(bytes, RtpDumpLimits::default())?;
        let mut packets = Vec::new();
        while let Some(record) = reader.next_record()? {
            assert_eq!(record.kind(), RtpDumpKind::Rtp);
            let packet = RtpPacket::parse(record.packet(), PacketLimits::default())?;
            assert_eq!(packet.ssrc(), self.ssrc());
            assert!(!packet.payload().is_empty());
            // Preserve the original parameter sets, fragments, sequence and clock wraps.
            packets.push(record.packet().to_vec());
        }
        Ok(packets)
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
fn request(peer: &mut TcpStream, deadline: Instant) -> Test<Option<Request>> {
    let mut bytes = Vec::new();
    while bytes.len() < 16 * 1024 {
        if Instant::now() >= deadline {
            return Err("bounded camera request deadline exceeded".into());
        }
        let mut byte = [0];
        match peer.read(&mut byte) {
            Ok(0) if bytes.is_empty() => return Ok(None),
            Ok(0) => return Err("client closed inside a request".into()),
            Ok(_) => bytes.push(byte[0]),
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset && bytes.is_empty() => {
                return Ok(None);
            }
            Err(error)
                if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted) =>
            {
                continue;
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
    RejectedTeardown,
    WrongTeardownCseq,
    NoMarkers,
    MarkerOnly,
    ForgedSlice,
    MissingHevcEos,
    AvcField,
    AvcMbaff,
    HevcField,
    ParameterDrift,
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
    let mut packets = if matches!(behavior, Behavior::MarkerOnly | Behavior::ForgedSlice) {
        // Deliberately insufficient native syntax, with perfectly plausible RTP markers,
        // timestamps and sender identity. This is a refusal fixture, never a picture.
        let mut packets = Vec::new();
        for index in 0u16..4 {
            let mut packet = vec![0x80, codec.payload() | 0x80];
            packet.extend_from_slice(&65534u16.wrapping_add(index).to_be_bytes());
            packet.extend_from_slice(
                &FIRST_TIMESTAMP.wrapping_add(u32::from(index) * FRAME_TICKS).to_be_bytes(),
            );
            packet.extend_from_slice(&codec.ssrc().to_be_bytes());
            let payload: &[u8] = match (codec, behavior) {
                (Codec::Avc, Behavior::MarkerOnly) => &[9, 0xf0],
                (Codec::Hevc, Behavior::MarkerOnly) => &[0x46, 1, 0x50],
                (Codec::Avc, _) => &[0x65, 0, 0x80],
                (Codec::Hevc, _) => &[0x26, 1, 0x80],
            };
            packet.extend_from_slice(payload);
            packets.push(packet);
        }
        packets
    } else {
        codec.packets()?
    };
    if matches!(behavior, Behavior::MissingHevcEos) {
        let eos = packets.pop().ok_or("missing checked-in HEVC EOS")?;
        assert!(matches!(codec, Codec::Hevc));
        assert_eq!(
            RtpPacket::parse(&eos, PacketLimits::default())?.payload(),
            &[0x48, 1, 0x80]
        );
    }
    if matches!(behavior, Behavior::EofBeforeTarget) {
        packets.retain(|packet| {
            let timestamp = u32::from_be_bytes(packet[4..8].try_into().expect("validated RTP header"));
            timestamp == FIRST_TIMESTAMP
                || timestamp == FIRST_TIMESTAMP.wrapping_add(FRAME_TICKS)
        });
    }
    let mut parameter_changed = false;
    for (index, bytes) in packets.iter_mut().enumerate() {
        let parsed = RtpPacket::parse(bytes, PacketLimits::default())?;
        let timestamp = parsed.timestamp();
        let payload = parsed.payload_range();
        let kind = match codec {
            Codec::Avc => parsed.payload()[0] & 31,
            Codec::Hevc => (parsed.payload()[0] >> 1) & 63,
        };
        let parameter_kind = match codec {
            Codec::Avc => 7,
            Codec::Hevc => 32,
        };
        match behavior {
            Behavior::WrongCadence if timestamp == FIRST_TIMESTAMP.wrapping_add(2 * FRAME_TICKS) => {
                bytes[4..8].copy_from_slice(&timestamp.wrapping_add(100).to_be_bytes());
            }
            Behavior::WrongSender if index == 1 => {
                bytes[8..12].copy_from_slice(&codec.ssrc().wrapping_add(1).to_be_bytes());
            }
            Behavior::MalformedRtp if index == 1 => bytes.truncate(4),
            Behavior::NoMarkers => bytes[1] &= 0x7f,
            Behavior::ParameterDrift if !parameter_changed && kind == parameter_kind => {
                bytes[payload.end - 1] ^= 1;
                parameter_changed = true;
            }
            _ => {}
        }
    }
    if matches!(behavior, Behavior::ParameterDrift) {
        assert!(parameter_changed, "real fixture parameter mutation did not apply");
    }
    let mut wire = Vec::new();
    for packet in packets {
        wire.extend_from_slice(&[b'$', codec.channel()]);
        wire.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
        wire.extend_from_slice(&packet);
    }
    Ok(wire)
}

fn description(codec: Codec, behavior: &Behavior) -> String {
    let body = codec.description();
    match behavior {
        Behavior::MalformedSdp => format!(
            "v=0\r\n{PRIVATE_SDP}\r\na=control:rtsp://user:{PASSWORD}@foreign.invalid/escape\r\n"
        ),
        Behavior::AvcField => body.replace(AVC_SPS, "Z0IAH/QUIJA=").replace(AVC_PPS, "aM44gA=="),
        Behavior::AvcMbaff => body.replace(AVC_SPS, "Z0IAH/QUIZA=").replace(AVC_PPS, "aM44gA=="),
        Behavior::HevcField => body.replace(HEVC_SPS, HEVC_FIELD_SPS),
        _ => body,
    }
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
    peer.set_read_timeout(Some(Duration::from_millis(100)))?;
    peer.set_write_timeout(Some(Duration::from_secs(1)))?;
    peer.set_nodelay(true)?;
    let mut transcript = Transcript::default();
    let mut challenged = false;
    for _ in 0..16 {
        let Some(request) = request(&mut peer, deadline)? else {
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
                let sdp = description(codec, &behavior);
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
                    "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved={}-{};ssrc={:08x}\r\n",
                    codec.channel(),
                    codec.channel() + 1,
                    codec.ssrc()
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
                } else if matches!(behavior, Behavior::RejectedTeardown) {
                    peer.write_all(format!(
                        "RTSP/1.0 500 Close Rejected\r\nCSeq: {}\r\nContent-Length: 0\r\n\r\n",
                        request.cseq
                    ).as_bytes())?;
                } else {
                    let cseq = if matches!(behavior, Behavior::WrongTeardownCseq) {
                        request.cseq + 1
                    } else {
                        request.cseq
                    };
                    reply(&mut peer, cseq, "Session: fixture\r\n", "")?;
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
            AVC_SPS,
            AVC_PPS,
            HEVC_VPS,
            HEVC_SPS,
            HEVC_PPS,
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

/// Session output exposes retirement facts, while only a measured result carries
/// a usable receipt. Socket EOF in the owned peer proves local transport cleanup;
/// there is deliberately no invented runtime-quiescence or pixel-decoding claim.
fn session(output: Output, measured: bool, remote_session: bool) -> Test<Value> {
    no_secrets(&output);
    assert_eq!(output.status.code(), Some(if measured { 0 } else { 1 }),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr));
    assert!(output.stderr.is_empty());
    let value = json_input::parse(std::str::from_utf8(&output.stdout)?)?;
    assert_eq!(text(&value, "schema")?, "fss.site_probe_session.v1");
    assert_eq!(text(&value, "status")?, if measured {
        "measured"
    } else if remote_session {
        "indeterminate"
    } else {
        "refused"
    });
    assert!(boolean(&value, "connection_attempted")?);
    assert!(!boolean(&value, "credential_access_attempted")?);
    assert!(!boolean(&value, "credentials_loaded")?);
    assert_eq!(boolean(&value, "remote_session_may_exist")?, remote_session);
    assert_eq!(boolean(&value, "teardown_acknowledged")?, measured);
    let receipts = field(&value, "receipts")?.array().ok_or("receipt array missing")?;
    assert_eq!(receipts.len(), usize::from(measured));
    for name in ["receipt_digest", "completion_digest"] {
        if measured {
            let digest = text(&value, name)?;
            assert!(digest.starts_with("sha256:"));
            assert_eq!(ContentDigest::parse(digest)?.to_text(), digest);
        } else {
            assert_eq!(field(&value, name)?, &Value::Null);
        }
    }
    let transport = field(&value, "transport")?;
    assert!(integer(transport, "sent_bytes")? > 0);
    assert!(integer(transport, "received_bytes")? > 0);
    assert!(integer(transport, "read_calls")? > 0);
    assert!(integer(transport, "write_calls")? > 0);
    let _ = boolean(transport, "peer_eof")?;
    let accounting = field(&value, "accounting")?;
    for name in [
        "rtp_packets", "rtp_bytes", "rtcp_frames_excluded", "rtcp_bytes_excluded",
        "closing_frames_excluded", "closing_bytes_excluded", "control_responses",
        "discarded_wire_bytes", "unverified_nal_bytes_excluded",
        "unfinished_fragment_bytes_excluded",
    ] {
        assert!(integer(accounting, name)? >= 0, "{name}");
    }
    assert!(integer(&value, "last_observed_ns")? >= 0);
    if measured {
        assert_eq!(field(&value, "pending_cseq")?, &Value::Null);
        assert_eq!(integer(&value, "unsent_request_bytes")?, 0);
        assert_eq!(integer(transport, "last_sent_cseq")?, 5);
        assert_eq!(integer(accounting, "discarded_wire_bytes")?, integer(transport, "received_bytes")?);
    } else {
        assert!(text(&value, "error_id")?.starts_with("ERR-SITE-PROBE-"));
        assert!(!render(&value).contains(PRIVATE_ROUTE), "session refusal leaked the route");
    }
    Ok(value)
}

fn session_receipt(value: &Value, fixture: &Fixture, codec: Codec) -> Test {
    let receipts = parse_probe_receipts(render(field(value, "receipts")?).as_bytes())?;
    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0];
    receipt.validate_for(&parse_manifest(render(&fixture.manifest).as_bytes())?)?;
    assert_eq!(receipt.codec.as_str(), codec.name());
    assert_eq!(receipt.observed_frames, 3);
    assert_eq!(receipt.frame_duration_ticks, FRAME_TICKS);
    assert_eq!(receipt.first_rtp_timestamp, FIRST_TIMESTAMP);
    assert_eq!(receipt.last_rtp_timestamp, FIRST_TIMESTAMP.wrapping_add(2 * FRAME_TICKS));
    assert_eq!(receipt.ssrc, codec.ssrc());
    assert_eq!(receipt.parameter_set_digests, codec.parameter_digests()?);
    Ok(())
}

#[test]
fn preview_and_mismatched_approval_do_not_connect_or_resolve_credentials() -> Test {
    let listener = listener()?;
    let mut fixture = Fixture::new("preview", listener.local_addr()?)?;
    let credential = fixture.directory.0.join("PRIVATE_CREDENTIAL_PATH_CANARY");
    fixture.authentication(&credential)?;
    fixture.write()?;
    let original_entries = fixture.directory.entries()?;
    let original_manifest = fs::read(fixture.directory.0.join("manifest.json"))?;
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
    assert_eq!(fixture.directory.entries()?, original_entries);
    assert_eq!(fs::read(fixture.directory.0.join("manifest.json"))?, original_manifest);
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
    let mut changed_output = approved.clone();
    changed_output.extend(["--output".into(), "session".into()]);
    assert_eq!(
        text(&diagnostic(run(&changed_output)?, false, false)?, "error_id")?,
        "ERR-SITE-PROBE-APPROVAL-001",
        "output mode must remain part of the exact reviewed plan"
    );
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
        assert_eq!(receipt.ssrc, codec.ssrc());
        assert_eq!(receipt.observed_frames, 3);
        assert_eq!(receipt.frame_duration_ticks, codec.cadence());
        assert_eq!(receipt.first_rtp_timestamp, FIRST_TIMESTAMP);
        assert_eq!(receipt.last_rtp_timestamp, FIRST_TIMESTAMP.wrapping_add(2 * codec.cadence()));
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


#[test]
fn native_markerless_pictures_issue_a_session_receipt_with_explicit_sample_tail() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        let listener = listener()?;
        let fixture = Fixture::new(&format!("markerless-{}", codec.name()), listener.local_addr()?)?;
        fixture.write()?;
        let before = fixture.directory.entries()?;
        let (output, transcript) = probed(
            listener, &fixture.session_args(codec)?, codec, Behavior::NoMarkers,
        )?;
        let measured = session(output, true, false)?;
        session_receipt(&measured, &fixture, codec)?;
        let accounting = field(&measured, "accounting")?;
        assert_eq!(integer(accounting, "unfinished_fragment_bytes_excluded")?, 0);
        match codec {
            Codec::Avc => {
                // The real fourth access unit closes picture three; its partial group
                // is an excluded derivative tail, never a fourth measured picture.
                assert!(integer(accounting, "unverified_nal_bytes_excluded")? > 0);
                assert!(integer(accounting, "closing_frames_excluded")? > 0);
            }
            Codec::Hevc => {
                // The source fixture's actual EOS closes its final native picture.
                assert_eq!(integer(accounting, "unverified_nal_bytes_excluded")?, 0);
                assert_eq!(integer(accounting, "rtp_packets")?, 14);
            }
        }
        assert_eq!(transcript.methods, ["OPTIONS", "DESCRIBE", "SETUP", "PLAY", "TEARDOWN"]);
        assert!(transcript.client_closed);
        assert_eq!(fixture.directory.entries()?, before, "probe wrote a local artifact");
    }
    Ok(())
}

#[test]
fn marker_only_metadata_and_forged_slice_headers_never_issue_session_receipts() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        for (label, behavior) in [
            ("metadata", Behavior::MarkerOnly),
            ("forged-slice", Behavior::ForgedSlice),
        ] {
            let listener = listener()?;
            let fixture = Fixture::new(&format!("{label}-{}", codec.name()), listener.local_addr()?)?;
            fixture.write()?;
            // The peer stays open and would acknowledge a premature TEARDOWN.
            // A marker-counting implementation therefore fails this test by succeeding.
            let (output, transcript) = probed(
                listener, &fixture.session_args(codec)?, codec, behavior,
            )?;
            let _ = session(output, false, true)?;
            assert_eq!(transcript.methods, ["OPTIONS", "DESCRIBE", "SETUP", "PLAY"]);
            assert!(transcript.client_closed);
        }
    }
    Ok(())
}

#[test]
fn three_hevc_marked_timestamps_without_eos_leave_the_native_sample_incomplete() -> Test {
    let listener = listener()?;
    let fixture = Fixture::new("hevc-without-eos", listener.local_addr()?)?;
    fixture.write()?;
    let (output, transcript) = probed(
        listener, &fixture.session_args(Codec::Hevc)?, Codec::Hevc, Behavior::MissingHevcEos,
    )?;
    let refused = session(output, false, true)?;
    assert_eq!(integer(field(&refused, "accounting")?, "rtp_packets")?, 13);
    assert_eq!(transcript.methods, ["OPTIONS", "DESCRIBE", "SETUP", "PLAY"]);
    assert!(transcript.client_closed);
    Ok(())
}

#[test]
fn interlaced_codec_descriptions_refuse_before_setup_without_picture_receipts() -> Test {
    for (label, codec, behavior) in [
        ("avc-field", Codec::Avc, Behavior::AvcField),
        ("avc-mbaff", Codec::Avc, Behavior::AvcMbaff),
        ("hevc-field", Codec::Hevc, Behavior::HevcField),
    ] {
        let listener = listener()?;
        let fixture = Fixture::new(label, listener.local_addr()?)?;
        fixture.write()?;
        let (output, transcript) = probed(
            listener, &fixture.session_args(codec)?, codec, behavior,
        )?;
        let refused = session(output, false, false)?;
        assert_eq!(integer(field(&refused, "accounting")?, "rtp_packets")?, 0);
        assert_eq!(transcript.methods, ["OPTIONS", "DESCRIBE"]);
        assert!(transcript.client_closed);
    }
    Ok(())
}

#[test]
fn changed_inband_parameter_sets_refuse_the_whole_live_receipt() -> Test {
    for codec in [Codec::Avc, Codec::Hevc] {
        let listener = listener()?;
        let fixture = Fixture::new(&format!("parameter-drift-{}", codec.name()), listener.local_addr()?)?;
        fixture.write()?;
        let (output, transcript) = probed(
            listener, &fixture.session_args(codec)?, codec, Behavior::ParameterDrift,
        )?;
        let _ = session(output, false, true)?;
        assert_eq!(transcript.methods, ["OPTIONS", "DESCRIBE", "SETUP", "PLAY"]);
        assert!(transcript.client_closed);
    }
    Ok(())
}

#[test]
fn lost_rejected_or_mismatched_teardown_never_releases_a_session_completion() -> Test {
    for (label, behavior) in [
        ("lost", Behavior::LostTeardownAck),
        ("rejected", Behavior::RejectedTeardown),
        ("wrong-cseq", Behavior::WrongTeardownCseq),
    ] {
        let listener = listener()?;
        let fixture = Fixture::new(&format!("session-close-{label}"), listener.local_addr()?)?;
        fixture.write()?;
        let (output, transcript) = probed(
            listener, &fixture.session_args(Codec::Avc)?, Codec::Avc, behavior,
        )?;
        let refused = session(output, false, true)?;
        assert!(integer(field(&refused, "accounting")?, "rtp_packets")? >= 3);
        assert_eq!(transcript.methods, ["OPTIONS", "DESCRIBE", "SETUP", "PLAY", "TEARDOWN"]);
        assert!(transcript.client_closed);
    }
    Ok(())
}
