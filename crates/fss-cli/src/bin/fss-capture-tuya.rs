#![forbid(unsafe_code)]
//! fss-capture-tuya — operator command: open a direct, owner-authorized Tuya
//! LAN (3.4/3.5) session to a camera/homebase on the operator's network and
//! capture its live data points, WITHOUT the vendor cloud.
//!
//! This wires the finished sans-IO [`fss_tuya::client::TuyaClient`] onto a real
//! TCP session channel (LAB-AOSU-2 territory): negotiate (cmd 3/4/5), then a
//! bounded heartbeat + dp_query loop that reads the device's live status
//! (dps). The camera cfg (ip/port/local_key/proto) is read from a secrets
//! file (mode 600 expected); the `local_key` never appears in argv, the report,
//! or logs. The report JSON (`fss.tuya_capture_cli.v1`) is the machine
//! contract and the device data points are the captured evidence.
//!
//! Media continuity is NOT established here: the Tuya live-video channel rides
//! the OEM iotbing stream (a separate, login-keyed lane) and is reported
//! `unverified`, per INTEROPERABILITY_LAB.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use fss_cli::ExitIdentity;
use fss_tuya::client::{Proto, TuyaClient};
use fss_tuya::wire::{cmd, parse_header};

const HELP: &str = "fss-capture-tuya --cfg CAMERA_CFG [--secs N] --owner-authorized\n\n\
                    Open a direct, owner-authorized Tuya LAN (3.4/3.5) session to a camera on\n\
                    the operator's network and capture its live data points (no vendor cloud).\n\
                    The cfg JSON (mode 600) holds ip / port / local_key[hex] / proto[3.4|3.5];\n\
                    the local_key is never printed. --owner-authorized attests the device is yours.\n\
                    Report: fss.tuya_capture_cli.v1 JSON on stdout.";

const FORMAT: &str = "fss.tuya_capture_cli.v1";
const MAX_ARGS: usize = 16;
/// Reassembly buffer bound: a well-behaved device streams small frames, so
/// overflow means a corrupt prefix we resync past rather than an unbounded grow.
const MAX_BUF: usize = 4 * 1024 * 1024;

#[derive(Debug)]
struct Options {
    cfg: PathBuf,
    secs: u64,
    owner_authorized: bool,
}

fn parse(args: &[OsString]) -> Result<Options, &'static str> {
    if args.is_empty() || args.len() > MAX_ARGS || args.iter().any(|s| s.as_encoded_bytes().len() > 4096) {
        return Err("invalid argument count or bound");
    }
    let mut o = Options {
        cfg: PathBuf::new(),
        secs: 5,
        owner_authorized: false,
    };
    let mut i = 0;
    while i < args.len() {
        let Some(flag) = args[i].to_str() else {
            return Err("non-UTF-8 argument");
        };
        let need_value = |i: usize| -> Result<&OsString, &'static str> {
            args.get(i + 1).ok_or("missing flag value")
        };
        match flag {
            "--cfg" => o.cfg = PathBuf::from(need_value(i)?),
            "--secs" => {
                let v = need_value(i)?;
                o.secs = v.to_str().and_then(|s| s.parse().ok()).ok_or("invalid --secs")?;
                if o.secs == 0 || o.secs > 86_400 {
                    return Err("--secs out of bounds");
                }
            }
            "--owner-authorized" => {
                o.owner_authorized = true;
                i += 1;
                continue;
            }
            _ => return Err("unknown flag"),
        }
        i += 2;
    }
    if o.cfg.as_os_str().is_empty() {
        return Err("--cfg is required");
    }
    if !o.owner_authorized {
        return Err("--owner-authorized attestation is required for live device access");
    }
    Ok(o)
}

/// Minimal flat-JSON field reader for the operator's camera cfg. String values
/// are returned unquoted; numeric values as their digits. No external JSON
/// parser dependency (the cfg is a bounded, operator-authored file).
fn cfg_field(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = json.find(&needle)? + needle.len();
    let rest = json[start..].trim_start_matches([':', ' ', '\t']);
    if let Some(inner) = rest.strip_prefix('"') {
        let end = inner.find('"')?;
        return Some(inner[..end].to_string());
    }
    let end = rest.find([',', '}']).unwrap_or(rest.len());
    Some(rest[..end].trim().to_string())
}

/// Decode a 32-hex-char Tuya `local_key` into the 16-byte session key.
fn parse_hex16(s: &str) -> Option<[u8; 16]> {
    let b = s.trim().trim_start_matches("0x");
    if b.len() != 32 {
        return None;
    }
    let bytes = b.as_bytes();
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = (bytes[2 * i].to_digit(16)? * 16 + bytes[2 * i + 1].to_digit(16)?) as u8;
    }
    Some(out)
}

/// Fresh per-message client nonces / GCM IVs. A bounded capture opens ONE
/// session with ONE session key; a seed-mixed, monotonically-increasing
/// counter guarantees a unique (key, nonce) pair per frame within the run —
/// the IV-reuse guarantee the wire core requires — without a runtime RNG.
struct Nonce {
    seed: u64,
    counter: u64,
}
impl Nonce {
    fn new() -> Result<Self, &'static str> {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "ERR-TUYA-CAPTURE-SESSION-002: clock")?
            .as_nanos() as u64;
        Ok(Self { seed, counter: 0 })
    }
    fn next12(&mut self) -> [u8; 12] {
        let h = self.derive();
        let mut v = [0u8; 12];
        v.copy_from_slice(&h[..12]);
        v
    }
    fn next16(&mut self) -> [u8; 16] {
        let h = self.derive();
        let mut v = [0u8; 16];
        v.copy_from_slice(&h[..16]);
        v
    }
    fn derive(&mut self) -> [u8; 32] {
        self.counter = self.counter.wrapping_add(1);
        let mut pre = [0u8; 16];
        pre[..8].copy_from_slice(&self.seed.to_be_bytes());
        pre[8..].copy_from_slice(&self.counter.to_be_bytes());
        fss_core::sha256(&pre)
    }
}

/// One read + one frame-demux off the session channel.
#[derive(Debug, PartialEq, Eq)]
enum ReadStep {
    /// A complete 55AA/6699 frame was reassembled.
    Frame(Vec<u8>),
    /// No complete frame yet (read timeout or partial bytes).
    More,
    /// The peer closed the channel (or a transport error).
    Closed,
}

fn drain(stream: &mut TcpStream, buf: &mut Vec<u8>, tmp: &mut [u8]) -> ReadStep {
    match stream.read(tmp) {
        Ok(0) => return ReadStep::Closed,
        Ok(n) => buf.extend_from_slice(&tmp[..n]),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
        Err(_) => return ReadStep::Closed,
    }
    if buf.len() > MAX_BUF {
        buf.clear();
    }
    match next_frame(buf) {
        Some(frame) => ReadStep::Frame(frame),
        None => ReadStep::More,
    }
}

/// Pull the next complete Tuya frame (55AA/6699) off a reassembly buffer, or
/// `None` when fewer bytes than a header / declared total are present. Uses
/// the wire core's own `parse_header` so the demux and the auth/decrypt path
/// cannot drift apart on the length semantics (6699 appends a 4-byte trailer).
fn next_frame(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buf.len() < 16 {
        return None;
    }
    let h = parse_header(buf).ok()?;
    let frame = buf[..h.total].to_vec();
    buf.drain(..h.total);
    Some(frame)
}

/// Outcome of a bounded direct-LAN Tuya session capture.
#[derive(Debug, Default)]
struct PumpOutcome {
    established: bool,
    frames_sent: u64,
    frames_recv: u64,
    heartbeats: u64,
    dp_queries: u64,
    last_dps: Option<String>,
    error: Option<String>,
}

/// Open the session (cmd 3/4/5), then run a bounded heartbeat + dp_query loop
/// against the owner-authorized device, reading its live status (dps).
/// Transport errors are recorded on the outcome, never panicked; a failed
/// negotiation aborts (there is no session to hold).
fn pump(stream: &mut TcpStream, local_key: [u8; 16], proto: Proto, budget: Duration) -> PumpOutcome {
    let mut out = PumpOutcome::default();
    let mut nonce = match Nonce::new() {
        Ok(n) => n,
        Err(e) => {
            out.error = Some(e.to_owned());
            return out;
        }
    };
    let mut client = TuyaClient::new(local_key, proto);
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 8192];
    let t0 = Instant::now();

    // Negotiation: cmd 3 (client nonce) -> cmd 4 (device proof) -> cmd 5.
    let start = client.start_session(nonce.next16(), nonce.next12());
    if start.is_empty() {
        out.error = Some("negotiation start frame empty".to_owned());
        return out;
    }
    if stream.write_all(&start).is_err() {
        out.error = Some("write negotiation start failed".to_owned());
        return out;
    }
    out.frames_sent += 1;
    let neg_deadline = t0 + Duration::from_secs(5);
    while Instant::now() < neg_deadline {
        match drain(stream, &mut buf, &mut tmp) {
            ReadStep::Closed => {
                out.error = Some("session closed during negotiation".to_owned());
                return out;
            }
            ReadStep::More => std::thread::sleep(Duration::from_millis(10)),
            ReadStep::Frame(frame) => {
                out.frames_recv += 1;
                match client.negotiate_finish(&frame, nonce.next12()) {
                    Ok(cmd5) => {
                        if stream.write_all(&cmd5).is_err() {
                            out.error = Some("write negotiation finish failed".to_owned());
                            return out;
                        }
                        out.frames_sent += 1;
                        out.established = client.is_established();
                        break;
                    }
                    Err(_) => {
                        out.error =
                            Some("negotiation rejected (wrong key, offline, or not a Tuya device)".to_owned());
                        return out;
                    }
                }
            }
        }
    }
    if !out.established && out.error.is_none() {
        out.error = Some("negotiation timed out (wrong key, offline, or unreachable)".to_owned());
        return out;
    }

    // Bounded live session: heartbeat (~1 Hz) + dp_query, reading status.
    let end = t0 + budget;
    let mut last_hb = Instant::now();
    while Instant::now() < end {
        if last_hb.elapsed() >= Duration::from_secs(1) {
            match client.heartbeat(nonce.next12()) {
                Ok(hb) if stream.write_all(&hb).is_ok() => {
                    out.frames_sent += 1;
                    out.heartbeats += 1;
                }
                _ => {}
            }
            last_hb = Instant::now();
        }
        match client.dp_query(nonce.next12()) {
            Ok(dq) if stream.write_all(&dq).is_ok() => {
                out.frames_sent += 1;
                out.dp_queries += 1;
            }
            _ => {}
        }
        match drain(stream, &mut buf, &mut tmp) {
            ReadStep::Closed => break,
            ReadStep::More => {}
            ReadStep::Frame(frame) => {
                out.frames_recv += 1;
                if let Ok(inbound) = client.handle(&frame) {
                    if inbound.cmd == cmd::STATUS {
                        let dps = String::from_utf8_lossy(&inbound.payload).into_owned();
                        if !dps.is_empty() {
                            out.last_dps = Some(dps);
                        }
                    }
                }
            }
        }
    }
    out
}

fn run(o: &Options) -> Result<String, &'static str> {
    let raw = std::fs::read_to_string(&o.cfg).map_err(|_| "ERR-TUYA-CAPTURE-CONFIG-001: cannot read cfg")?;
    let get = |k: &str| -> Result<String, &'static str> {
        cfg_field(&raw, k).ok_or("ERR-TUYA-CAPTURE-CONFIG-002: cfg missing required field")
    };
    let ip = get("ip")?;
    let port: u16 = get("port")?.parse().map_err(|_| "ERR-TUYA-CAPTURE-CONFIG-003: invalid port")?;
    let key_hex = get("local_key")?;
    let proto_str = cfg_field(&raw, "proto").unwrap_or_else(|| "3.5".to_owned());
    let proto = match proto_str.trim() {
        "3.4" | "v34" => Proto::V34,
        "3.5" | "v35" => Proto::V35,
        _ => return Err("ERR-TUYA-CAPTURE-CONFIG-004: proto must be 3.4 or 3.5"),
    };
    let local_key =
        parse_hex16(&key_hex).ok_or("ERR-TUYA-CAPTURE-CONFIG-005: local_key must be 32 hex chars")?;

    let addr: SocketAddr =
        format!("{ip}:{port}").parse().map_err(|_| "ERR-TUYA-CAPTURE-CONFIG-006: invalid ip:port")?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|_| "ERR-TUYA-CAPTURE-SESSION-001: tcp connect failed (unreachable or port closed)")?;
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(|_| "ERR-TUYA-CAPTURE-SESSION-001: socket options")?;
    let outcome = pump(&mut stream, local_key, proto, Duration::from_secs(o.secs));
    let proto_label = match proto {
        Proto::V34 => "3.4",
        Proto::V35 => "3.5",
    };
    Ok(format!(
        "{{\"schema\":\"{FORMAT}\",\"device\":\"{ip}:{port}\",\"proto\":\"{proto_label}\",\"owner_authorized\":true,\"established\":{established},\"frames_sent\":{frames_sent},\"frames_recv\":{frames_recv},\"heartbeats\":{heartbeats},\"dp_queries\":{dp_queries},\"dps\":{dps},\"error\":{error},\"media_continuity\":\"unverified\",\"note\":\"direct LAN session; device data points captured; Tuya video rides the OEM iotbing stream (not wired here)\"}}",
        established = outcome.established,
        frames_sent = outcome.frames_sent,
        frames_recv = outcome.frames_recv,
        heartbeats = outcome.heartbeats,
        dp_queries = outcome.dp_queries,
        dps = json_or_null(&outcome.last_dps),
        error = json_or_null(&outcome.error),
    ))
}

fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_or_null(v: &Option<String>) -> String {
    match v {
        Some(s) => json_string(s),
        None => "null".to_owned(),
    }
}

fn write_bounded<W: Write>(w: &mut W, bytes: &[u8]) -> io::Result<()> {
    w.write_all(bytes)
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).take(MAX_ARGS + 1).collect();
    if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help" | "-h")) {
        return match write_bounded(&mut io::stdout().lock(), HELP.as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        };
    }
    let options = match parse(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("ERR-TUYA-CAPTURE-ARGUMENT-001: {e}; use fss-capture-tuya --help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    let mut out = io::stdout().lock();
    match run(&options) {
        Ok(report) => match write_bounded(&mut out, (report + "\n").as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => {
                eprintln!("ERR-TUYA-CAPTURE-OUTPUT-001: report emission failed");
                ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
            }
        },
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_tuya::sim::{HomebaseSim, SimConfig};

    fn base_args() -> Vec<OsString> {
        ["--cfg", "/tmp/c.json", "--owner-authorized"].into_iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_minimal_args() {
        let o = parse(&base_args()).unwrap();
        assert_eq!(o.secs, 5);
        assert!(o.owner_authorized);
    }

    #[test]
    fn refuses_missing_owner_attestation() {
        let args: Vec<OsString> = ["--cfg", "/tmp/c.json"].into_iter().map(OsString::from).collect();
        let e = parse(&args).unwrap_err();
        assert!(e.contains("owner-authorized"), "{e}");
    }

    #[test]
    fn refuses_missing_cfg() {
        let args: Vec<OsString> = vec![OsString::from("--owner-authorized")];
        assert!(parse(&args).is_err());
    }

    #[test]
    fn refuses_out_of_bounds_secs() {
        let mut args = base_args();
        args.push(OsString::from("--secs"));
        args.push(OsString::from("0"));
        assert!(parse(&args).is_err());
        let mut args = base_args();
        args.push(OsString::from("--secs"));
        args.push(OsString::from("99999"));
        assert!(parse(&args).is_err());
    }

    #[test]
    fn cfg_field_flat_and_numeric() {
        let j = r#"{"ip":"192.0.2.10","port":6668,"local_key":"00112233445566778899aabbccddeeff","proto":"3.5"}"#;
        assert_eq!(cfg_field(j, "ip").as_deref(), Some("192.0.2.10"));
        assert_eq!(cfg_field(j, "port").as_deref(), Some("6668"));
        assert_eq!(cfg_field(j, "local_key").as_deref(), Some("00112233445566778899aabbccddeeff"));
        assert_eq!(cfg_field(j, "proto").as_deref(), Some("3.5"));
        assert!(cfg_field(j, "missing").is_none());
    }

    #[test]
    fn hex16_roundtrip_and_rejects() {
        let b = parse_hex16("00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(b, [0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255]);
        // 31 hex chars, non-hex char, and a 0x-prefixed 32-char all handled.
        assert!(parse_hex16("00112233445566778899aabbccddeef").is_none());
        assert!(parse_hex16("zz112233445566778899aabbccddeeff").is_none());
        assert_eq!(parse_hex16("0x00112233445566778899aabbccddeeff"), Some(b));
    }

    #[test]
    fn next_frame_never_yields_before_complete() {
        let mut sim = HomebaseSim::new(SimConfig::v35_homebase());
        let f1 = sim.beacon_udp_new();
        let mut acc = Vec::new();
        for (i, byte) in f1.iter().enumerate() {
            acc.push(*byte);
            let complete = i + 1 == f1.len();
            let got = next_frame(&mut acc);
            if complete {
                assert_eq!(got, Some(f1.clone()));
            } else {
                assert!(got.is_none(), "premature frame at byte {i}");
            }
        }
    }

    #[test]
    fn next_frame_splits_concatenated_frames() {
        let mut sim = HomebaseSim::new(SimConfig::v35_homebase());
        let f1 = sim.beacon_udp_new();
        let f2 = sim.beacon_lpv34();
        let mut buf = Vec::new();
        buf.extend_from_slice(&f1);
        buf.extend_from_slice(&f2);
        assert_eq!(next_frame(&mut buf), Some(f1.clone()));
        assert_eq!(next_frame(&mut buf), Some(f2.clone()));
        assert!(buf.is_empty());
    }

    /// End-to-end: the real pump over a real 127.0.0.1 TCP socket against the
    /// oracle-simulated homebase must negotiate and read the sim's live dps.
    #[test]
    fn loopback_negotiates_and_reads_dps() {
        let key = SimConfig::test_key();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
            let mut sim = HomebaseSim::new(SimConfig::v35_homebase());
            let mut buf: Vec<u8> = Vec::new();
            let mut tmp = [0u8; 8192];
            loop {
                match sock.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => break,
                }
                if buf.len() > MAX_BUF {
                    buf.clear();
                }
                while let Some(frame) = next_frame(&mut buf) {
                    let responses = sim.handle(&frame);
                    for r in responses {
                        if sock.write_all(&r).is_err() {
                            return sim.is_established();
                        }
                    }
                }
            }
            sim.is_established()
        });
        let outcome = {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
            pump(&mut stream, key, Proto::V35, Duration::from_secs(3))
        };
        assert!(outcome.established, "session must establish against the sim: {:?}", outcome.error);
        assert!(
            outcome.last_dps.as_deref().is_some_and(|d| d.contains("armed_away")),
            "dp_query must return the sim's dps: {:?}",
            outcome.last_dps
        );
        assert!(outcome.heartbeats >= 1, "at least one heartbeat in a 3s run");
        assert!(server.join().unwrap(), "sim must have established a session");
    }
}
