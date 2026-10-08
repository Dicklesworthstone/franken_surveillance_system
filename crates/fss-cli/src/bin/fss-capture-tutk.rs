#![forbid(unsafe_code)]
//! fss-capture-tutk — operator command: acquire a live TUTK/IOTC NEW-protocol
//! (0xCC51) owner-authorized camera into a durable FSS deployment.
//!
//! The camera cfg (uid/enr/mac/ip) is read from a secrets file (mode 600
//! expected); secrets never appear in argv, reports, or logs. The report JSON
//! (`fss.tutk_capture_cli.v1`) is the machine contract; the human text is
//! secondary. Cancellation is request→drain→finalize via ReplayCx.

use std::ffi::OsString;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use fss_cli::ExitIdentity;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId, SensorId, StreamId};
use fss_reference::ReplayCx;
use fss_reference::ingest::tutk::{
    AcquisitionState, AudioPolicy, TutkIngest, TutkIngestConfig, TutkIngestLimits,
};
use fss_reference::ReferenceDeployment;
use fss_tutk::session::SessionConfig;

const HELP: &str = "fss-capture-tutk --root ARCHIVE_DIR --cfg CAMERA_CFG [--secs N] [--site LINEAGE]\n\
                    \x20 [--sensor-id ID] [--stream-id ID] [--principal ID] --owner-authorized\n\
                    \n\
                    Acquire a live owner-authorized TUTK (0xCC51) camera into a durable deployment.\n\
                    The cfg JSON (mode 600) holds uid/enr/mac/camera_ip/camera_port[/bind_ip];\n\
                    secrets are never printed. --owner-authorized attests the device is yours.\n\
                    Report: fss.tutk_capture_cli.v1 JSON on stdout.";

const FORMAT: &str = "fss.tutk_capture_cli.v1";
const MAX_ARGS: usize = 24;

#[derive(Debug)]
struct Options {
    root: PathBuf,
    cfg: PathBuf,
    secs: u64,
    site: String,
    sensor_id: String,
    stream_id: String,
    principal: String,
    owner_authorized: bool,
}

fn parse(args: &[OsString]) -> Result<Options, &'static str> {
    if args.is_empty() || args.len() > MAX_ARGS || args.iter().any(|s| s.as_encoded_bytes().len() > 4096) {
        return Err("invalid argument count or bound");
    }
    let mut o = Options {
        root: PathBuf::new(),
        cfg: PathBuf::new(),
        secs: 30,
        site: "site:lab:tutk:acquire".to_owned(),
        sensor_id: "sensor:tutk:acquire:01".to_owned(),
        stream_id: "stream:tutk:acquire:01".to_owned(),
        principal: "principal:operator:tutk-capture".to_owned(),
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
            "--root" => o.root = PathBuf::from(need_value(i)?),
            "--cfg" => o.cfg = PathBuf::from(need_value(i)?),
            "--secs" => {
                let v = need_value(i)?;
                o.secs = v.to_str().and_then(|s| s.parse().ok()).ok_or("invalid --secs")?;
                if o.secs == 0 || o.secs > 86_400 {
                    return Err("--secs out of bounds");
                }
            }
            "--site" => {
                o.site = need_value(i)?.to_str().ok_or("invalid --site")?.to_owned();
            }
            "--sensor-id" => {
                o.sensor_id = need_value(i)?.to_str().ok_or("invalid --sensor-id")?.to_owned();
            }
            "--stream-id" => {
                o.stream_id = need_value(i)?.to_str().ok_or("invalid --stream-id")?.to_owned();
            }
            "--principal" => {
                o.principal = need_value(i)?.to_str().ok_or("invalid --principal")?.to_owned();
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
    if o.root.as_os_str().is_empty() {
        return Err("--root is required");
    }
    if o.cfg.as_os_str().is_empty() {
        return Err("--cfg is required");
    }
    if !o.owner_authorized {
        return Err("--owner-authorized attestation is required for live device access");
    }
    Ok(o)
}

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

fn run(o: &Options) -> Result<String, &'static str> {
    let raw = std::fs::read_to_string(&o.cfg).map_err(|_| "ERR-TUTK-CAPTURE-CONFIG-001: cannot read cfg")?;
    let get = |k: &str| -> Result<String, &'static str> {
        cfg_field(&raw, k).ok_or("ERR-TUTK-CAPTURE-CONFIG-002: cfg missing required field")
    };
    let (uid, enr, mac) = (get("uid")?, get("enr")?, get("mac")?);
    let cam_ip = get("camera_ip")?;
    let cam_port: u16 = get("camera_port")?
        .parse()
        .map_err(|_| "ERR-TUTK-CAPTURE-CONFIG-003: invalid camera_port")?;
    let bind_ip = cfg_field(&raw, "bind_ip").unwrap_or_else(|| "0.0.0.0".into());

    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: format!("trace:tutk-capture:{}", o.site),
        operation_id: OperationId::parse("op:tutk-capture:01")
            .map_err(|_| "ERR-TUTK-CAPTURE-AUTHORITY-001: operation id")?,
        principal: o.principal.clone(),
        capabilities: vec![
            "ADP-REPLAY-001".to_owned(),
            "ADP-WYZE-V4-LAB-001".to_owned(),
            "CAP-ADAPTER-NET-001".to_owned(),
            "CAP-OBJECT-STAGE-001".to_owned(),
            "CAP-OBJECT-PUBLISH-001".to_owned(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(1u64 << 30)
            .build()
            .map_err(|_| "ERR-TUTK-CAPTURE-AUTHORITY-002: budgets")?,
        privacy_scope: "privacy:owner-authorized-lan".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: fss_core::ContentDigest::sha256(o.site.as_bytes()),
        generation: 1,
    })
    .map_err(|_| "ERR-TUTK-CAPTURE-AUTHORITY-003: authority rejected")?;
    let cx = ReplayCx::from_context_authority(&authority, &o.root)
        .map_err(|_| "ERR-TUTK-CAPTURE-AUTHORITY-004: replay context refused")?;
    let mut deployment = ReferenceDeployment::open(&o.root, &o.site, &cx)
        .map_err(|_| "ERR-TUTK-CAPTURE-DEPLOYMENT-001: open failed")?;

    let result = (|| -> Result<String, &'static str> {
        let sock = std::net::UdpSocket::bind((bind_ip.as_str(), 0u16))
            .map_err(|_| "ERR-TUTK-CAPTURE-SESSION-001: socket bind failed")?;
        sock.set_read_timeout(Some(Duration::from_millis(20)))
            .map_err(|_| "ERR-TUTK-CAPTURE-SESSION-001: socket options failed")?;
        let mut peer: SocketAddr = format!("{cam_ip}:{cam_port}")
            .parse()
            .map_err(|_| "ERR-TUTK-CAPTURE-CONFIG-003: invalid camera address")?;

        let seed = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "ERR-TUTK-CAPTURE-SESSION-002: clock")?
            .as_nanos() as u64)
            | 1;
        let cfg = TutkIngestConfig {
            session: SessionConfig {
                uid,
                enr,
                mac,
                audio: false,
                psk_truncated: false,
                seed,
                known_tuples: vec![("HL_CAM4".to_string(), "4.52.17.26".to_string())],
            },
            sensor_id: SensorId::parse(&o.sensor_id)
                .map_err(|_| "ERR-TUTK-CAPTURE-ARGUMENT-002: sensor id")?,
            stream_id: StreamId::parse(&o.stream_id)
                .map_err(|_| "ERR-TUTK-CAPTURE-ARGUMENT-003: stream id")?,
            site_lineage: o.site.clone(),
            audio: AudioPolicy::Disabled,
            limits: TutkIngestLimits::default(),
            known_tuples: vec![("HL_CAM4".to_string(), "4.52.17.26".to_string())],
        };
        let mut ing = TutkIngest::new(cfg).map_err(|_| "ERR-TUTK-CAPTURE-SESSION-003: config")?;

        let t0 = Instant::now();
        let mut buf = [0u8; 65535];
        while t0.elapsed() < Duration::from_secs(o.secs) {
            let now_ns = t0.elapsed().as_nanos() as u64;
            while let Some(d) = ing.poll_send() {
                let _ = sock.send_to(&d, peer);
            }
            if let Ok((n, src)) = sock.recv_from(&mut buf) {
                if ing.session_phase() == fss_tutk::session::PhaseName::Discovery
                    && src.ip() == peer.ip()
                {
                    peer = src;
                }
                ing.feed_datagram(&buf[..n], now_ns);
            }
            ing.advance(now_ns);
            if matches!(
                ing.state(),
                AcquisitionState::Failed { .. } | AcquisitionState::Indeterminate { .. }
            ) {
                break;
            }
        }
        ing.flush().map_err(|_| "ERR-TUTK-CAPTURE-SESSION-004: flush failed")?;

        let stats = ing.stats();
        let sess = ing.session_stats();
        let state_text = format!("{:?}", ing.state());

        // Seal into the deployment as a decodable file-import-shaped custody
        // contract: payloads staged, capsule batches committed, fi- slot
        // published, manifest batch completes the import at generation 2.
        let seal = ing
            .seal_acquisition(&mut deployment, "HL_CAM4/4.52.17.26", &cx)
            .map_err(|_| "ERR-TUTK-CAPTURE-COMMIT-002: seal refused")?;
        let committed = vec![seal.manifest_batch.as_str().to_owned()];
        let staged = (seal.capsule_count * 2) as u64;
        let frames = sess.video_frames;
        Ok(format!(
            "{{\"schema\":\"{FORMAT}\",\"site\":\"{}\",\"root\":\"{}\",\"state\":{},\"frames\":{},\"capsules\":{},\"batches\":{},\"gaps\":{},\"resync_bytes\":{},\"acks\":{},\"custody_staged\":{},\"anchors\":{:?}}}",
            o.site,
            o.root.display(),
            json_string(&state_text),
            frames,
            stats.capsules_committed,
            stats.batches_committed,
            stats.gaps,
            sess.resync_bytes,
            sess.acks_sent,
            staged,
            committed
        ))
    })();
    cx.drain_and_finalize();
    result
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
            eprintln!("ERR-TUTK-CAPTURE-ARGUMENT-001: {e}; use fss-capture-tutk --help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    let mut out = io::stdout().lock();
    match run(&options) {
        Ok(report) => match write_bounded(&mut out, (report + "\n").as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => {
                eprintln!("ERR-TUTK-CAPTURE-OUTPUT-001: report emission failed");
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

    fn base_args() -> Vec<OsString> {
        [
            "--root", "/tmp/x", "--cfg", "/tmp/c.json", "--owner-authorized",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn parses_minimal_args() {
        let o = parse(&base_args()).unwrap();
        assert_eq!(o.secs, 30);
        assert!(o.owner_authorized);
    }

    #[test]
    fn refuses_missing_owner_attestation() {
        let args: Vec<OsString> = ["--root", "/tmp/x", "--cfg", "/tmp/c.json"]
            .into_iter()
            .map(OsString::from)
            .collect();
        let e = parse(&args).unwrap_err();
        assert!(e.contains("owner-authorized"), "{e}");
    }

    #[test]
    fn refuses_missing_root_and_cfg() {
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
    fn json_string_escapes() {
        assert_eq!(json_string("a\"b\\c"), "\"a\\\"b\\\\c\"");
    }

    #[test]
    fn cfg_field_flat() {
        let j = r#"{"uid":"ABCDEFGH","camera_port":32761}"#;
        assert_eq!(cfg_field(j, "uid").as_deref(), Some("ABCDEFGH"));
        assert_eq!(cfg_field(j, "camera_port").as_deref(), Some("32761"));
        assert!(cfg_field(j, "missing").is_none());
    }
}
