#![forbid(unsafe_code)]
//! Operator vertical slice: acquire a live TUTK camera stream into a REAL FSS
//! deployment — custody payloads staged root-last, evidence batches committed
//! to the deployment's durable ledger, inspectable afterward with `fss doctor`
//! / `fss orient`.
//!
//! Run:
//!   cargo run -p fss-reference --example tutk_acquire -- <cfg.json> <root> [--secs N] [--site S]
//!
//! <cfg.json> is the lab camera config (uid/enr/mac/ip, mode 600) — secrets
//! are read from the file and never printed. The deployment is opened (or
//! created) at <root> under the given site lineage (default
//! "site:lab:tutk:acquire"). Every run's batch identities carry the session
//! id, so repeated acquisitions never conflict.

use std::net::UdpSocket;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{OperationId, SensorId, StreamId};
use fss_reference::ingest::tutk::{
    AcquisitionState, AudioPolicy, TutkIngest, TutkIngestConfig, TutkIngestLimits,
};
use fss_reference::{ReferenceDeployment, ReplayCx};
use fss_tutk::session::SessionConfig;

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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: tutk_acquire <cfg.json> <root> [--secs N] [--site S]");
        std::process::exit(2);
    }
    let cfg_path = &args[1];
    let root = PathBuf::from(&args[2]);
    let flag = |name: &str| -> Option<String> {
        args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
    };
    let secs: u64 = flag("--secs").and_then(|v| v.parse().ok()).unwrap_or(30);
    let site = flag("--site").unwrap_or_else(|| "site:lab:tutk:acquire".into());

    let raw = std::fs::read_to_string(cfg_path).expect("read cfg");
    let get = |k: &str| cfg_field(&raw, k).unwrap_or_else(|| panic!("cfg missing {k}"));
    let (uid, enr, mac) = (get("uid"), get("enr"), get("mac"));
    let cam_ip = get("camera_ip");
    let cam_port: u16 = get("camera_port").parse().unwrap();
    let bind_ip = cfg_field(&raw, "bind_ip").unwrap_or_else(|| "0.0.0.0".into());

    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:tutk-acquire".into(),
        operation_id: OperationId::parse("op:tutk-acquire:01").expect("operation id"),
        principal: "principal:operator:tutk-acquire".into(),
        capabilities: vec![
            "ADP-REPLAY-001".to_owned(),
            "ADP-WYZE-V4-LAB-001".to_owned(),
            "CAP-ADAPTER-NET-001".to_owned(),
            "CAP-OBJECT-STAGE-001".to_owned(),
            "CAP-OBJECT-PUBLISH-001".to_owned(),
        ],
        deadline: None,
        priority: 10,
        budgets: fss_core::BudgetVector::builder()
            .bytes(1u64 << 30)
            .build()
            .expect("budget"),
        privacy_scope: "privacy:owner-authorized-lan".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: fss_core::ContentDigest::sha256(site.as_bytes()),
        generation: 1,
    })
    .expect("authority");
    let cx = ReplayCx::from_context_authority(&authority, &root).expect("replay cx");
    let mut deployment = ReferenceDeployment::open(&root, &site, &cx).expect("open deployment");

    let sock = UdpSocket::bind((bind_ip.as_str(), 0u16)).expect("bind");
    sock.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    let mut peer: std::net::SocketAddr = format!("{cam_ip}:{cam_port}").parse().unwrap();

    let seed = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
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
        sensor_id: SensorId::parse("sensor:tutk:acquire:01").unwrap(),
        stream_id: StreamId::parse("stream:tutk:acquire:01").unwrap(),
        site_lineage: site.clone(),
        audio: AudioPolicy::Disabled,
        limits: TutkIngestLimits::default(),
        known_tuples: vec![("HL_CAM4".to_string(), "4.52.17.26".to_string())],
    };
    let mut ing = TutkIngest::new(cfg).expect("construct ingest");

    println!("acquire: {cam_ip}:{cam_port} -> {} ({}s)", root.display(), secs);
    let t0 = Instant::now();
    let mut last_phase = ing.session_phase();
    let mut buf = [0u8; 65535];
    while t0.elapsed() < Duration::from_secs(secs) {
        let now_ns = t0.elapsed().as_nanos() as u64;
        while let Some(d) = ing.poll_send() {
            let _ = sock.send_to(&d, peer);
        }
        if let Ok((n, src)) = sock.recv_from(&mut buf) {
            if ing.session_phase() == fss_tutk::session::PhaseName::Discovery && src.ip() == peer.ip() {
                peer = src;
            }
            ing.feed_datagram(&buf[..n], now_ns);
        }
        ing.advance(now_ns);
        let phase = ing.session_phase();
        if phase != last_phase {
            println!("acquire: [{:6.2?}] phase {:?} -> {:?}", t0.elapsed(), last_phase, phase);
            last_phase = phase;
        }
        if matches!(
            ing.state(),
            AcquisitionState::Failed { .. } | AcquisitionState::Indeterminate { .. }
        ) {
            break;
        }
    }
    ing.flush().expect("flush");

    let stats = ing.stats();
    println!(
        "acquire: state={:?} capsules={} batches={} gaps={}",
        ing.state(),
        stats.capsules_committed,
        stats.batches_committed,
        stats.gaps
    );

    // Seal into the deployment as a decodable file-import-shaped custody
    // contract (RetainedFileImport-compatible): payloads staged, capsule
    // batches committed, fi- slot published, manifest batch completes gen 2.
    let seal = ing
        .seal_acquisition(&mut deployment, "HL_CAM4/4.52.17.26", &cx)
        .expect("seal acquisition");
    println!(
        "acquire: SEALED import={} manifest={} root={} batch={} capsules={} bytes={}",
        seal.import_identity,
        seal.manifest_digest,
        seal.import_root,
        seal.manifest_batch.as_str(),
        seal.capsule_count,
        seal.input_bytes
    );
    println!("acquire: inspect with: fss doctor --root {}", root.display());
}
