//! End-to-end qualification: TUTK live adapter vs the Python TUTK-NEW camera
//! simulator (LAB-WYZE-4, fss-x4a.21.2.4) over loopback UDP.
//!
//! Spawns `sim_camera.py --mode normal` with the canned 30-frame H.264 clip,
//! drives `TutkIngest` through discovery → DTLS → AV login → K-auth → stream,
//! and verifies the acquisition lifecycle, capsule custody, ledger batches,
//! and a BYTE-IDENTICAL reassembled clip (codec passthrough proof).
//!
//! Run:
//!   cargo run -p fss-reference --example tutk_sim_e2e
//!
//! Requires the interop lab checkout at ~/projects/fss-interop-lab (override
//! with FSS_INTEROP_LAB=/path). Detailed log lines go to stdout.

use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use fss_core::{SensorId, StreamId};
use fss_reference::ingest::tutk::{
    AcquisitionState, AudioPolicy, TutkIngest, TutkIngestConfig, TutkIngestLimits,
};
use fss_tutk::session::SessionConfig;

fn lab_root() -> PathBuf {
    std::env::var("FSS_INTEROP_LAB")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(std::env::var("HOME").unwrap()).join("projects/fss-interop-lab"))
}

struct SimGuard(Child);
impl Drop for SimGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn main() {
    let lab = lab_root();
    let py = lab.join("venv/bin/python3");
    let sim = lab.join("wyze_newproto/sim/sim_camera.py");
    let fixture = lab.join("wyze_newproto/out_5905/stream.h264");
    for p in [&py, &sim, &fixture] {
        if !p.exists() {
            eprintln!("FATAL: missing {}", p.display());
            std::process::exit(2);
        }
    }
    // `live <cfg.json>`: run against a real owner-authorized camera over the
    // LAN (the simulator-vs-live differential). Secrets stay in the cfg file;
    // nothing secret is printed. The allowlist carries the lab-proven tuple;
    // if the camera drifted, the quarantine reason reports the exact new one.
    if std::env::args().nth(1).as_deref() == Some("live") {
        let cfg_path = std::env::args().nth(2).unwrap_or_else(|| {
            eprintln!("FATAL: live lane needs a cfg path: tutk_sim_e2e live <cfg.json>");
            std::process::exit(2);
        });
        let soak_secs = std::env::args().nth(3).and_then(|v| v.parse::<u64>().ok());
        live_lane(&cfg_path, soak_secs);
    }

    let mode = std::env::args().nth(1).unwrap_or_else(|| "normal".to_string());
    let port: u16 = match mode.as_str() {
        "normal" => 32881,
        "expired" => 32882,
        "revoked" => 32883,
        "flaky" => 32884,
        "legacy-key" => 32885,
        "drift" => 32886,
        "malformed" => 32887,
        "drop" => 32888,
        other => {
            eprintln!("FATAL: unknown mode {other} (normal|expired|revoked|flaky|legacy-key|drift|malformed|drop)");
            std::process::exit(2);
        }
    };

    println!("e2e: spawning simulator on 127.0.0.1:{port} mode={mode}");
    let child = Command::new(&py)
        .arg(&sim)
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--mode")
        .arg(&mode)
        .arg("--av-clip")
        .arg(&fixture)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn simulator");
    let _guard = SimGuard(child);
    std::thread::sleep(Duration::from_millis(900));

    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind client socket");
    sock.connect(("127.0.0.1", port)).expect("connect");
    sock.set_read_timeout(Some(Duration::from_millis(20))).unwrap();

    // drift lane: empty allowlist — the unknown tuple itself must quarantine
    let sim_tuples: Vec<(String, String)> = if mode == "drift" {
        Vec::new()
    } else {
        vec![("SIM-CAM".to_string(), "9.99.0.SIM".to_string())]
    };
    let cfg = TutkIngestConfig {
        session: SessionConfig {
            uid: "SIMCAMSIMCAMSIMCAM11".to_string(),
            enr: "sim-enr-16byte!!".to_string(),
            mac: "00AA11BB22CC".to_string(),
            audio: false,
            psk_truncated: false,
            seed: 0xCC51_2026_1007,
            known_tuples: sim_tuples.clone(),
        },
        sensor_id: SensorId::parse("sensor:tutk:sim:01").unwrap(),
        stream_id: StreamId::parse("stream:tutk:sim:e2e:01").unwrap(),
        site_lineage: "site:lab:tutk:e2e".to_string(),
        audio: AudioPolicy::Disabled,
        limits: TutkIngestLimits::default(),
        known_tuples: sim_tuples,
    };

    let mut ing = TutkIngest::new(cfg).expect("construct ingest");

    let t0 = Instant::now();
    let mut now_ns: u64 = 0;
    let mut last_phase = ing.session_phase();
    let mut frames_seen = 0u64;
    let mut aus: Vec<Vec<u8>> = Vec::new();
    println!("e2e: pumping (deadline 45s)");
    let mut buf = [0u8; 65535];
    while t0.elapsed() < Duration::from_secs(45) {
        now_ns = t0.elapsed().as_nanos() as u64; // session clock = driver clock
        while let Some(d) = ing.poll_send() {
            let _ = sock.send(&d);
        }
        match sock.recv(&mut buf) {
            Ok(n) => ing.feed_datagram(&buf[..n], now_ns),
            Err(_) => {}
        }
        ing.advance(now_ns);
        let phase = ing.session_phase();
        if phase != last_phase {
            println!("e2e: [{:6.2?}] phase {:?} -> {:?}", t0.elapsed(), last_phase, phase);
            last_phase = phase;
        }
        let committed = ing.stats().capsules_committed + ing_pending(&ing);
        if committed > frames_seen {
            frames_seen = committed;
            println!(
                "e2e: [{:6.2?}] capsules={} state={:?}",
                t0.elapsed(),
                committed,
                ing.state()
            );
        }
        if matches!(ing.state(), AcquisitionState::Failed { .. } | AcquisitionState::Indeterminate { .. }) {
            break;
        }
        // Stop the moment the requested frames are reassembled: the batch
        // commit happens at flush(), so waiting on capsules_committed would
        // pump into the stream-silence budget after a finite clip ends.
        if ing.session_stats().video_frames >= 30 {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let _ = ing.flush();

    // collect AUs from custody via the ledger deltas (witness digests)
    let mut au_concat = Vec::new();
    for batch in ing.ledger().batches() {
        for delta in &batch.deltas {
            if let Some(au_digest) = delta.witness_digest {
                let au = ing.custody(&au_digest).expect("au in custody");
                aus.push(au.to_vec());
                au_concat.extend_from_slice(au);
            }
        }
    }

    let fixture_bytes = std::fs::read(&fixture).expect("read fixture");
    let state = format!("{:?}", ing.state());
    let stats = ing.stats();
    let sess = ing.session_stats();

    println!("e2e: ---- results ----");
    println!("e2e: final state            : {state}");
    println!("e2e: capsules committed     : {}", stats.capsules_committed);
    println!("e2e: batches committed      : {}", stats.batches_committed);
    println!("e2e: continuity gaps        : {}", stats.gaps);
    println!("e2e: video frames (session) : {}", sess.video_frames);
    println!("e2e: audio dropped (policy) : {}", sess.audio_frames_dropped);
    println!("e2e: acks sent              : {}", sess.acks_sent);
    println!("e2e: AU frames collected    : {}", aus.len());
    println!("e2e: AU concat bytes        : {}", au_concat.len());
    println!("e2e: fixture bytes          : {}", fixture_bytes.len());

    let mut failures = 0;
    let mut check = |name: &str, ok: bool| {
        println!("e2e: {:<34} {}", name, if ok { "PASS" } else { "FAIL" });
        if !ok {
            failures += 1;
        }
    };
    match mode.as_str() {
        "normal" | "legacy-key" => {
            check("lifecycle ContinuityVerified", matches!(ing.state(), AcquisitionState::ContinuityVerified { .. }));
            check("30 capsules committed", stats.capsules_committed == 30);
            check("no continuity gaps", stats.gaps == 0);
            check("ledger batches present", stats.batches_committed >= 1);
            check("clip byte-identical (passthrough)", au_concat == fixture_bytes);
        }
        "expired" | "revoked" => {
            check("login refusal -> Failed", matches!(ing.state(), AcquisitionState::Failed { .. }));
            check("no capsules from refused login", stats.capsules_committed == 0);
        }
        "flaky" => {
            check("dropped session -> terminal honesty",
                matches!(ing.state(), AcquisitionState::Failed { .. } | AcquisitionState::Indeterminate { .. }));
            check("no capsules from dead session", stats.capsules_committed == 0);
        }
        "drift" => {
            match ing.state() {
                AcquisitionState::Failed { reason } => {
                    check("drift quarantine -> Failed", reason.contains("quarantine"));
                }
                other => check(&format!("drift quarantine -> Failed (got {other:?})"), false),
            }
            check("no capsules from quarantined camera", stats.capsules_committed == 0);
        }
        "malformed" => {
            match ing.state() {
                AcquisitionState::Failed { reason } => {
                    check("garbage discovery -> Failed", reason.contains("discovery"));
                }
                other => check(&format!("garbage discovery -> Failed (got {other:?})"), false),
            }
            check("no capsules from malformed peer", stats.capsules_committed == 0);
        }
        "drop" => {
            match ing.state() {
                AcquisitionState::Failed { reason } => {
                    check("camera vanish -> stream-silence Failed", reason.contains("silent"));
                }
                other => check(&format!("camera vanish -> Failed (got {other:?})"), false),
            }
            // frames received before the vanish are committed (honest partial custody)
            check("partial capsules before drop committed", stats.capsules_committed > 0 && stats.capsules_committed < 30);
        }
        _ => unreachable!(),
    }
    println!("e2e: {}", if failures == 0 { "ALL CHECKS PASSED" } else { "FAILURES PRESENT" });
    std::process::exit(if failures == 0 { 0 } else { 1 });
}
/// Flat JSON string/number field extraction for the lab cfg files
/// ({"key":"value"} or {"key":123}); sufficient for the flat cfg schema.
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

/// Simulator-vs-live differential: run the adapter against a real
/// owner-authorized camera over the LAN. Secrets stay in the cfg file; only
/// state/counters/tuple are printed.
fn live_lane(cfg_path: &str, soak_secs: Option<u64>) -> ! {
    let raw = std::fs::read_to_string(cfg_path).expect("read cfg");
    let get = |k: &str| cfg_field(&raw, k).unwrap_or_else(|| panic!("cfg missing {k}"));
    let (uid, enr, mac) = (get("uid"), get("enr"), get("mac"));
    let cam_ip = get("camera_ip");
    let cam_port: u16 = get("camera_port").parse().unwrap();
    let bind_ip = cfg_field(&raw, "bind_ip").unwrap_or_else(|| "0.0.0.0".into());
    let audio = cfg_field(&raw, "audio").is_some_and(|v| v == "true" || v == "1");
    let psk_truncated = cfg_field(&raw, "psk_truncated").is_some_and(|v| v == "true" || v == "1")
        || cfg_field(&raw, "dtls_nonce_legacy").is_some_and(|v| v == "true" || v == "1");

    println!("live: target {cam_ip}:{cam_port} (credentials loaded, not printed)");
    // Unconnected socket + send_to/recv_from: live cameras answer discovery
    // from a DIFFERENT source port and the session must adopt it (live-proven
    // 2026-10-07: responses arrived from 44650, not 32761).
    let sock = UdpSocket::bind((bind_ip.as_str(), 0u16)).expect("bind");
    sock.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    let mut peer: std::net::SocketAddr = format!("{cam_ip}:{cam_port}").parse().unwrap();


    let cfg = TutkIngestConfig {
        session: SessionConfig {
            uid,
            enr,
            mac,
            audio,
            psk_truncated,
            seed: 0xCC51_2026_1008,
            known_tuples: vec![("HL_CAM4".to_string(), "4.52.17.26".to_string())],
        },
        sensor_id: SensorId::parse("sensor:tutk:live:01").unwrap(),
        stream_id: StreamId::parse("stream:tutk:live:01").unwrap(),
        site_lineage: "site:lab:tutk:live".to_string(),
        audio: if audio { AudioPolicy::Enabled } else { AudioPolicy::Disabled },
        limits: TutkIngestLimits::default(),
        known_tuples: vec![("HL_CAM4".to_string(), "4.52.17.26".to_string())],
    };
    let mut ing = TutkIngest::new(cfg).expect("construct ingest");

    let t0 = Instant::now();
    let mut last_phase = ing.session_phase();
    let mut buf = [0u8; 65535];
    let deadline = soak_secs.unwrap_or(60);
    println!("live: pumping (deadline {deadline}s real{})", soak_secs.map(|_| ", soak").unwrap_or(""));
    let mut bytes_received = 0u64;
    while t0.elapsed() < Duration::from_secs(deadline) {
        let now_ns = t0.elapsed().as_nanos() as u64;
        while let Some(d) = ing.poll_send() {
            let _ = sock.send_to(&d, peer);
        }
        if let Ok((n, src)) = sock.recv_from(&mut buf) {
            bytes_received += n as u64;
            // adopt the responder's address during discovery (live port hop)
            if ing.session_phase() == fss_tutk::session::PhaseName::Discovery && src.ip() == peer.ip() {
                peer = src;
            }
            ing.feed_datagram(&buf[..n], now_ns);
        }
        ing.advance(now_ns);
        let phase = ing.session_phase();
        if phase != last_phase {
            println!("live: [{:6.2?}] phase {:?} -> {:?}", t0.elapsed(), last_phase, phase);
            last_phase = phase;
        }
        if matches!(
            ing.state(),
            AcquisitionState::Failed { .. } | AcquisitionState::Indeterminate { .. }
        ) {
            break;
        }
        if soak_secs.is_none() && ing.stats().capsules_committed >= 30 {
            break;
        }
    }
    let _ = ing.flush();
    let stats = ing.stats();
    let sess = ing.session_stats();
    println!("live: ---- results ----");
    println!("live: final state        : {:?}", ing.state());
    println!("live: capsules committed : {}", stats.capsules_committed);
    println!("live: batches committed  : {}", stats.batches_committed);
    println!("live: continuity gaps    : {}", stats.gaps);
    println!("live: session frames     : {}", sess.video_frames);
    println!("live: acks sent          : {}", sess.acks_sent);
    println!("live: resync bytes       : {}", sess.resync_bytes);
    let wall = t0.elapsed();
    println!("live: ---- cost rows ----");
    println!("live: wall_s               : {:.1}", wall.as_secs_f64());
    println!("live: bytes_received       : {}", bytes_received);
    println!("live: bitrate_kbps         : {:.0}", (bytes_received * 8) as f64 / wall.as_secs_f64() / 1000.0);
    println!("live: frames_per_sec       : {:.1}", sess.video_frames as f64 / wall.as_secs_f64());
    println!("live: capsules_per_sec     : {:.1}", stats.capsules_committed as f64 / wall.as_secs_f64());
    println!("live: reconnects           : 0 (none requested)");

    let mut failures = 0;
    let mut check = |name: &str, ok: bool| {
        println!("live: {:<38} {}", name, if ok { "PASS" } else { "FAIL" });
        if !ok {
            failures += 1;
        }
    };
    check(
        "frames observed (FirstFrameObserved+)",
        matches!(
            ing.state(),
            AcquisitionState::FirstFrameObserved { .. } | AcquisitionState::ContinuityVerified { .. }
        ),
    );
    check("30 capsules committed", stats.capsules_committed >= 30);
    if soak_secs.is_some() {
        check("soak: streaming sustained to deadline", wall.as_secs() + 5 >= deadline);
        check("soak: zero resync bytes", sess.resync_bytes == 0);
    }
    check("ledger batches present", stats.batches_committed >= 1);
    println!(
        "live: continuity note   : {} gap(s) on the live path (data, not failure)",
        stats.gaps
    );
    println!("live: {}", if failures == 0 { "ALL CHECKS PASSED" } else { "FAILURES PRESENT" });
    std::process::exit(if failures == 0 { 0 } else { 1 });
}


fn ing_pending(ing: &TutkIngest) -> u64 {
    ing.session_stats()
        .video_frames
        .saturating_sub(ing.stats().capsules_committed)
}
