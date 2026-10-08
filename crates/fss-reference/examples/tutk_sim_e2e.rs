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
    let mode = std::env::args().nth(1).unwrap_or_else(|| "normal".to_string());
    let port: u16 = match mode.as_str() {
        "normal" => 32881,
        "expired" => 32882,
        "revoked" => 32883,
        "flaky" => 32884,
        "legacy-key" => 32885,
        other => {
            eprintln!("FATAL: unknown mode {other} (normal|expired|revoked|flaky|legacy-key)");
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

    let cfg = TutkIngestConfig {
        session: SessionConfig {
            uid: "SIMCAMSIMCAMSIMCAM11".to_string(),
            enr: "sim-enr-16byte!!".to_string(),
            mac: "00AA11BB22CC".to_string(),
            audio: false,
            psk_truncated: false,
            seed: 0xCC51_2026_1007,
        },
        sensor_id: SensorId::parse("sensor:tutk:sim:01").unwrap(),
        stream_id: StreamId::parse("stream:tutk:sim:e2e:01").unwrap(),
        site_lineage: "site:lab:tutk:e2e".to_string(),
        audio: AudioPolicy::Disabled,
        limits: TutkIngestLimits::default(),
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
        if ing.stats().capsules_committed >= 30 && ing_pending(&ing) == 0 {
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
        _ => unreachable!(),
    }
    println!("e2e: {}", if failures == 0 { "ALL CHECKS PASSED" } else { "FAILURES PRESENT" });
    std::process::exit(if failures == 0 { 0 } else { 1 });
}

fn ing_pending(ing: &TutkIngest) -> u64 {
    ing.session_stats()
        .video_frames
        .saturating_sub(ing.stats().capsules_committed)
}
