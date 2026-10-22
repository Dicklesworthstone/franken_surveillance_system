#![forbid(unsafe_code)]
//! `session_probe` — drive one live TUTK-NEW session against one camera from
//! the command line, with three interop/research knobs the production driver
//! does not expose:
//!
//! * `--identity` — replace the DTLS PSK identity. An identity starting with
//!   `AUTHTKN_` selects the legacy arbitrary-PSK path on unpatched firmware.
//! * `--encoders` / `--encoders-count` / `--k10000-file` — control the
//!   `audioEncoderList` array (the vendor parser's fixed-size stack array).
//! * `--ioctl` + `--payload-file` — send one raw IOCTRL once streaming.
//!
//! Secrets (ENR) arrive on argv; the probe never persists them.
//!
//! Usage:
//!   session_probe --ip IP --uid UID --enr ENR --mac MAC [options]
//!
//! Options: `--port N` (32761), `--secs N` (20), `--identity S`,
//! `--psk-hex H`, `--encoders a,b,c`, `--encoders-count N`,
//! `--k10000-file PATH`, `--ioctl N`, `--payload-file PATH`.

use std::net::UdpSocket;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use fss_tutk::session::{PhaseName, SessionConfig, SessionEvent, TutkSession};

#[derive(Debug, Default)]
struct Args {
    ip: String,
    port: u16,
    uid: String,
    enr: String,
    mac: String,
    secs: u64,
    identity: Option<String>,
    psk_hex: Option<Vec<u8>>,
    encoders: Option<Vec<u32>>,
    k10000: Option<String>,
    ioctl: Option<u16>,
    payload: Option<Vec<u8>>,
    capture: Option<String>,
    raw: Option<Vec<u8>>,
    raw_wrap: bool,
}

fn parse() -> Result<Args, String> {
    let mut a = Args { port: 32761, secs: 20, raw_wrap: true, ..Args::default() };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut v = || it.next().ok_or_else(|| format!("{k} needs a value"));
        match k.as_str() {
            "--ip" => a.ip = v()?,
            "--port" => a.port = v()?.parse().map_err(|_| "bad --port")?,
            "--uid" => a.uid = v()?,
            "--enr" => a.enr = v()?,
            "--mac" => a.mac = v()?,
            "--secs" => a.secs = v()?.parse().map_err(|_| "bad --secs")?,
            "--identity" => a.identity = Some(v()?),
            "--psk-hex" => a.psk_hex = Some(hex(v()?.as_bytes())?),
            "--encoders" => {
                let s = v()?;
                let mut out = Vec::new();
                for p in s.split(',').filter(|p| !p.is_empty()) {
                    out.push(p.trim().parse().map_err(|_| "bad --encoders item")?);
                }
                a.encoders = Some(out);
            }
            "--encoders-count" => {
                let n: u32 = v()?.parse().map_err(|_| "bad --encoders-count")?;
                a.encoders = Some((0..n).collect());
            }
            "--k10000-file" => {
                let p = v()?;
                a.k10000 = Some(std::fs::read_to_string(p).map_err(|_| "read k10000")?);
            }
            "--ioctl" => {
                let s = v()?;
                a.ioctl = Some(parse_u16(&s)?);
            }
            "--capture-dir" => a.capture = Some(v()?),
            "--raw-wrap" => a.raw_wrap = true,
            "--raw-file" => { let p = v()?; a.raw = Some(std::fs::read(p).map_err(|_| "read raw")?); }
            "--payload-file" => {
                let p = v()?;
                a.payload = Some(std::fs::read(p).map_err(|_| "read payload")?);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    for (name, ok) in [
        ("--ip", !a.ip.is_empty()),
        ("--uid", a.uid.len() == 20),
        ("--enr", !a.enr.is_empty()),
        ("--mac", !a.mac.is_empty()),
    ] {
        if !ok {
            return Err(format!("missing/invalid {name}"));
        }
    }
    Ok(a)
}

fn parse_u16(s: &str) -> Result<u16, String> {
    let t = s.trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(t, if s.starts_with("0x") || s.starts_with("0X") { 16 } else { 10 })
        .map_err(|_| "bad u16".to_string())
}

fn hex(s: &[u8]) -> Result<Vec<u8>, String> {
    let s: Vec<u8> = s.iter().copied().filter(|c| !c.is_ascii_whitespace()).collect();
    if s.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for c in s.chunks(2) {
        let hi = (c[0] as char).to_digit(16).ok_or("bad hex")?;
        let lo = (c[1] as char).to_digit(16).ok_or("bad hex")?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

fn main() -> ExitCode {
    let a = match parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("session_probe: {e}");
            return ExitCode::from(2);
        }
    };

    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0xCC51_2026)
        | 1;
    let cfg = SessionConfig {
        uid: a.uid.clone(),
        enr: a.enr.clone(),
        mac: a.mac.clone(),
        audio: false,
        psk_truncated: false,
        seed,
        known_tuples: vec![("HL_CAM4".into(), "4.52.17.26".into())],
        psk_identity: a.identity.clone(),
        psk_override: a.psk_hex.clone(),
        audio_encoder_list: a.encoders.clone(),
        k10000_json: a.k10000.clone(),
    };
    let mut sess = match TutkSession::new(cfg) {
        Some(s) => s,
        None => {
            eprintln!("session_probe: bad session config");
            return ExitCode::from(2);
        }
    };

    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("session_probe: bind: {e}");
            return ExitCode::from(2);
        }
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(2)));
    let mut peer: std::net::SocketAddr = match format!("{}:{}", a.ip, a.port).parse() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("session_probe: bad target address");
            return ExitCode::from(2);
        }
    };

    println!(
        "probe {} uid={} identity={} encoders={:?} ioctl={:?} secs={}",
        peer,
        a.uid,
        a.identity.as_deref().unwrap_or("(default)"),
        a.encoders.as_ref().map(Vec::len),
        a.ioctl,
        a.secs
    );

    let t0 = Instant::now();
    let mut last_phase = PhaseName::Discovery;
    let mut buf = [0u8; 65535];
    let mut sent_ioctl = false;
    let mut n = 0usize;
    let deadline = Duration::from_secs(a.secs);
    while t0.elapsed() < deadline {
        let now_ns = t0.elapsed().as_nanos() as u64;
        while let Some(d) = sess.poll_send() {
            let _ = sock.send_to(&d, peer);
        }
        if let Ok((n, src)) = sock.recv_from(&mut buf) {
            if src.ip() == peer.ip() && sess.phase() == PhaseName::Discovery {
                peer = src;
            }
            sess.feed_datagram(&buf[..n], now_ns);
        }
        sess.advance(now_ns);

        while let Some(ev) = sess.poll_event() {
            match &ev {
                SessionEvent::DiscoveryComplete { ticket, .. } => {
                    println!("[{}] discovery complete ticket={ticket}", t0.elapsed().as_millis())
                }
                SessionEvent::DtlsEstablished => println!("[{}] DTLS established", t0.elapsed().as_millis()),
                SessionEvent::LoginAccepted { .. } => println!("[{}] login accepted", t0.elapsed().as_millis()),
                SessionEvent::LoginRejected { response_type } => {
                    println!("[{}] login REJECTED 0x{response_type:02x}", t0.elapsed().as_millis())
                }
                SessionEvent::KAuthComplete { camera_info } => println!(
                    "[{}] K-auth ok: {}",
                    t0.elapsed().as_millis(),
                    camera_info
                ),
                SessionEvent::KAuthRejected { connection_res } => {
                    println!("[{}] K-auth rejected: {connection_res}", t0.elapsed().as_millis())
                }
                SessionEvent::KAuthQuarantined { model, firmware, .. } => {
                    println!("[{}] K-auth quarantined {model}/{firmware}", t0.elapsed().as_millis())
                }
                SessionEvent::StreamStarted { .. } => println!("[{}] STREAM STARTED", t0.elapsed().as_millis()),
                SessionEvent::Ioctl { cmd, payload } => {
                    let hexs: String = payload.iter().take(64).map(|b| format!("{b:02x} ")).collect();
                    println!(
                        "[{}] IOCTL from camera 0x{cmd:04x} {}B [{hexs}]",
                        t0.elapsed().as_millis(),
                        payload.len()
                    );
                    if let Some(dir) = &a.capture {
                        let path = format!("{dir}/cam_{cmd:04x}_{n:03}.bin");
                        if std::fs::write(&path, payload).is_ok() {
                            println!("     saved {path}");
                        }
                        n += 1;
                    }
                }
                SessionEvent::Frame(f) => {
                    if f.frame_no % 30 == 0 {
                        println!(
                            "[{}] frame {} ch{} {}B",
                            t0.elapsed().as_millis(),
                            f.frame_no,
                            f.channel,
                            f.au.len()
                        );
                    }
                }
                SessionEvent::Failed { stage, reason } => {
                    println!("[{}] FAILED {stage}: {reason}", t0.elapsed().as_millis())
                }
            }
            if matches!(ev, SessionEvent::Failed { .. }) {
                break;
            }
        }

        if sess.phase() != last_phase {
            println!(
                "[{}] phase {:?} -> {:?}",
                t0.elapsed().as_millis(),
                last_phase,
                sess.phase()
            );
            last_phase = sess.phase();
        }

        if !sent_ioctl
            && let Some(raw) = a.raw.as_ref()
            && sess.phase() == PhaseName::Streaming
        {
            let mut frame = Vec::with_capacity(12 + raw.len());
            if a.raw_wrap {
                frame.extend_from_slice(&[0x0c, 0, 0, 0]);
                frame.extend_from_slice(&sess.session_id());
            }
            frame.extend_from_slice(raw);
            sess.send_raw(&frame);
            sent_ioctl = true;
            println!("[{}] sent raw av {}B (wrapped={})", t0.elapsed().as_millis(), frame.len(), a.raw_wrap);
        }

        if !sent_ioctl
            && let Some(cmd) = a.ioctl
            && sess.phase() == PhaseName::Streaming
        {
            sess.send_ioctl(cmd, a.payload.as_deref().unwrap_or(&[]));
            sent_ioctl = true;
            println!(
                "[{}] sent ioctl 0x{cmd:04x} ({}B)",
                t0.elapsed().as_millis(),
                a.payload.as_ref().map(Vec::len).unwrap_or(0)
            );
        }

        if sess.phase() == PhaseName::Terminal {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    let st = sess.stats();
    println!(
        "probe end phase={:?} frames={} gaps={} acks={}",
        sess.phase(),
        st.video_frames,
        st.continuity_gaps,
        st.acks_sent
    );
    ExitCode::SUCCESS
}
