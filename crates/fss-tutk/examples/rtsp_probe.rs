//! Owner-authorized LAN probe: open a TUTK session and send one vendor
//! IOCTRL command after the camera starts streaming (used to enable the Wyze
//! RTSP server, HL cmd `0x29e9`, without the app or cloud).
//!
//! Usage: rtsp_probe <uid> <enr> <mac> <ip> <port> <hl_cmd_hex> <json> <secs>

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use fss_tutk::session::{SessionConfig, SessionEvent, TutkSession};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 8 {
        eprintln!("usage: rtsp_probe <uid> <enr> <mac> <ip> <port> <hl_cmd_hex> <json> <secs>");
        std::process::exit(2);
    }
    let cmd = u16::from_str_radix(&args[5], 16).expect("hl cmd hex");
    let peer: std::net::SocketAddr = format!("{}:{}", args[3], args[4]).parse().expect("peer");
    let secs: u64 = args[7].parse().expect("secs");
    

    let cfg = SessionConfig {
        uid: args[0].clone(),
        enr: args[1].clone(),
        mac: args[2].clone(),
        audio: false,
        psk_truncated: false,
        seed: 0x5eed_2026_1022,
        known_tuples: vec![
            ("HL_CAM4".to_string(), "4.52.17.26".to_string()),
            ("HL_CAM4".to_string(), "4.52.9.6119".to_string()),
        ],
        psk_identity: None,
        psk_override: None,
        audio_encoder_list: None,
        k10000_json: None,
    };
    let mut session = TutkSession::new(cfg).expect("session");
    let sock = UdpSocket::bind("0.0.0.0:0").expect("bind");
    sock.set_read_timeout(Some(Duration::from_millis(5)))
        .expect("timeout");
    let mut peer = peer;

    let t0 = Instant::now();
    let mut sent = false;
    let mut streamed_at: Option<Instant> = None;
    let mut buf = [0u8; 65535];

    while t0.elapsed() < Duration::from_secs(secs) {
        let now = t0.elapsed().as_nanos() as u64;
        session.advance(now);
        while let Some(datagram) = session.poll_send() {
            let _ = sock.send_to(&datagram, peer);
        }
        if let Ok((n, src)) = sock.recv_from(&mut buf) {
            if session.phase() == fss_tutk::session::PhaseName::Discovery && src.ip() == peer.ip() {
                peer = src;
            }
            if n > 0 {
                session.feed_datagram(&buf[..n], now);
            }
        }
        while let Some(event) = session.poll_event() {
            match &event {
                SessionEvent::StreamStarted { payload } => {
                    println!("stream_started {}B", payload.len());
                    streamed_at = Some(Instant::now());
                }
                SessionEvent::Failed { stage, reason } => {
                    eprintln!("failed {stage}: {reason}");
                    std::process::exit(1);
                }
                other => println!("event {other:?}"),
            }
        }
        if !sent {
            if let Some(at) = streamed_at {
                if at.elapsed() > Duration::from_millis(400) {
                    let payload = match args[6].strip_prefix("hex:") {
                        Some(h) => (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i+2], 16).unwrap()).collect::<Vec<u8>>(),
                        None => args[6].as_bytes().to_vec(),
                    };
                    session.send_ioctl(cmd, &payload);
                    sent = true;
                    println!("sent hl {cmd:#06x}");
                }
            }
        }
    }
    println!("done");
}
