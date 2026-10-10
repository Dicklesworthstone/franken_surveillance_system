#![forbid(unsafe_code)]
//! TUTK OLD-protocol (0x0601) LAN-search probe driver — owner-authorized
//! LAN scope only (lab charter). Broadcast + directed modes, bounded retries,
//! no session, no credentials.
//!
//! Run: cargo run -p fss-tutk --example oldproto_probe -- <bind_ip> [target_ip ...]
//! Example: cargo run -p fss-tutk --example oldproto_probe -- 192.168.4.165

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use fss_tutk::oldproto::{build_probe, parse_response, ProbeResponse};

const PROBE_PORT: u16 = 32761;
const RETRIES: u32 = 3;
const LISTEN_MS: u64 = 1500;

fn main() {
    let bind_ip: Ipv4Addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0".into())
        .parse()
        .expect("bind ip");
    let directed: Vec<Ipv4Addr> = std::env::args().skip(2).map(|a| a.parse().unwrap()).collect();

    let sock = UdpSocket::bind((bind_ip, 0u16)).expect("bind");
    sock.set_broadcast(true).expect("broadcast");
    sock.set_read_timeout(Some(Duration::from_millis(150))).unwrap();

    // Deterministic probe identity for reproducible runs.
    let fingerprint = [0xF5, 0x05, 0x20, 0x26, 0x10, 0x08];
    let probe = build_probe(b"", 0x0601, fingerprint);
    println!("probe: 88-byte 0x0601 frame, {} rounds", RETRIES);

    let mut targets: Vec<SocketAddrV4> = vec![
        SocketAddrV4::new(Ipv4Addr::BROADCAST, PROBE_PORT),
        SocketAddrV4::new(Ipv4Addr::new(192, 168, 7, 255), PROBE_PORT), // lab /22 broadcast
    ];
    targets.extend(directed.iter().map(|ip| SocketAddrV4::new(*ip, PROBE_PORT)));

    let mut answers = 0u64;
    for round in 1..=RETRIES {
        for t in &targets {
            let _ = sock.send_to(&probe, t);
        }
        let end = Instant::now() + Duration::from_millis(LISTEN_MS);
        while Instant::now() < end {
            let mut buf = [0u8; 2048];
            let Ok((n, src)) = sock.recv_from(&mut buf) else {
                continue;
            };
            answers += 1;
            match parse_response(&buf[..n]) {
                ProbeResponse::Old { cmd, uid, stage } => println!(
                    "probe: ANSWER {src} OLD cmd=0x{cmd:04x} uid={uid:?} stage={stage:?} ({n}B)"
                ),
                ProbeResponse::NewProto { cmd } => {
                    println!("probe: ANSWER {src} NEW-0xCC51 cmd=0x{cmd:04x} ({n}B)")
                }
                ProbeResponse::Malformed => {
                    println!("probe: ANSWER {src} malformed ({n}B)")
                }
            }
        }
        println!("probe: round {round}/{RETRIES} done");
    }
    println!(
        "probe: complete — {answers} answer(s) (0 = negative evidence: no OLD-protocol TUTK devices answered)"
    );
}
