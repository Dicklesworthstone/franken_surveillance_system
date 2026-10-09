//! Live Tuya beacon listener (DISC-4 qualification): listens on UDP :6667
//! and prints decoded beacons. The AOSU homebase broadcasts cmd 0x23 every
//! ~5s, so a 15s window captures ~3.
//!
//! Run: cargo run -p fss-reference --example tuya_listen -- [seconds]

use std::sync::atomic::AtomicBool;

use fss_reference::discovery::tuya_beacon::listen;

fn main() {
    let seconds: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(15);
    let cancel = AtomicBool::new(false);
    println!("listening on :6667 for {seconds}s...");
    let beacons = listen(seconds, 32, &cancel);
    println!("captured {} beacon(s)", beacons.len());
    for b in &beacons {
        println!(
            "  {} {} seq={} cmd=0x{:02X} {} crc={} payload={}B enc={:?} hint={}",
            b.source,
            b.frame,
            b.seqno,
            b.cmd,
            b.cmd_name,
            b.crc_good,
            b.payload_len,
            b.encrypted,
            b.version_hint
        );
        if let Some(json) = &b.payload_json {
            println!("    json: {json}");
        }
    }
}
