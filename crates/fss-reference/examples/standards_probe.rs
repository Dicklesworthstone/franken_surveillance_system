//! Live standards-probe runner (DISC-2 qualification): mDNS browse, SSDP
//! M-SEARCH and ONVIF WS-Discovery on the owner LAN, printing every answer.
//!
//! Run: cargo run -p fss-reference --example standards_probe -- [iface_ip] [seconds]

use std::net::Ipv4Addr;
use std::sync::atomic::AtomicBool;

use fss_reference::discovery::standards::{
    mdns_probe, ssdp_probe, wsdiscovery_probe, MDNS_CAMERA_TYPES,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let iface: Ipv4Addr = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(Ipv4Addr::new(192, 168, 4, 165));
    let seconds: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(8);
    let cancel = AtomicBool::new(false);

    println!("== mDNS (camera types, {seconds}s) ==");
    let answers = mdns_probe(iface, &MDNS_CAMERA_TYPES, seconds, &cancel);
    println!("mDNS answers: {}", answers.len());
    for a in &answers {
        println!(
            "  {} type={} ttl={} rdata={}",
            a.name, a.rr_type, a.ttl, a.rdata
        );
    }

    println!("== SSDP (M-SEARCH, {seconds}s) ==");
    let ssdp = ssdp_probe(iface, seconds, &cancel);
    println!("SSDP responses: {}", ssdp.len());
    let mut seen = std::collections::BTreeSet::new();
    for r in &ssdp {
        let key = (r.ip.clone(), r.st.clone(), r.usn.clone());
        if seen.insert(key) {
            println!(
                "  {} ST={} SERVER={} LOC={}",
                r.ip,
                r.st,
                r.server,
                &r.location[..r.location.len().min(60)]
            );
        }
    }

    println!("== ONVIF WS-Discovery (Probe, {seconds}s) ==");
    let wsd = wsdiscovery_probe(iface, seconds, &cancel);
    println!("Probe Matches: {}", wsd.len());
    for m in &wsd {
        println!("  {} xaddrs={:?} types={:?}", m.ip, m.xaddrs, m.types);
    }
    if wsd.is_empty() {
        println!("  (negative: no ONVIF responders — matches the 2026-10-07 census)");
    }
}
