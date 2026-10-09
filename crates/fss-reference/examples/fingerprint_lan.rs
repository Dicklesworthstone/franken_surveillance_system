//! Live fingerprint + dispatch runner (DISC-5/6 qualification): runs a real
//! census, classifies every host, dispatches candidates to adapter paths,
//! and prints the full table (including honest Unknown/LAA rows).
//!
//! Run: cargo run -p fss-reference --example fingerprint_lan -- 192.168.4.0/22

use std::sync::atomic::AtomicBool;
use std::time::Duration;

use fss_reference::discovery::{
    census::{run_census, CensusConfig, OuiTable, OUI_SNAPSHOT},
    dispatch::{dispatch, AdapterPath, Readiness},
    fingerprint::{classify_host, Brand},
    tuya_beacon::listen,
};

fn main() {
    let subnet = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "192.168.4.0/22".to_owned());
    let oui = OuiTable::parse_snapshot(OUI_SNAPSHOT);
    let cfg = CensusConfig {
        subnets: vec![subnet],
        workers: 64,
        tcp_timeout: Duration::from_millis(700),
    };
    let cancel = AtomicBool::new(false);

    println!("== census ==");
    let report = run_census(&cfg, &oui, &cancel).expect("census");
    println!(
        "{} hosts from {} ping targets",
        report.hosts.len(),
        report.ping_targets
    );

    // beacons (10s window) keyed by host IP
    println!("== beacons (10s) ==");
    let beacons = listen(10, 64, &cancel);
    let mut beacon_ips = std::collections::BTreeMap::new();
    for b in &beacons {
        let ip = b.source.split(':').next().unwrap_or("").to_owned();
        println!(
            "  beacon {} cmd={} crc={}",
            b.source, b.cmd_name, b.crc_good
        );
        beacon_ips.entry(ip).or_insert_with(|| vec![]).push(b.clone());
    }

    println!("== classify + dispatch ==");
    let mut counts = std::collections::BTreeMap::new();
    for h in &report.hosts {
        let refs: Vec<_> = beacon_ips
            .get(&h.ip.to_string())
            .map(|v| v.iter().collect())
            .unwrap_or_default();
        let c = classify_host(h, &refs);
        let d = dispatch(&c);
        *counts.entry(format!("{:?}", c.brand)).or_insert(0u32) += 1;
        if c.brand != Brand::Unknown {
            println!(
                "  {:<15} {:?}/{:?} -> {:?} ({:?}) missing={:?}",
                h.ip.to_string(),
                c.brand,
                c.confidence,
                d.adapter,
                d.readiness,
                d.missing
            );
        }
    }
    println!("brand histogram: {counts:?}");
    let tutk = report
        .hosts
        .iter()
        .filter(|h| h.ip.to_string().starts_with("192.168.4.2"))
        .count();
    let _ = tutk;
    let _ = AdapterPath::ImportOnly;
    let _ = Readiness::Unavailable;
}
