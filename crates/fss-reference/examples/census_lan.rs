//! Live census runner (DISC-1 qualification): sweeps the owner LAN and
//! prints HostObs rows for comparison against the 2026-10-07 golden census.
//!
//! Run: cargo run -p fss-reference --example census_lan -- 192.168.4.0/22

use std::sync::atomic::AtomicBool;
use std::time::Duration;

use fss_reference::discovery::{run_census, CensusConfig, OuiTable, OUI_SNAPSHOT};

fn main() {
    let subnets: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| a.contains('/'))
        .collect();
    let subnets = if subnets.is_empty() {
        vec!["192.168.4.0/22".to_owned()]
    } else {
        subnets
    };
    let oui = OuiTable::parse_snapshot(OUI_SNAPSHOT);
    println!("census: {} OUI prefixes vendored", oui.len());
    let cfg = CensusConfig {
        subnets,
        workers: 64,
        tcp_timeout: Duration::from_millis(700),
    };
    let cancel = AtomicBool::new(false);
    let t0 = std::time::Instant::now();
    let report = run_census(&cfg, &oui, &cancel).expect("census");
    println!(
        "census: {} ping targets, {} hosts observed ({:.1}s)",
        report.ping_targets,
        report.hosts.len(),
        t0.elapsed().as_secs_f32()
    );
    for h in &report.hosts {
        println!(
            "  {:<15} {:<17} {:<40} open={:?}",
            h.ip.to_string(),
            h.mac,
            h.oui_vendor.as_deref().unwrap_or("-"),
            h.open_ports
        );
    }
}
