#![forbid(unsafe_code)]

//! Scope and current-response contracts for the owner-network census.
//! Network results are replayed as fixtures; no live probe is required.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use fss_reference::discovery::census::{
    ArpRow, CensusConfig, CensusError, MAX_SUBNET_HOSTS, MAX_SUBNETS, OUI_SNAPSHOT, OuiTable,
    run_census,
};
use fss_reference::discovery::service::{DiscoverConfig, discover};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config(subnets: &[&str]) -> CensusConfig {
    CensusConfig {
        subnets: subnets.iter().map(|s| (*s).to_owned()).collect(),
        workers: 2,
        tcp_timeout: Duration::from_millis(100),
    }
}

fn ip(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 168, 4, last)
}

fn neighbor(address: Ipv4Addr, mac: &str, iface: &str) -> ArpRow {
    ArpRow {
        ip: address,
        mac: mac.to_owned(),
        iface: iface.to_owned(),
    }
}

#[test]
fn arp_cache_cannot_expand_the_authorized_probe_scope() -> TestResult {
    let plan = config(&["192.168.4.0/30"]).plan()?;
    let rows = vec![
        neighbor(ip(2), "80:48:2c:00:00:02", "en0"),
        neighbor(Ipv4Addr::new(10, 0, 0, 2), "80:48:2c:00:00:03", "vpn0"),
        neighbor(ip(0), "80:48:2c:00:00:04", "en0"),
        neighbor(ip(3), "80:48:2c:00:00:05", "en0"),
        neighbor(ip(1), "80:48:2c:00:00:01", "en0"),
    ];
    let scoped = plan.scoped_neighbors(rows);
    assert_eq!(
        scoped.iter().map(|row| row.ip).collect::<Vec<_>>(),
        vec![ip(1), ip(2)]
    );
    assert!(plan.contains(ip(1)));
    assert!(!plan.contains(ip(0)));
    assert!(!plan.contains(ip(3)));
    assert!(!plan.contains(Ipv4Addr::new(10, 0, 0, 2)));
    Ok(())
}

#[test]
fn cidr_cardinality_is_refused_before_expanding_a_large_network() -> TestResult {
    for subnet in [
        "10.0.0.0/8",
        "10.0.0.0/15",
        "10.0.0.0/0",
        "10.0.0.0/33",
        "invalid",
    ] {
        assert_eq!(
            config(&[subnet]).plan(),
            Err(CensusError::SubnetTooLarge(subnet.to_owned())),
        );
    }
    let largest = config(&["10.0.0.0/16"]).plan()?;
    assert_eq!(largest.ping_targets.len(), MAX_SUBNET_HOSTS as usize - 2);
    Ok(())
}

#[test]
fn empty_and_excessive_scope_declarations_are_refused() -> TestResult {
    assert_eq!(config(&[]).plan(), Err(CensusError::SubnetCount(0)));
    let mut cfg = config(&["192.168.4.1/32"]);
    cfg.subnets = vec!["192.168.4.1/32".to_owned(); MAX_SUBNETS];
    assert_eq!(cfg.plan()?.ping_targets, vec![ip(1)]);
    cfg.subnets.push("192.168.4.1/32".to_owned());
    assert_eq!(cfg.plan(), Err(CensusError::SubnetCount(MAX_SUBNETS + 1)));
    Ok(())
}

#[test]
fn point_to_point_and_single_host_scopes_remain_discoverable() -> TestResult {
    assert_eq!(
        config(&["192.168.4.3/31"]).plan()?.ping_targets,
        vec![ip(2), ip(3)],
    );
    assert_eq!(
        config(&["192.168.4.255/32"]).plan()?.ping_targets,
        vec![ip(255)],
    );
    Ok(())
}

#[test]
fn combined_target_bound_counts_the_exact_union() -> TestResult {
    let at_limit = config(&["10.0.0.0/16", "10.1.0.0/31", "10.0.1.0/24"]).plan()?;
    assert_eq!(at_limit.ping_targets.len(), MAX_SUBNET_HOSTS as usize);
    assert!(
        at_limit
            .ping_targets
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert_eq!(
        config(&["10.0.0.0/16", "10.1.0.0/31", "10.1.0.2/32"]).plan(),
        Err(CensusError::SubnetTooLarge("*".to_owned())),
    );
    Ok(())
}

#[test]
fn cached_inventory_and_fresh_network_responses_have_distinct_meaning() -> TestResult {
    let plan = config(&["192.168.4.0/24"]).plan()?;
    let oui = OuiTable::parse_snapshot(OUI_SNAPSHOT);
    let outside = Ipv4Addr::new(10, 0, 0, 1);
    let report = plan.assemble_report(
        vec![
            neighbor(ip(1), "80:48:2c:00:00:01", "en0"),
            neighbor(ip(2), "80:48:2c:00:00:02", "en0"),
            neighbor(outside, "80:48:2c:00:00:03", "vpn0"),
        ],
        &[ip(3), outside, ip(3)],
        &BTreeMap::from([
            (ip(2), vec![554, 443, 554, 25]),
            (ip(4), vec![]),
            (ip(5), vec![25]),
            (outside, vec![554]),
        ]),
        &oui,
    );
    assert_eq!(
        report.hosts.iter().map(|host| host.ip).collect::<Vec<_>>(),
        vec![ip(1), ip(2), ip(3)]
    );
    assert_eq!(report.responders, vec![ip(2), ip(3)]);
    assert_eq!(report.hosts[0].oui_vendor.as_deref(), Some("Wyze Labs Inc"));
    assert!(
        report.hosts[0].open_ports.is_empty(),
        "cached identity has no fresh response"
    );
    assert_eq!(report.hosts[1].open_ports, vec![443, 554]);
    assert!(
        report.hosts[2].mac.is_empty(),
        "routed responder has no invented neighbor identity"
    );
    assert_eq!(report.hosts[2].oui_vendor, None);
    assert!(report.hosts.iter().all(|host| host.rtt_ms.is_none()));
    Ok(())
}

#[test]
fn a_tcp_responder_without_an_arp_entry_is_retained() -> TestResult {
    let plan = config(&["192.168.4.7/32"]).plan()?;
    let report = plan.assemble_report(
        Vec::new(),
        &[],
        &BTreeMap::from([(ip(7), vec![554])]),
        &OuiTable::default(),
    );
    assert_eq!(report.responders, vec![ip(7)]);
    assert_eq!(report.hosts.len(), 1);
    assert_eq!(report.hosts[0].ip, ip(7));
    assert_eq!(report.hosts[0].open_ports, vec![554]);
    assert!(report.hosts[0].mac.is_empty());
    assert_eq!(report.hosts[0].oui_vendor, None);
    Ok(())
}

#[test]
fn conflicting_cached_identities_remain_unknown_independent_of_input_order() -> TestResult {
    let plan = config(&["192.168.4.0/24"]).plan()?;
    let oui = OuiTable::parse_snapshot(OUI_SNAPSHOT);
    let mut rows = vec![
        neighbor(ip(1), "80:48:2c:00:00:01", "en0"),
        neighbor(ip(1), "60:d5:61:00:00:01", "en0"),
        neighbor(ip(2), "80:48:2c:00:00:02", "en0"),
        neighbor(ip(2), "80:48:2c:00:00:02", "en0"),
    ];
    let a = plan.assemble_report(rows.clone(), &[ip(2), ip(1), ip(1)], &BTreeMap::new(), &oui);
    rows.reverse();
    let b = plan.assemble_report(rows, &[ip(1), ip(2)], &BTreeMap::new(), &oui);
    assert_eq!(a, b);
    assert!(a.hosts[0].mac.is_empty());
    assert_eq!(a.hosts[0].oui_vendor, None);
    assert_eq!(a.hosts[1].oui_vendor.as_deref(), Some("Wyze Labs Inc"));
    assert_eq!(a.responders, vec![ip(1), ip(2)]);
    Ok(())
}

#[test]
fn precancelled_census_has_no_network_or_neighbor_observations() -> TestResult {
    let report = run_census(
        &config(&["192.168.4.7/32"]),
        &OuiTable::default(),
        &AtomicBool::new(true),
    )?;
    assert_eq!(report.ping_targets, 1);
    assert!(report.hosts.is_empty());
    assert!(report.responders.is_empty());
    Ok(())
}

#[test]
fn discovery_validates_scope_before_starting_any_probe() {
    let mut cfg = DiscoverConfig::for_subnets(Vec::new(), Ipv4Addr::LOCALHOST);
    cfg.beacon_seconds = u64::MAX;
    cfg.standards_seconds = u64::MAX;
    assert_eq!(
        discover(&cfg, &AtomicBool::new(false)),
        Err(fss_reference::discovery::DiscoveryError::Census(
            CensusError::SubnetCount(0)
        )),
    );
}
