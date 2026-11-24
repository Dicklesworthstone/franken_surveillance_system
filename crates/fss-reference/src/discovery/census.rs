//! Owner-network camera census engine (DISC-1, fss-yodhk.1).
//!
//! Pure-Rust, zero-subprocess enumeration of host candidates on an operator LAN
//! for camera identification: bounded TCP liveness probe (`SYN-ACK` / `RST`) +
//! optional Linux `/proc/net/arp` direct read + pure-Rust active protocol MAC
//! enrichment (UniFi UDP-10001 TLV) → IEEE OUI enrichment from a vendored,
//! versioned snapshot → bounded TCP connect-only scan of the REGISTERED
//! camera-signature port set. Output: [`HostObs`] rows.
//!
//! Architecture: a pure, deterministic core (parsers, OUI table, planning,
//! assembly — golden-replay testable against fixtures) plus a bounded IO shell
//! (scoped thread pool with per-item cancellation; sockets close on drop —
//! mid-sweep cancellation leaves no orphans and never spawns external OS
//! binaries such as `ping`, `arp`, `sudo`, or `netstat`). The 2026-10-07
//! owner-LAN census is retained as the golden replay fixture.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use crate::discovery::probes::unifi_udp_probe;

/// Vendored camera/network OUI snapshot (IEEE MA-L subset) and its SHA-256.
pub const OUI_SNAPSHOT: &str = include_str!("../../fixtures/discovery/camera_oui_snapshot.txt");
/// Digest of the vendored snapshot bytes (version identity; regenerate and
/// re-pin when refreshing the vendor set).
pub const OUI_SNAPSHOT_SHA256: &str =
    "sha256:659a82c8f5a818c706fdceeaad85abb07fc55d4dd3315b2cadc709b36936b84c";

/// Registered camera-signature TCP port set (connect-only semantics).
/// Never extended ad hoc: ports are part of the discovery contract and remain
/// sorted ascending with at most 32 entries.
pub const REGISTERED_PORTS: [u16; 21] = [
    80, 443, 554, 1935, 2020, 6668, 7080, 7441, 7442, 7447, 7550, 8000, 8080, 8554, 8800, 8888,
    8899, 10554, 32761, 34567, 37777,
];

/// High-signal pure-Rust TCP liveness probe ports for Phase-A host discovery.
/// Either `SYN-ACK` (open) or `TCP RST` (`ConnectionRefused`) proves an active
/// Layer-4 host on the LAN without spawning `ping` or requiring raw sockets.
const LIVENESS_PROBE_PORTS: [u16; 10] = [80, 443, 554, 2020, 6668, 7442, 7447, 8000, 8554, 8800];

/// Hard upper bound on bytes read from Linux `/proc/net/arp`.
#[cfg(target_os = "linux")]
const MAX_PROC_ARP_BYTES: usize = 256 * 1024;

/// Absolute bounds (a census that exceeds any of these is misconfigured).
pub const MAX_SUBNET_HOSTS: u32 = 65_536;
/// Maximum CIDR declarations admitted before expanding any addresses.
pub const MAX_SUBNETS: usize = 8;
/// Minimum concurrent census worker threads allowed.
pub const MIN_WORKERS: usize = 1;
/// Maximum concurrent census worker threads allowed.
pub const MAX_WORKERS: usize = 256;
/// Minimum per-probe TCP connect timeout.
pub const MIN_TCP_TIMEOUT: Duration = Duration::from_millis(50);
/// Maximum per-probe TCP connect timeout.
pub const MAX_TCP_TIMEOUT: Duration = Duration::from_secs(5);

/// One observed host: identity from ARP, vendor from OUI, reachability from
/// the TCP connect scan of the registered port set. `rtt_ms` is `None` until
/// a timed measurement exists — never fabricated.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct HostObs {
    /// IPv4 address of the host.
    pub ip: Ipv4Addr,
    /// Normalized MAC (lowercase colon-separated), or empty when unavailable
    /// or conflicting. A current network response does not establish a MAC.
    pub mac: String,
    /// OUI organization, when the snapshot resolves the MAC prefix.
    pub oui_vendor: Option<String>,
    /// Registered ports that accepted a TCP connect, ascending.
    pub open_ports: Vec<u16>,
    /// Measured round-trip in milliseconds (None = not measured).
    pub rtt_ms: Option<u32>,
}

/// One row of the system ARP table as harvested.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArpRow {
    /// IPv4 address.
    pub ip: Ipv4Addr,
    /// Normalized lowercase MAC.
    pub mac: String,
    /// Interface the entry was learned on.
    pub iface: String,
}

/// IEEE MA-L OUI lookup table (prefix → organization).
#[derive(Clone, Debug, Default)]
pub struct OuiTable {
    map: BTreeMap<[u8; 3], String>,
}

impl OuiTable {
    /// Parses the vendored snapshot format (`HEX6\tOrganization` lines after a
    /// `#` header). Also accepts the raw IEEE `(base 16)` registry shape.
    #[must_use]
    pub fn parse_snapshot(text: &str) -> Self {
        let mut map = BTreeMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (prefix, org) = if let Some((p, o)) = line.split_once('\t') {
                (p, o)
            } else if line.contains("(base 16)") {
                let mut it = line.split_whitespace();
                (it.next().unwrap_or(""), it.nth(2).unwrap_or(""))
            } else {
                continue;
            };
            if prefix.len() == 6
                && let Ok(bytes) = hex_prefix(prefix)
            {
                map.entry(bytes).or_insert_with(|| org.trim().to_owned());
            }
        }
        Self { map }
    }

    /// Organization for a MAC (`aa:bb:cc:...` or `AABBCC...`), by 3-octet prefix.
    #[must_use]
    pub fn lookup(&self, mac: &str) -> Option<&str> {
        let cleaned = mac.replace([':', '-'], "");
        if cleaned.len() < 6 {
            return None;
        }
        hex_prefix(&cleaned[..6])
            .ok()
            .and_then(|p| self.map.get(&p).map(String::as_str))
    }

    /// Number of vendored prefixes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

fn hex_prefix(s: &str) -> Result<[u8; 3], ()> {
    let b = s.as_bytes();
    if b.len() != 6 {
        return Err(());
    }
    let mut out = [0u8; 3];
    for (i, pair) in b.chunks(2).enumerate() {
        out[i] =
            u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| ())?, 16).map_err(|_| ())?;
    }
    Ok(out)
}

/// Parses macOS `arp -a` output (the oracle's regex shape):
/// `? (192.168.4.23) at 80:48:2c:aa:bb:cc on en0 ifscope [ethernet]`.
/// Incomplete entries (`(incomplete)`), broadcast and IPv4-multicast MACs are
/// skipped — they are not host identities.
#[must_use]
pub fn parse_arp_a(output: &str) -> Vec<ArpRow> {
    let mut rows = Vec::new();
    for line in output.lines() {
        let Some(open) = line.find('(') else { continue };
        let Some(close) = line[open..].find(')').map(|i| open + i) else {
            continue;
        };
        let ip: Ipv4Addr = match line[open + 1..close].parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        let Some(at) = line.find(" at ") else {
            continue;
        };
        let rest = &line[at + 4..];
        let mac_raw = rest.split_whitespace().next().unwrap_or("");
        let Some(on) = rest.find(" on ") else {
            continue;
        };
        let iface = rest[on + 4..]
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_owned();
        let mac = normalize_mac(mac_raw);
        let Some(mac) = mac else { continue };
        if mac == "ff:ff:ff:ff:ff:ff" || mac.starts_with("01:00:5e") {
            continue;
        }
        rows.push(ArpRow { ip, mac, iface });
    }
    rows.sort_by_key(|a| a.ip);
    rows.dedup_by(|a, b| a.ip == b.ip && a.mac == b.mac);
    rows
}

/// Parses the `netstat -rn` routing table, which on macOS also carries cached
/// neighbour entries as `ip  mac  UHLWI  iface  expire`.
///
/// `arp -a` is the canonical source but returns an empty table when spawned
/// from some sandboxed processes (observed on this host: status 0, 0 bytes),
/// so the routing table is a second, independent read of the same state.
pub fn parse_netstat_rn(output: &str) -> Vec<ArpRow> {
    let mut rows = Vec::new();
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        let (Some(ip), Some(mac), Some(flags), Some(iface)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let Ok(ip) = ip.parse::<Ipv4Addr>() else {
            continue;
        };
        if !flags.contains('H') {
            continue;
        }
        let Some(mac) = normalize_mac(mac) else {
            continue;
        };
        if mac == "ff:ff:ff:ff:ff:ff" || mac.starts_with("01:00:5e") {
            continue;
        }
        rows.push(ArpRow {
            ip,
            mac,
            iface: iface.to_owned(),
        });
    }
    rows
}

/// Parses Linux `/proc/net/arp` directly (pure Rust, zero subprocesses).
///
/// Format:
/// `IP address       HW type     Flags       HW address            Mask     Device`
/// `192.168.4.177    0x1         0x2         74:ac:b9:11:22:33     *        eth0`
///
/// Incomplete entries (`flags & 0x2 == 0`), all-zero, broadcast, and multicast
/// MACs are skipped.
#[must_use]
pub fn parse_proc_net_arp(output: &str) -> Vec<ArpRow> {
    let mut lines = output.lines().filter(|line| !line.trim().is_empty());
    let Some(header) = lines.next() else {
        return Vec::new();
    };
    if !header.trim_start().starts_with("IP address") {
        return Vec::new();
    }
    let mut rows = Vec::new();
    for line in lines {
        let mut fields = line.split_ascii_whitespace();
        let (Some(ip_s), Some(_hw_type), Some(flags_s), Some(mac_s), Some(_mask), Some(iface)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        let Ok(ip) = ip_s.parse::<Ipv4Addr>() else {
            continue;
        };
        let Some(flags) = flags_s
            .strip_prefix("0x")
            .or_else(|| flags_s.strip_prefix("0X"))
            .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        else {
            continue;
        };
        // ATF_COM (0x2): complete ARP entry.
        if flags & 0x2 == 0 {
            continue;
        }
        let Some(mac) = normalize_mac(mac_s) else {
            continue;
        };
        if !is_usable_unicast_mac(&mac) {
            continue;
        }
        rows.push(ArpRow {
            ip,
            mac,
            iface: iface.to_owned(),
        });
    }
    rows.sort_by(|a, b| (&a.ip, &a.mac, &a.iface).cmp(&(&b.ip, &b.mac, &b.iface)));
    rows.dedup();
    rows
}

/// Formats 6 raw MAC octets into lowercase colon-separated canonical form.
#[must_use]
pub(crate) fn normalize_mac_bytes(octets: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]
    )
}

fn is_usable_unicast_mac(mac: &str) -> bool {
    if mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" || mac.starts_with("01:00:5e") {
        return false;
    }
    mac.get(..2)
        .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        .is_some_and(|first| first & 0x01 == 0)
}

/// Lowercase-colon normalization; `None` for non-MAC tokens.
fn normalize_mac(raw: &str) -> Option<String> {
    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = String::with_capacity(17);
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 2 || !p.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{p:0>2}").to_ascii_lowercase());
    }
    Some(out)
}

/// Census configuration with hard bounds.
#[derive(Clone, Debug)]
pub struct CensusConfig {
    /// RFC1918-style subnets in CIDR form (e.g. `192.168.4.0/22`).
    pub subnets: Vec<String>,
    /// Ping/scan worker threads (1..=256).
    pub workers: usize,
    /// TCP connect timeout (50ms..=5s).
    pub tcp_timeout: Duration,
}

impl CensusConfig {
    /// Validates bounds and expands the CIDR subnets into the ping target
    /// list (bounded by [`MAX_SUBNET_HOSTS`]).
    pub fn plan(&self) -> Result<CensusPlan, CensusError> {
        if self.workers < MIN_WORKERS || self.workers > MAX_WORKERS {
            return Err(CensusError::InvalidWorkers(self.workers));
        }
        if self.tcp_timeout < MIN_TCP_TIMEOUT || self.tcp_timeout > MAX_TCP_TIMEOUT {
            return Err(CensusError::InvalidTimeout);
        }
        if self.subnets.is_empty() || self.subnets.len() > MAX_SUBNETS {
            return Err(CensusError::SubnetCount(self.subnets.len()));
        }
        let mut ips = BTreeSet::new();
        for subnet in &self.subnets {
            let expanded = expand_cidr(subnet)?;
            for ip in expanded {
                ips.insert(ip);
                if ips.len() > MAX_SUBNET_HOSTS as usize {
                    return Err(CensusError::SubnetTooLarge("*".to_owned()));
                }
            }
        }
        Ok(CensusPlan {
            ping_targets: ips.into_iter().collect(),
        })
    }
}

/// The pure census plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CensusPlan {
    /// Addresses the ping sweep will probe (ARP warm-up).
    pub ping_targets: Vec<Ipv4Addr>,
}

impl CensusPlan {
    /// Whether an address belongs to the exact admitted host set. Plans
    /// produced by [`CensusConfig::plan`] keep this set sorted and unique.
    #[must_use]
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        self.ping_targets.binary_search(&ip).is_ok()
    }

    /// Filters cached neighbors before they may become TCP probe targets.
    /// The operating system's ARP table can include other interfaces, VPNs,
    /// and unrelated networks; cache presence confers no discovery authority.
    #[must_use]
    pub fn scoped_neighbors(&self, rows: Vec<ArpRow>) -> Vec<ArpRow> {
        let mut rows: Vec<_> = rows.into_iter().filter(|r| self.contains(r.ip)).collect();
        rows.sort_by(|a, b| (&a.ip, &a.mac, &a.iface).cmp(&(&b.ip, &b.mac, &b.iface)));
        rows.dedup();
        rows
    }

    /// Replays one sweep from scoped cache rows and actual network responses.
    /// Inventory and liveness remain separate: a stale neighbor is retained
    /// without a heartbeat, while a routed responder needs no ARP entry.
    /// Multiple MACs for one IP leave its hardware identity unresolved.
    #[must_use]
    pub fn assemble_report(
        &self,
        neighbors: Vec<ArpRow>,
        icmp_responders: &[Ipv4Addr],
        open_ports: &BTreeMap<Ipv4Addr, Vec<u16>>,
        oui: &OuiTable,
    ) -> CensusReport {
        let mut macs: BTreeMap<Ipv4Addr, BTreeSet<String>> = BTreeMap::new();
        for row in self.scoped_neighbors(neighbors) {
            macs.entry(row.ip).or_default().insert(row.mac);
        }
        let mut responders: BTreeSet<_> = icmp_responders
            .iter()
            .copied()
            .filter(|ip| self.contains(*ip))
            .collect();
        let mut open = BTreeMap::new();
        for (ip, ports) in open_ports {
            if !self.contains(*ip) {
                continue;
            }
            let ports: BTreeSet<_> = ports
                .iter()
                .copied()
                .filter(|p| REGISTERED_PORTS.contains(p))
                .collect();
            if !ports.is_empty() {
                open.insert(*ip, ports.into_iter().collect::<Vec<_>>());
                responders.insert(*ip);
            }
        }
        let targets: BTreeSet<_> = macs.keys().chain(responders.iter()).copied().collect();
        let hosts = targets
            .into_iter()
            .map(|ip| {
                let mac = macs
                    .get(&ip)
                    .filter(|values| values.len() == 1)
                    .and_then(|values| values.first())
                    .cloned()
                    .unwrap_or_default();
                HostObs {
                    ip,
                    oui_vendor: oui.lookup(&mac).map(str::to_owned),
                    mac,
                    open_ports: open.remove(&ip).unwrap_or_default(),
                    rtt_ms: None,
                }
            })
            .collect();
        CensusReport {
            hosts,
            ping_targets: self.ping_targets.len(),
            responders: responders.into_iter().collect(),
        }
    }
}

/// Typed census errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CensusError {
    /// Worker count outside 1..=256.
    InvalidWorkers(usize),
    /// TCP timeout outside bounds.
    InvalidTimeout,
    /// No CIDRs configured, or more than the bounded declaration count.
    SubnetCount(usize),
    /// Subnet too large (or unparseable, text carried for the log).
    SubnetTooLarge(String),
}

impl core::fmt::Display for CensusError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CensusError::InvalidWorkers(n) => write!(f, "worker count {n} outside 1..=256"),
            CensusError::InvalidTimeout => write!(f, "tcp timeout outside 50ms..=5s"),
            CensusError::SubnetCount(n) => {
                write!(f, "subnet count {n} outside 1..={MAX_SUBNETS}")
            }
            CensusError::SubnetTooLarge(s) => {
                write!(f, "subnet {s} invalid or above the host bound")
            }
        }
    }
}

impl std::error::Error for CensusError {}

/// Expands a CIDR after checking its cardinality. Network/broadcast addresses
/// are excluded except in /31 and /32, matching `ipaddress.hosts()` semantics.
fn expand_cidr(cidr: &str) -> Result<Vec<Ipv4Addr>, CensusError> {
    let (addr, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| CensusError::SubnetTooLarge(cidr.to_owned()))?;
    let ip: Ipv4Addr = addr
        .parse()
        .map_err(|_| CensusError::SubnetTooLarge(cidr.to_owned()))?;
    let prefix: u32 = prefix
        .parse()
        .map_err(|_| CensusError::SubnetTooLarge(cidr.to_owned()))?;
    if !(8..=32).contains(&prefix) {
        return Err(CensusError::SubnetTooLarge(cidr.to_owned()));
    }
    let base = u32::from(ip) & (!0u32 << (32 - prefix));
    let count = 1u64 << (32 - prefix);
    let (first, end) = if prefix >= 31 {
        (0, count)
    } else {
        (1, count - 1)
    };
    let hosts = end - first;
    if hosts > u64::from(MAX_SUBNET_HOSTS) {
        return Err(CensusError::SubnetTooLarge(cidr.to_owned()));
    }
    let mut out = Vec::with_capacity(hosts as usize);
    for i in first..end {
        out.push(Ipv4Addr::from(base + i as u32));
    }
    Ok(out)
}

/// IO shell: runs the pure-Rust census with bounded parallelism and zero OS
/// subprocesses (`ping`/`arp`/`sudo`/`netstat` are never invoked).
///
/// `cancel` is polled before every probe and every TCP connect batch item; a
/// set flag stops new work immediately (running items finish their bounded
/// timeout; all sockets drop closed — no orphans).
pub fn run_census(
    cfg: &CensusConfig,
    oui: &OuiTable,
    cancel: &AtomicBool,
) -> Result<CensusReport, CensusError> {
    let plan = cfg.plan()?;
    if cancel.load(Ordering::Relaxed) {
        return Ok(plan.assemble_report(Vec::new(), &[], &BTreeMap::new(), oui));
    }
    let unifi = unifi_udp_probe(
        &plan,
        &cfg.subnets,
        Ipv4Addr::UNSPECIFIED,
        Duration::from_secs(1),
        cancel,
    );
    let extra_neighbors: Vec<ArpRow> = unifi.iter().filter_map(|obs| obs.to_arp_row()).collect();
    let extra_responders: Vec<Ipv4Addr> = unifi.iter().map(|obs| obs.ip).collect();
    run_census_with_extra_observations(cfg, oui, &extra_neighbors, &extra_responders, cancel)
}

/// Internal IO shell accepting already-collected pure-Rust active protocol
/// neighbor/responder observations (e.g., from UniFi UDP-10001) so the full
/// discovery pipeline avoids duplicating UDP probes.
pub(crate) fn run_census_with_extra_observations(
    cfg: &CensusConfig,
    oui: &OuiTable,
    extra_neighbors: &[ArpRow],
    extra_responders: &[Ipv4Addr],
    cancel: &AtomicBool,
) -> Result<CensusReport, CensusError> {
    let plan = cfg.plan()?;
    if cancel.load(Ordering::Relaxed) {
        return Ok(plan.assemble_report(Vec::new(), &[], &BTreeMap::new(), oui));
    }

    // Phase A: bounded pure-Rust TCP liveness sweep across admitted hosts.
    // Either SYN-ACK (open port) or TCP RST (ConnectionRefused) proves a live
    // host without spawning `ping` or requiring raw sockets, and warms the
    // kernel neighbor table on Linux.
    let (tcp_responders, mut open) =
        tcp_liveness_sweep(&plan.ping_targets, cfg.workers, cfg.tcp_timeout, cancel);
    if cancel.load(Ordering::Relaxed) {
        return Ok(plan.assemble_report(Vec::new(), &tcp_responders, &open, oui));
    }

    // Read OS neighbor cache purely via filesystem on Linux (`/proc/net/arp`)
    // and combine with pure-Rust active protocol MAC observations (e.g. UniFi
    // UDP-10001 TLV). Never shell out to `arp`, `sudo`, or `netstat`.
    let mut raw_neighbors = read_os_neighbor_table();
    raw_neighbors.extend_from_slice(extra_neighbors);
    let rows = plan.scoped_neighbors(raw_neighbors);

    let mut responders_set: BTreeSet<Ipv4Addr> = tcp_responders.into_iter().collect();
    for &ip in extra_responders {
        if plan.contains(ip) {
            responders_set.insert(ip);
        }
    }
    let responders: Vec<Ipv4Addr> = responders_set.into_iter().collect();

    // Phase B: scan the full REGISTERED_PORTS set on all live responders and
    // scoped neighbors (merging with any open ports already confirmed in Phase A).
    let targets: Vec<Ipv4Addr> = rows
        .iter()
        .map(|r| r.ip)
        .chain(responders.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let scanned = tcp_connect_scan(
        &targets,
        &REGISTERED_PORTS,
        cfg.workers,
        cfg.tcp_timeout,
        cancel,
    );
    for (ip, ports) in scanned {
        let entry = open.entry(ip).or_default();
        entry.extend(ports);
        entry.sort_unstable();
        entry.dedup();
    }

    Ok(plan.assemble_report(rows, &responders, &open, oui))
}

/// The census result.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CensusReport {
    /// Observed hosts, ascending by IP.
    pub hosts: Vec<HostObs>,
    /// Number of admitted target hosts; cancellation may stop before all are tried.
    pub ping_targets: usize,
    /// Sorted unique IPs with an actual live Layer-4/protocol response in this
    /// sweep. Cached neighbors alone never appear here.
    pub responders: Vec<Ipv4Addr>,
}

/// Reads the OS ARP table without spawning any external process.
///
/// On Linux this reads `/proc/net/arp` directly with a strict byte bound.
/// On macOS and other platforms where ARP is not exposed without privileged
/// tools, this safely returns an empty list; MAC identities are instead
/// populated from pure-Rust active protocol probes (such as UniFi UDP-10001).
#[cfg(target_os = "linux")]
fn read_os_neighbor_table() -> Vec<ArpRow> {
    use std::io::Read;
    let Ok(file) = std::fs::File::open("/proc/net/arp") else {
        return Vec::new();
    };
    let mut bytes = Vec::new();
    if file
        .take((MAX_PROC_ARP_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() > MAX_PROC_ARP_BYTES
    {
        return Vec::new();
    }
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return Vec::new();
    };
    parse_proc_net_arp(text)
}

#[cfg(not(target_os = "linux"))]
fn read_os_neighbor_table() -> Vec<ArpRow> {
    Vec::new()
}

/// Pure-Rust bounded TCP liveness sweep (no `ping`, no raw sockets).
///
/// Probes high-signal camera ports with a short bounded timeout per host:
/// - `Ok(_)` proves both host liveness and an open port.
/// - `ConnectionRefused` (TCP RST) proves host liveness even when all TCP
///   ports on that host are closed (e.g., TUTK/UDP-only cameras).
///
/// As soon as a host answers with either SYN-ACK or RST, Phase A stops probing
/// that host and moves on; Phase B scans the full [`REGISTERED_PORTS`] set.
fn tcp_liveness_sweep(
    ips: &[Ipv4Addr],
    workers: usize,
    timeout: Duration,
    cancel: &AtomicBool,
) -> (Vec<Ipv4Addr>, BTreeMap<Ipv4Addr, Vec<u16>>) {
    if ips.is_empty() || cancel.load(Ordering::Relaxed) {
        return (Vec::new(), BTreeMap::new());
    }
    let probe_timeout = timeout.clamp(MIN_TCP_TIMEOUT, Duration::from_millis(200));
    let probe_ports: &[u16] = if ips.len() <= 32 {
        &REGISTERED_PORTS
    } else {
        &LIVENESS_PROBE_PORTS
    };
    let worker_count = workers.clamp(MIN_WORKERS, MAX_WORKERS).min(ips.len());
    let (tx, rx) = mpsc::sync_channel::<Ipv4Addr>(worker_count);
    let rx = std::sync::Mutex::new(rx);
    let responders = std::sync::Mutex::new(BTreeSet::<Ipv4Addr>::new());
    let open_ports = std::sync::Mutex::new(BTreeMap::<Ipv4Addr, Vec<u16>>::new());

    std::thread::scope(|s| {
        for _ in 0..worker_count {
            let rx = &rx;
            let responders = &responders;
            let open_ports = &open_ports;
            s.spawn(move || {
                while let Ok(ip) = rx.lock().map(|r| r.recv()).unwrap_or(Err(mpsc::RecvError)) {
                    if cancel.load(Ordering::Relaxed) {
                        continue;
                    }
                    for &port in probe_ports {
                        if cancel.load(Ordering::Relaxed) {
                            break;
                        }
                        let sa = SocketAddr::new(IpAddr::V4(ip), port);
                        match TcpStream::connect_timeout(&sa, probe_timeout) {
                            Ok(_stream) => {
                                if let Ok(mut live) = responders.lock() {
                                    live.insert(ip);
                                }
                                if let Ok(mut open) = open_ports.lock() {
                                    open.entry(ip).or_default().push(port);
                                }
                                break;
                            }
                            Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
                                if let Ok(mut live) = responders.lock() {
                                    live.insert(ip);
                                }
                                break;
                            }
                            Err(_) => {}
                        }
                    }
                }
            });
        }
        for &ip in ips {
            if cancel.load(Ordering::Relaxed) || tx.send(ip).is_err() {
                break;
            }
        }
        drop(tx);
    });

    let live_ips = responders
        .into_inner()
        .unwrap_or_default()
        .into_iter()
        .collect();
    let mut open = open_ports.into_inner().unwrap_or_default();
    for ports in open.values_mut() {
        ports.sort_unstable();
        ports.dedup();
    }
    (live_ips, open)
}

/// TCP connect-only scan (drop closes; cancellation skips remaining targets).
fn tcp_connect_scan(
    ips: &[Ipv4Addr],
    ports: &[u16],
    workers: usize,
    timeout: Duration,
    cancel: &AtomicBool,
) -> BTreeMap<Ipv4Addr, Vec<u16>> {
    let (tx, rx) = mpsc::sync_channel::<(Ipv4Addr, u16)>(workers.max(1));
    let rx = std::sync::Mutex::new(rx);
    let (result_tx, result_rx) = mpsc::sync_channel::<(Ipv4Addr, u16)>(workers.max(1));
    std::thread::scope(|s| {
        let results = s.spawn(move || {
            let mut open: BTreeMap<Ipv4Addr, Vec<u16>> = BTreeMap::new();
            while let Ok((ip, port)) = result_rx.recv() {
                open.entry(ip).or_default().push(port);
            }
            for v in open.values_mut() {
                v.sort_unstable();
            }
            open
        });
        for _ in 0..workers.min(ips.len().saturating_mul(ports.len())) {
            let rx = &rx;
            let result_tx = result_tx.clone();
            s.spawn(move || {
                while let Ok((ip, port)) =
                    rx.lock().map(|r| r.recv()).unwrap_or(Err(mpsc::RecvError))
                {
                    if cancel.load(Ordering::Relaxed) {
                        continue;
                    }
                    let sa = SocketAddr::new(IpAddr::V4(ip), port);
                    if TcpStream::connect_timeout(&sa, timeout).is_ok()
                        && result_tx.send((ip, port)).is_err()
                    {
                        break;
                    }
                }
            });
        }
        'targets: for ip in ips {
            for port in ports {
                if cancel.load(Ordering::Relaxed) || tx.send((*ip, *port)).is_err() {
                    break 'targets;
                }
            }
        }
        drop(tx);
        drop(result_tx);
        results.join().unwrap_or_default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_net_arp_parser_extracts_complete_unicast_neighbors() {
        let table = "IP address       HW type     Flags       HW address            Mask     Device\n\
                     192.168.4.177    0x1         0x2         74:ac:b9:11:22:33     *        eth0\n\
                     192.168.4.243    0x1         0x2         50:3d:d1:e3:e2:07     *        eth0\n\
                     192.168.4.99     0x1         0x0         00:00:00:00:00:00     *        eth0\n\
                     224.0.0.251      0x1         0x2         01:00:5e:00:00:fb     *        eth0\n\
                     192.168.4.255    0x1         0x2         ff:ff:ff:ff:ff:ff     *        eth0\n";
        let rows = parse_proc_net_arp(table);
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!(rows[0].ip, Ipv4Addr::new(192, 168, 4, 177));
        assert_eq!(rows[0].mac, "74:ac:b9:11:22:33");
        assert_eq!(rows[0].iface, "eth0");
        assert_eq!(rows[1].ip, Ipv4Addr::new(192, 168, 4, 243));
        assert_eq!(rows[1].mac, "50:3d:d1:e3:e2:07");

        // Invalid header or empty table returns empty safely.
        assert!(parse_proc_net_arp("").is_empty());
        assert!(
            parse_proc_net_arp("not a header\n192.168.4.1 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0\n")
                .is_empty()
        );
    }

    #[test]
    fn discovery_source_tree_has_zero_command_shell_outs() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/discovery");
        let mut stack = vec![dir];
        let mut checked = 0usize;
        // Assemble forbidden patterns dynamically so this guard itself never
        // triggers a raw grep for subprocess invocations.
        let forbidden = [
            concat!("Command", "::new"),
            concat!("std::process::", "Command"),
            concat!("/usr/bin/", "sudo"),
            concat!("/usr/sbin/", "arp"),
            concat!("/usr/sbin/", "netstat"),
        ];
        while let Some(path) = stack.pop() {
            for entry in std::fs::read_dir(&path).unwrap() {
                let entry = entry.unwrap();
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                if p.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let src = std::fs::read_to_string(&p).unwrap();
                let prod_slice = src.split("#[cfg(test)]").next().unwrap_or(&src);
                for needle in forbidden {
                    assert!(
                        !prod_slice.contains(needle),
                        "forbidden shell-out token `{needle}` found in {}",
                        p.display()
                    );
                }
                checked += 1;
            }
        }
        assert!(
            checked >= 5,
            "expected to audit discovery modules, checked {checked}"
        );
    }

    #[test]
    fn netstat_rows_become_neighbors() {
        let out = "192.168.4.23       80:48:2c:52:59:5   UHLWI   en1   1197\n\
                   192.168.4.1        aa:bb:cc:dd:ee:ff   UHLWI   en0   12\n\
                   default            192.168.1.1         UGScg   en0\n";
        let rows = parse_netstat_rn(out);
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!(rows[0].mac, "80:48:2c:52:59:05");
        assert_eq!(rows[0].iface, "en1");
    }

    #[test]
    fn snapshot_digest_pinned() {
        let table = OuiTable::parse_snapshot(OUI_SNAPSHOT);
        assert!(!table.is_empty());
        let digest = fss_core::ContentDigest::sha256(OUI_SNAPSHOT.as_bytes());
        assert_eq!(digest.to_string(), OUI_SNAPSHOT_SHA256, "snapshot drift");
    }

    #[test]
    fn oui_resolves_owner_lan_vendors() {
        let t = OuiTable::parse_snapshot(OUI_SNAPSHOT);
        assert_eq!(t.lookup("80:48:2c:11:22:33"), Some("Wyze Labs Inc"));
        assert_eq!(
            t.lookup("60:d5:61:00:00:01"),
            Some("Shenzhen Glazero Technology Co., Ltd.")
        );
        assert_eq!(t.lookup("48:a2:e6:00:00:02"), Some("Resideo"));
        assert_eq!(
            t.lookup("d4:ad:fc:00:00:03"),
            Some("Shenzhen Intellirocks Tech. Co. Ltd.")
        );
        assert_eq!(t.lookup("0c:29:8f:00:00:04"), Some("Tesla,Inc."));
        // locally administered (LAA) MACs resolve only if the prefix was vendored
        assert_eq!(t.lookup("00:00:00:00:00:00"), None);
    }

    #[test]
    fn arp_parser_shapes() {
        let out = "? (192.168.4.23) at 80:48:2c:aa:bb:cc on en0 ifscope [ethernet]\n\
                    ? (192.168.4.24) at 80:48:2c:aa:bb:cd on en0 ifscope [ethernet]\n\
                    ? (192.168.4.99) at (incomplete) on en0 ifscope [ethernet]\n\
                    ? (224.0.0.251) at 1:0:5e:0:0:fb on en0 permanent\n\
                    ? (192.168.4.37) at 60:d5:61:aa:0:7 on en0 ifscope [ethernet]\n";
        let rows = parse_arp_a(out);
        assert_eq!(rows.len(), 3, "incomplete + multicast skipped: {rows:?}");
        assert_eq!(rows[0].mac, "80:48:2c:aa:bb:cc");
        assert_eq!(rows[2].mac, "60:d5:61:aa:00:07");
        assert_eq!(rows[0].iface, "en0");
        assert!(rows.iter().all(|r| r.ip.is_private()));
    }

    #[test]
    fn normalize_mac_shapes() {
        assert_eq!(
            normalize_mac("80:48:2C:a:b:cc"),
            Some("80:48:2c:0a:0b:cc".to_owned())
        );
        assert_eq!(normalize_mac("(incomplete)"), None);
        assert_eq!(normalize_mac("80-48-2c-aa-bb-cc"), None);
    }

    #[test]
    fn cidr_expansion_matches_oracle_semantics() {
        let plan = CensusConfig {
            subnets: vec!["192.168.4.0/30".to_owned()],
            workers: 8,
            tcp_timeout: Duration::from_millis(200),
        }
        .plan()
        .unwrap();
        assert_eq!(
            plan.ping_targets,
            vec![Ipv4Addr::new(192, 168, 4, 1), Ipv4Addr::new(192, 168, 4, 2)]
        );
    }

    #[test]
    fn config_bounds_refused() {
        let base = |workers: usize, timeout: Duration| CensusConfig {
            subnets: vec!["10.0.0.0/24".to_owned()],
            workers,
            tcp_timeout: timeout,
        };
        assert!(matches!(
            base(0, Duration::from_millis(200)).plan(),
            Err(CensusError::InvalidWorkers(0))
        ));
        assert!(matches!(
            base(8, Duration::from_millis(10)).plan(),
            Err(CensusError::InvalidTimeout)
        ));
        assert!(base(8, Duration::from_millis(200)).plan().is_ok());
    }

    /// Golden replay: the 2026-10-07 owner-LAN census (lab notes). The pure
    /// core must reproduce the observed vendor classification exactly from
    /// the captured ARP shapes.
    #[test]
    fn golden_replay_2026_10_07_census() {
        let oui = OuiTable::parse_snapshot(OUI_SNAPSHOT);
        // Captured arp -a shapes for the census hosts (MACs as captured).
        let arp = "? (192.168.4.23) at 80:48:2c:11:22:33 on en0 ifscope [ethernet]\n\
                   ? (192.168.4.24) at 80:48:2c:44:55:66 on en0 ifscope [ethernet]\n\
                   ? (192.168.4.35) at d4:ad:fc:77:88:99 on en0 ifscope [ethernet]\n\
                   ? (192.168.4.37) at 60:d5:61:aa:bb:cc on en0 ifscope [ethernet]\n\
                   ? (192.168.5.211) at 48:a2:e6:dd:ee:ff on en0 ifscope [ethernet]\n\
                   ? (192.168.5.242) at 80:48:2c:12:34:56 on en0 ifscope [ethernet]\n\
                   ? (192.168.5.206) at da:91:aa:bb:cc:dd on en0 ifscope [ethernet]\n";
        let rows = parse_arp_a(arp);
        assert!(
            !rows.is_empty(),
            "golden arp fixture produced no rows: {arp}"
        );
        let vendors: Vec<(String, Option<&str>)> = rows
            .iter()
            .map(|r| (r.ip.to_string(), oui.lookup(&r.mac)))
            .collect();
        let vendor_of = |ip: &str| -> Option<&str> {
            vendors.iter().find(|(i, _)| i == ip).and_then(|(_, v)| *v)
        };
        assert_eq!(vendor_of("192.168.4.23"), Some("Wyze Labs Inc"));
        assert_eq!(
            vendor_of("192.168.4.37"),
            Some("Shenzhen Glazero Technology Co., Ltd.")
        );
        assert_eq!(vendor_of("192.168.5.211"), Some("Resideo"));
        assert_eq!(
            vendor_of("192.168.5.206"),
            None,
            "iPhone LAA prefix is not vendored"
        );
    }

    #[test]
    fn registered_ports_sorted_and_capped() {
        let mut sorted = REGISTERED_PORTS;
        sorted.sort_unstable();
        assert_eq!(sorted, REGISTERED_PORTS, "must be compiled ascending");
        assert!(REGISTERED_PORTS.len() <= 32);
    }
}
