//! Owner-network camera census engine (DISC-1, fss-yodhk.1).
//!
//! Enumerates host candidates on an operator LAN for camera identification:
//! ICMP/ping sweep (warms the ARP table; the reference oracle shells out to the
//! system `ping`, which needs no raw-socket privilege) → ARP harvest → IEEE OUI
//! enrichment from a vendored, versioned snapshot → bounded TCP connect-only
//! scan of the REGISTERED camera-signature port set (no auth attempts, no
//! banner grabs in this stage). Output: [`HostObs`] rows.
//!
//! Architecture: a pure, deterministic core (parsers, OUI table, planning,
//! assembly — golden-replay testable against fixtures) plus a bounded IO shell
//! (thread pool with per-item cancellation; sockets/processes close on drop —
//! mid-sweep cancellation leaves no orphans). The 2026-10-07 owner-LAN census
//! is retained as the golden replay fixture (lab notes, redacted shape below).
//!
//! Reference oracle: `~/projects/fss-interop-lab/discover.py` (byte-shape
//! parity for the `arp -a` parser).

use std::collections::BTreeMap;
use std::io::BufRead;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

/// Vendored camera/network OUI snapshot (IEEE MA-L subset) and its SHA-256.
pub const OUI_SNAPSHOT: &str = include_str!("../../fixtures/discovery/camera_oui_snapshot.txt");
/// Digest of the vendored snapshot bytes (version identity; regenerate and
/// re-pin when refreshing the vendor set).
pub const OUI_SNAPSHOT_SHA256: &str =
    "sha256:659a82c8f5a818c706fdceeaad85abb07fc55d4dd3315b2cadc709b36936b84c";

/// Registered camera-signature TCP port set (connect-only semantics).
/// Never extended ad hoc: ports are part of the discovery contract.
pub const REGISTERED_PORTS: [u16; 11] = [
    80, 443, 554, 6668, 8554, 8888, 8899, 10554, 32761, 34567, 37777,
];

/// Absolute bounds (a census that exceeds any of these is misconfigured).
pub const MAX_SUBNET_HOSTS: u32 = 65_536;
pub const MIN_WORKERS: usize = 1;
pub const MAX_WORKERS: usize = 256;
pub const MIN_TCP_TIMEOUT: Duration = Duration::from_millis(50);
pub const MAX_TCP_TIMEOUT: Duration = Duration::from_secs(5);

/// One observed host: identity from ARP, vendor from OUI, reachability from
/// the TCP connect scan of the registered port set. `rtt_ms` is `None` until
/// a timed measurement exists — never fabricated.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct HostObs {
    /// IPv4 address of the host.
    pub ip: Ipv4Addr,
    /// Normalized MAC (lowercase colon-separated).
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
        hex_prefix(&cleaned[..6]).ok().and_then(|p| {
            self.map.get(&p).map(String::as_str)
        })
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
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| ())?, 16)
            .map_err(|_| ())?;
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
        let Some(at) = line.find(" at ") else { continue };
        let rest = &line[at + 4..];
        let mac_raw = rest.split_whitespace().next().unwrap_or("");
        let Some(on) = rest.find(" on ") else { continue };
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
    rows.sort_by(|a, b| a.ip.cmp(&b.ip));
    rows.dedup_by(|a, b| a.ip == b.ip && a.mac == b.mac);
    rows
}

/// Lowercase-colon normalization; `None` for non-MAC tokens.
fn normalize_mac(raw: &str) -> Option<String> {
    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = String::with_capacity(17);
    for (i, p) in parts.iter().enumerate() {
        if p.len() == 0 || p.len() > 2 || !p.bytes().all(|b| b.is_ascii_hexdigit()) {
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
        let mut ips = Vec::new();
        for subnet in &self.subnets {
            let expanded = expand_cidr(subnet)?;
            if expanded.len() > MAX_SUBNET_HOSTS as usize {
                return Err(CensusError::SubnetTooLarge(subnet.clone()));
            }
            ips.extend(expanded);
        }
        ips.sort();
        ips.dedup();
        if ips.len() > MAX_SUBNET_HOSTS as usize {
            return Err(CensusError::SubnetTooLarge("*".to_owned()));
        }
        Ok(CensusPlan { ping_targets: ips })
    }
}

/// The pure census plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CensusPlan {
    /// Addresses the ping sweep will probe (ARP warm-up).
    pub ping_targets: Vec<Ipv4Addr>,
}

/// Typed census errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CensusError {
    /// Worker count outside 1..=256.
    InvalidWorkers(usize),
    /// TCP timeout outside bounds.
    InvalidTimeout,
    /// Subnet too large (or unparseable, text carried for the log).
    SubnetTooLarge(String),
}

impl core::fmt::Display for CensusError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CensusError::InvalidWorkers(n) => write!(f, "worker count {n} outside 1..=256"),
            CensusError::InvalidTimeout => write!(f, "tcp timeout outside 50ms..=5s"),
            CensusError::SubnetTooLarge(s) => write!(f, "subnet {s} invalid or above the host bound"),
        }
    }
}

impl std::error::Error for CensusError {}

/// Expands a CIDR (host addresses only, network+broadcast excluded like the
/// oracle's `ipaddress.hosts()`).
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
    if prefix > 32 || prefix < 8 {
        return Err(CensusError::SubnetTooLarge(cidr.to_owned()));
    }
    let base = u32::from(ip) & (!0u32 << (32 - prefix));
    let count = 1u64 << (32 - prefix);
    let mut out = Vec::new();
    for i in 1..count.saturating_sub(1) {
        out.push(Ipv4Addr::from(base + i as u32));
    }
    Ok(out)
}

/// IO shell: runs the census with bounded parallelism.
///
/// `cancel` is polled before every ping and every TCP connect batch item; a
/// set flag stops new work immediately (running items finish their bounded
/// timeout; all sockets/processes drop closed — no orphans).
pub fn run_census(
    cfg: &CensusConfig,
    oui: &OuiTable,
    cancel: &AtomicBool,
) -> Result<CensusReport, CensusError> {
    let plan = cfg.plan()?;
    ping_sweep(&plan.ping_targets, cfg.workers, cancel);
    let arp_output = arp_a();
    let rows = parse_arp_a(&arp_output);
    let targets: Vec<Ipv4Addr> = rows.iter().map(|r| r.ip).collect();
    let open = tcp_connect_scan(&targets, &REGISTERED_PORTS, cfg.workers, cfg.tcp_timeout, cancel);
    let hosts = rows
        .into_iter()
        .map(|r| HostObs {
            ip: r.ip,
            oui_vendor: oui.lookup(&r.mac).map(str::to_owned),
            open_ports: open.get(&r.ip).cloned().unwrap_or_default(),
            mac: r.mac,
            rtt_ms: None,
        })
        .collect();
    Ok(CensusReport {
        hosts,
        ping_targets: plan.ping_targets.len(),
    })
}

/// The census result.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CensusReport {
    /// Observed hosts, ascending by IP.
    pub hosts: Vec<HostObs>,
    /// Number of ping targets the sweep covered.
    pub ping_targets: usize,
}

/// Shells out to system `ping` (oracle parity; no raw-socket privilege).
/// Short-lived child processes join before return; cancellation skips
/// outstanding targets.
fn ping_sweep(ips: &[Ipv4Addr], workers: usize, cancel: &AtomicBool) {
    let (tx, rx) = mpsc::channel::<Ipv4Addr>();
    let rx = std::sync::Mutex::new(rx);
    std::thread::scope(|s| {
        for _ in 0..workers.min(ips.len().max(1)) {
            let rx = &rx;
            s.spawn(move || {
                while let Ok(ip) = rx.lock().map(|r| r.recv()).unwrap_or(Err(mpsc::RecvError)) {
                    if cancel.load(Ordering::Relaxed) {
                        continue; // drain without spawning
                    }
                    let _ = std::process::Command::new("ping")
                        .args(["-c", "1", "-W", "150", "-t", "1", &ip.to_string()])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();
                }
            });
        }
        for ip in ips {
            let _ = tx.send(*ip);
        }
        drop(tx);
    });
}

/// Runs `arp -a` and returns its stdout.
fn arp_a() -> String {
    std::process::Command::new("arp")
        .arg("-a")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// TCP connect-only scan (drop closes; cancellation skips remaining targets).
fn tcp_connect_scan(
    ips: &[Ipv4Addr],
    ports: &[u16],
    workers: usize,
    timeout: Duration,
    cancel: &AtomicBool,
) -> BTreeMap<Ipv4Addr, Vec<u16>> {
    let (tx, rx) = mpsc::channel::<(Ipv4Addr, u16)>();
    let rx = std::sync::Mutex::new(rx);
    let (result_tx, result_rx) = mpsc::channel::<(Ipv4Addr, u16)>();
    let results = std::thread::Builder::new()
        .spawn(move || {
            let mut open: BTreeMap<Ipv4Addr, Vec<u16>> = BTreeMap::new();
            while let Ok((ip, port)) = result_rx.recv() {
                open.entry(ip).or_default().push(port);
            }
            for v in open.values_mut() {
                v.sort_unstable();
            }
            open
        })
        .expect("result collector thread");
    std::thread::scope(|s| {
        for _ in 0..workers.min(ips.len() * ports.len().max(1)) {
            let rx = &rx;
            let result_tx = &result_tx;
            let cancel = cancel;
            s.spawn(move || {
                while let Ok((ip, port)) = rx.lock().map(|r| r.recv()).unwrap_or(Err(mpsc::RecvError)) {
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
        for ip in ips {
            for port in ports {
                let _ = tx.send((*ip, *port));
            }
        }
        drop(tx);
    });
    drop(result_tx);
    results.join().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(t.lookup("d4:ad:fc:00:00:03"), Some("Shenzhen Intellirocks Tech. Co. Ltd."));
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
        assert_eq!(normalize_mac("80:48:2C:a:b:cc"), Some("80:48:2c:0a:0b:cc".to_owned()));
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
        assert_eq!(plan.ping_targets, vec![Ipv4Addr::new(192, 168, 4, 1), Ipv4Addr::new(192, 168, 4, 2)]);
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
        assert!(matches!(
            base(8, Duration::from_millis(200)).plan(),
            Ok(_)
        ));
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
        assert!(!rows.is_empty(), "golden arp fixture produced no rows: {arp}");
        let vendors: Vec<(String, Option<&str>)> = rows
            .iter()
            .map(|r| (r.ip.to_string(), oui.lookup(&r.mac)))
            .collect();
        let vendor_of = |ip: &str| -> Option<&str> {
            vendors
                .iter()
                .find(|(i, _)| i == ip)
                .and_then(|(_, v)| *v)
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
