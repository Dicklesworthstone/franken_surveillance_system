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

use std::collections::{BTreeMap, BTreeSet};
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
/// Maximum CIDR declarations admitted before expanding any addresses.
pub const MAX_SUBNETS: usize = 8;
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
    rows.sort_by(|a, b| a.ip.cmp(&b.ip));
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
        let Ok(ip) = ip.parse::<Ipv4Addr>() else { continue };
        if !flags.contains('H') {
            continue;
        }
        let Some(mac) = normalize_mac(mac) else { continue };
        if mac == "ff:ff:ff:ff:ff:ff" || mac.starts_with("01:00:5e") {
            continue;
        }
        rows.push(ArpRow { ip, mac, iface: iface.to_owned() });
    }
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
    if prefix > 32 || prefix < 8 {
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
    if cancel.load(Ordering::Relaxed) {
        return Ok(plan.assemble_report(Vec::new(), &[], &BTreeMap::new(), oui));
    }
    let responders = ping_sweep(&plan.ping_targets, cfg.workers, cancel);
    if cancel.load(Ordering::Relaxed) {
        return Ok(plan.assemble_report(Vec::new(), &responders, &BTreeMap::new(), oui));
    }
    // A ping reply can arrive before the kernel has committed the neighbour
    // entry, and the cache is read once per sweep otherwise: re-read briefly
    // until every responder we can resolve has a MAC, so the vendor lookup is
    // not silently starved (macOS also expires entries under sweep load).
    let mut rows = Vec::new();
    let debug = std::env::var_os("FSS_DISCOVER_DEBUG").is_some();
    for attempt in 0..4 {
        let mut raw = parse_arp_a(&arp_a());
        raw.extend(parse_netstat_rn(&netstat_rn()));
        if debug {
            eprintln!("DEBUG raw={} first={:?}", raw.len(), raw.first());
        }
        rows = plan.scoped_neighbors(raw);
        let resolved = rows.len();
        if resolved >= responders.len() || attempt == 3 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
    }
    if debug {
        let n = netstat_rn();
        eprintln!(
            "DEBUG responders={} rows={} arp_len={} netstat_len={} sample={:?}",
            responders.len(),
            rows.len(),
            arp_a().len(),
            n.len(),
            n.lines().filter(|l| l.contains("UHLW")).take(2).collect::<Vec<_>>()
        );
    }
    let targets: Vec<Ipv4Addr> = rows
        .iter()
        .map(|r| r.ip)
        .chain(responders.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let open = tcp_connect_scan(
        &targets,
        &REGISTERED_PORTS,
        cfg.workers,
        cfg.tcp_timeout,
        cancel,
    );
    Ok(plan.assemble_report(rows, &responders, &open, oui))
}

/// The census result.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CensusReport {
    /// Observed hosts, ascending by IP.
    pub hosts: Vec<HostObs>,
    /// Number of admitted ping targets; cancellation may stop before all are tried.
    pub ping_targets: usize,
    /// Sorted unique IPs with an actual successful ICMP reply or accepted TCP
    /// connection in this sweep. Cached neighbors alone never appear here.
    pub responders: Vec<Ipv4Addr>,
}

/// Shells out to system `ping` (oracle parity; no raw-socket privilege).
/// Short-lived child processes join before return; cancellation skips
/// outstanding targets.
fn ping_sweep(ips: &[Ipv4Addr], workers: usize, cancel: &AtomicBool) -> Vec<Ipv4Addr> {
    let (tx, rx) = mpsc::sync_channel::<Ipv4Addr>(workers.max(1));
    let rx = std::sync::Mutex::new(rx);
    let responders = std::sync::Mutex::new(BTreeSet::new());
    std::thread::scope(|s| {
        for _ in 0..workers.min(ips.len().max(1)) {
            let rx = &rx;
            let responders = &responders;
            s.spawn(move || {
                while let Ok(ip) = rx.lock().map(|r| r.recv()).unwrap_or(Err(mpsc::RecvError)) {
                    if cancel.load(Ordering::Relaxed) {
                        continue; // drain without spawning
                    }
                    // macOS uses milliseconds for -W and -t for a deadline;
                    // Linux uses seconds for -W and -w for the total deadline.
                    #[cfg(target_os = "macos")]
                    let flags = ["-c", "1", "-W", "150", "-t", "1"];
                    #[cfg(not(target_os = "macos"))]
                    let flags = ["-c", "1", "-W", "1", "-w", "1"];
                    let status = std::process::Command::new("ping")
                        .args(flags)
                        .arg(ip.to_string())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();
                    if status.is_ok_and(|status| status.success())
                        && let Ok(mut replies) = responders.lock()
                    {
                        replies.insert(ip);
                    }
                }
            });
        }
        for ip in ips {
            if cancel.load(Ordering::Relaxed) || tx.send(*ip).is_err() {
                break;
            }
        }
        drop(tx);
    });
    responders
        .into_inner()
        .unwrap_or_default()
        .into_iter()
        .collect()
}

/// Runs `arp -a` and returns its stdout.
fn arp_a() -> String {
    // `arp` lives in /usr/sbin on macOS, which is absent from the PATH of a
    // GUI-spawned process; falling back by absolute path keeps the vendor
    // lookup from silently starving (every MAC empty, every row Unknown).
    // macOS 27 returns an empty table for `arp -a` (reverse-DNS form) while
    // `arp -an` answers immediately; try the numeric form first and keep `-a`
    // only as a fallback for older hosts.
    for (program, flag) in [
        ("arp", "-an"),
        ("/usr/sbin/arp", "-an"),
        ("/sbin/arp", "-an"),
        ("arp", "-a"),
        ("/usr/sbin/arp", "-a"),
        ("/sbin/arp", "-a"),
    ] {
        match std::process::Command::new(program).arg(flag).output() {
            Ok(o) => {
                if std::env::var_os("FSS_DISCOVER_DEBUG").is_some() {
                    eprintln!(
                        "DEBUG arp prog={program} {flag} status={:?} out={} err={:?}",
                        o.status.code(),
                        o.stdout.len(),
                        String::from_utf8_lossy(&o.stderr)
                    );
                }
                if o.status.success() {
                    return String::from_utf8_lossy(&o.stdout).into_owned();
                }
            }
            Err(e) => {
                if std::env::var_os("FSS_DISCOVER_DEBUG").is_some() {
                    eprintln!("DEBUG arp prog={program} spawn_err={e:?}");
                }
            }
        }
    }
    String::new()
}

/// Neighbour view from the routing table (`arp` may be unavailable in sandboxes).
fn netstat_rn() -> String {
    for program in ["/usr/sbin/netstat", "/usr/bin/netstat", "netstat"] {
        if let Ok(o) = std::process::Command::new(program).arg("-rn").output() {
            if o.status.success() {
                return String::from_utf8_lossy(&o.stdout).into_owned();
            }
        }
    }
    String::new()
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
        assert!(matches!(base(8, Duration::from_millis(200)).plan(), Ok(_)));
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
