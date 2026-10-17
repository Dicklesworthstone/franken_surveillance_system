#![forbid(unsafe_code)]
//! fss-discover — owner-network camera discovery service (SVC `fss discover`,
//! bead family fss-yodhk): census + Tuya beacons + standards probes → typed
//! DeviceCandidate table with adapter dispatch and exact owner-auth
//! requirements.
//!
//! Owner-network scope ONLY: the subnet list comes from the operator; the
//! census, multicast probes and TCP connects never leave those subnets.
//! `--json` is required (machine contract `fss.discover_cli.v1`); nothing
//! secret ever appears (no MACs are secrets on the operator's own LAN, but
//! no credentials or keys are read or printed).

use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;

use fss_cli::ExitIdentity;
use fss_reference::discovery::{
    DiscoverConfig, DiscoverReport, Readiness, discover,
};

const HELP: &str = "fss-discover --subnet CIDR [--subnet CIDR ...] [--iface IP] [--beacon-seconds N] [--watch N]\n\
                    \x20 [--standards-seconds N] --owner-authorized --json\n\
                    \n\
                    Owner-network camera discovery: passive-first (beacons + mDNS/SSDP/\n\
                    WS-Discovery), then a bounded census (ping -> ARP -> OUI -> registered\n\
                    port connects), typed brand classification and adapter dispatch with\n\
                    the exact missing owner-auth ingredient per candidate. Owner-network\n\
                    scope only. Report: fss.discover_cli.v1 JSON on stdout.";

const MAX_ARGS: usize = 24; // 8 subnets (16) + --json + --owner-authorized + --beacon/--standards/--watch pairs

#[derive(Debug)]
struct Options {
    subnets: Vec<String>,
    iface: Ipv4Addr,
    beacon_seconds: u64,
    standards_seconds: u64,
    /// `--watch N`: sweep every N seconds, emitting one report per sweep
    /// plus typed device_state_change records from the liveness watchdog.
    watch_seconds: Option<u64>,
}

fn parse(args: &[std::ffi::OsString]) -> Result<Options, &'static str> {
    if args.is_empty() || args.len() > MAX_ARGS {
        return Err("argument bound exceeded");
    }
    let mut subnets = Vec::new();
    let mut iface = Ipv4Addr::new(192, 168, 4, 165);
    let mut beacon_seconds = 10u64;
    let mut standards_seconds = 5u64;
    let mut watch_seconds: Option<u64> = None;
    let mut i = 0;
    while i < args.len() {
        let Some(flag) = args[i].to_str() else {
            return Err("non-UTF-8 argument");
        };
        match flag {
            "--json" | "--owner-authorized" => {
                i += 1;
                continue;
            }
            "--subnet" => {
                let v = args
                    .get(i + 1)
                    .and_then(|s| s.to_str())
                    .ok_or("missing --subnet value")?;
                if !v.contains('/') {
                    return Err("--subnet requires CIDR form");
                }
                subnets.push(v.to_owned());
                i += 2;
            }
            "--iface" => {
                iface = args
                    .get(i + 1)
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse().ok())
                    .ok_or("invalid --iface IP")?;
                i += 2;
            }
            "--beacon-seconds" | "--standards-seconds" => {
                let v = args
                    .get(i + 1)
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse().ok())
                    .ok_or("invalid seconds")?;
                if v == 0 || v > 120 {
                    return Err("seconds out of bounds (1..=120)");
                }
                if flag == "--beacon-seconds" {
                    beacon_seconds = v;
                } else {
                    standards_seconds = v;
                }
                i += 2;
            }
            "--watch" => {
                let v = args
                    .get(i + 1)
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse().ok())
                    .ok_or("invalid --watch seconds")?;
                if v == 0 || v > 3600 {
                    return Err("--watch seconds out of bounds (1..=3600)");
                }
                watch_seconds = Some(v);
                i += 2;
            }
            _ => return Err("unknown flag; use fss-discover --help"),
        }
    }
    if subnets.is_empty() {
        return Err("at least one --subnet CIDR is required");
    }
    if subnets.len() > 8 {
        return Err("at most 8 subnets");
    }
    if !args.iter().any(|a| a == "--owner-authorized") {
        return Err("--owner-authorized is required (network discovery touches the LAN; the flag attests owner authorization)");
    }
    Ok(Options {
        subnets,
        iface,
        beacon_seconds,
        standards_seconds,
        watch_seconds,
    })
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn run_typed(o: &Options) -> Result<(DiscoverReport, DiscoverConfig), &'static str> {
    let cfg = DiscoverConfig::for_subnets(o.subnets.clone(), o.iface);
    let cfg = DiscoverConfig {
        beacon_seconds: o.beacon_seconds,
        standards_seconds: o.standards_seconds,
        ..cfg
    };
    let cancel = AtomicBool::new(false);
    let report =
        discover(&cfg, &cancel).map_err(|_| "ERR-DISCOVER-CENSUS-001: census failed")?;
    Ok((report, cfg))
}

fn run(o: &Options) -> Result<String, &'static str> {
    let (report, cfg) = run_typed(o)?;
    Ok(format_report(&report, &cfg))
}

fn format_report(report: &DiscoverReport, cfg: &DiscoverConfig) -> String {
    let mut rows = Vec::new();
    for c in &report.candidates {
        let signals: Vec<String> = c
            .brand
            .signals
            .iter()
            .map(|s| match s {
                fss_reference::discovery::Signal::OuiVendor(v) => {
                    json_escape(&format!("oui:{v}"))
                }
                fss_reference::discovery::Signal::PortSignature(p) => {
                    format!("\"ports:{}\"", p.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("+"))
                }
                fss_reference::discovery::Signal::TuyaBeacon(cmd) => {
                    format!("\"beacon:{cmd}\"")
                }
                fss_reference::discovery::Signal::LocallyAdministeredMac => {
                    "\"laa-mac\"".to_owned()
                }
                fss_reference::discovery::Signal::TutkListener(port) => {
                    format!("\"tutk-listener:{port}\"")
                }
            })
            .collect();
        rows.push(format!(
            "{{\"ip\":\"{}\",\"mac\":\"{}\",\"vendor\":{},\"open_ports\":{:?},\"brand\":\"{:?}\",\"confidence\":\"{:?}\",\"signals\":[{}],\"adapter\":\"{:?}\",\"readiness\":\"{:?}\",\"missing\":{},\"blocked_reason\":{}}}",
            c.host.ip,
            c.host.mac,
            c.host.oui_vendor.as_deref().map(json_escape).unwrap_or_else(|| "null".into()),
            c.host.open_ports,
            c.brand.brand,
            c.brand.confidence,
            signals.join(","),
            c.dispatch.adapter,
            c.dispatch.readiness,
            c.dispatch
                .missing
                .as_ref()
                .map(|m| format!("\"{:?}\"", m))
                .unwrap_or_else(|| "null".into()),
            c.dispatch
                .blocked_reason
                .map(json_escape)
                .unwrap_or_else(|| "null".into()),
        ));
    }
    format!(
        "{{\"schema\":\"fss.discover_cli.v1\",\"subnets\":{:?},\"ping_targets\":{},\"beacons\":{},\"ssdp\":{},\"mdns\":{},\"wsd\":{},\"hosts\":[{}]}}",
        cfg.census.subnets,
        report.ping_targets,
        report.beacons.len(),
        report.ssdp_responders,
        report.mdns_answers,
        report.wsd_matches,
        rows.join(","),
    )
}


/// `--watch` loop: one discovery sweep per period; each sweep prints the
/// standard report object (unchanged `fss.discover_cli.v1` shape) as one
/// JSONL line, then feeds the device-liveness watchdog from the typed
/// candidate set and prints any resulting `device_state_change` records as
/// self-describing JSONL lines. Consumers discriminate on the record shape
/// (transitions carry `"type":"device_state_change"`).
///
/// Runs until terminated (Ctrl-C/SIGTERM); a camera going dark between
/// sweeps surfaces as a typed transition, never as silence.
fn watch_loop(o: &Options, period_secs: u64) -> ExitCode {
    use fss_reference::discovery::Brand;
    use fss_reference::discovery::watchdog::{DeviceClass, DeviceWatchdog};

    let mut watchdog = DeviceWatchdog::new();
    let period = std::time::Duration::from_secs(period_secs);
    // Wall-clock-free sweep clock: NTP adjustments must never shift the
    // watchdog's silence arithmetic (a backward jump would fake fresh
    // sightings; a forward jump would fake mass offline). Anchor once,
    // advance by monotonic Instant deltas only.
    let mut clock = SweepClock::new();
    loop {
        let sweep_start = std::time::Instant::now();
        match run_typed(o) {
            Ok((report, cfg)) => {
                println!("{}", format_report(&report, &cfg));
                let now_ns = clock.next_ns();
                for c in &report.candidates {
                    let id = c.host.ip.to_string();
                    let class = match c.brand.brand {
                        Brand::Tutk => DeviceClass::Tutk,
                        Brand::Tuya => DeviceClass::Tuya,
                        Brand::Standards => DeviceClass::Onvif,
                        _ => DeviceClass::Unknown,
                    };
                    watchdog.register(&id, class, None);
                    watchdog.observe(&id, now_ns);
                }
                watchdog.evaluate(now_ns);
                for change in watchdog.drain_changes() {
                    println!("{}", change.to_record());
                }
            }
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code);
            }
        }
        let elapsed = sweep_start.elapsed();
        if elapsed < period {
            std::thread::sleep(period - elapsed);
        }
    }
}

/// A sweep clock whose values move only with monotonic elapsed time.
/// The epoch base is cosmetic (records embed it); deltas are Instant-true.
struct SweepClock {
    base_ns: u64,
    base_instant: std::time::Instant,
}

impl SweepClock {
    fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        Self {
            base_ns: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
            base_instant: std::time::Instant::now(),
        }
    }

    fn next_ns(&mut self) -> u64 {
        self.base_ns + self.base_instant.elapsed().as_nanos() as u64
    }
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help" | "-h")) {
        print!("{HELP}");
        return ExitCode::SUCCESS;
    }
    if !args.iter().any(|a| a == "--json") {
        eprintln!("ERR-DISCOVER-ARGUMENT-001: --json is required; use fss-discover --help");
        return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
    }
    match parse(&args) {
        Ok(o) => match o.watch_seconds {
            Some(period) => watch_loop(&o, period),
            None => match run(&o) {
            Ok(report) => {
                println!("{report}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
            }
            },
        },
        Err(e) => {
            eprintln!("ERR-DISCOVER-ARGUMENT-001: {e}; use fss-discover --help");
            ExitCode::from(ExitIdentity::MALFORMED_VALUE.code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<std::ffi::OsString> {
        v.iter().map(std::ffi::OsString::from).collect()
    }

    #[test]
    fn parses_minimal() {
        let o = parse(&args(&["--subnet", "192.168.4.0/22", "--json", "--owner-authorized"])).unwrap();
        assert_eq!(o.subnets, vec!["192.168.4.0/22"]);
    }

    #[test]
    fn refuses_no_subnet() {
        assert!(parse(&args(&["--json", "--owner-authorized"])).is_err());
    }

    #[test]
    fn refuses_without_owner_authorization() {
        assert!(parse(&args(&["--subnet", "192.168.4.0/22", "--json"])).is_err());
    }

    #[test]
    fn eight_subnets_fit_the_argument_bound() {
        let o = parse(&args(&[
            "--json", "--owner-authorized",
            "--subnet", "10.0.0.0/24", "--subnet", "10.0.1.0/24",
            "--subnet", "10.0.2.0/24", "--subnet", "10.0.3.0/24",
            "--subnet", "10.0.4.0/24", "--subnet", "10.0.5.0/24",
            "--subnet", "10.0.6.0/24", "--subnet", "10.0.7.0/24",
        ]));
        assert!(o.is_ok(), "8 subnets + required flags must fit: {o:?}");
        assert_eq!(o.unwrap().subnets.len(), 8);
        // Nine subnets refuse at the subnet check.
        let mut v = vec!["--json", "--owner-authorized"];
        for _ in 0..9 {
            v.push("--subnet");
            v.push("10.0.0.0/24");
        }
        assert!(parse(&args(&v)).is_err());
    }

    #[test]
    fn refuses_bad_seconds() {
        assert!(parse(&args(&["--subnet", "10.0.0.0/24", "--beacon-seconds", "0", "--json", "--owner-authorized"])).is_err());
        assert!(parse(&args(&["--subnet", "10.0.0.0/24", "--standards-seconds", "999", "--json", "--owner-authorized"])).is_err());
    }

    #[test]
    fn refuses_unknown_flag() {
        assert!(parse(&args(&["--scan", "--json", "--owner-authorized"])).is_err());
    }

    #[test]
    fn json_escape_shapes() {
        assert_eq!(json_escape("a\"b"), "\"a\\\"b\"");
    }
}
