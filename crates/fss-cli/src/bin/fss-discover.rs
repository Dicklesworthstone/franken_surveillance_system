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
use fss_reference::discovery::{DiscoverConfig, DiscoverReport, discover};

#[path = "fss-discover/liveness.rs"]
mod liveness;

const HELP: &str = "fss-discover --subnet CIDR [--subnet CIDR ...] [--iface IP] [--beacon-seconds N] [--watch N]\n\
                    \x20 [--standards-seconds N] --owner-authorized --json\n\
                    \n\
                    Owner-network camera discovery: passive-first (beacons + mDNS/SSDP/\n\
                    WS-Discovery), then a bounded census (ping -> ARP -> OUI -> registered\n\
                    port connects), typed brand classification and adapter dispatch with\n\
                    the exact missing owner-auth ingredient per candidate. Owner-network\n\
                    scope only. Report: fss.discover_cli.v1 JSON on stdout.\n\
                    \n\
                    Retain network health in an existing deployment with:\n\
                    --root ABS_DIR --site SITE --bind IP=SENSOR[,CLASS] [--bind ...]\n\
                    Bind each retained endpoint within --subnet (at most 64).\n\
                    Classes: tutk, tuya, onvif, battery_event_driven, unknown (default),\n\
                    provisioned_agent. Responses are bounded by each sweep window;\n\
                    network return never proves pixel continuity. Retained observations\n\
                    appear in fss orient and fss follow.";

const MAX_ARGS: usize = 160; // 64 bindings, 8 subnets, and bounded options

#[derive(Debug)]
struct Options {
    subnets: Vec<String>,
    iface: Ipv4Addr,
    beacon_seconds: u64,
    standards_seconds: u64,
    /// `--watch N`: sweep every N seconds, emitting one report per sweep
    /// plus typed device_state_change records from the liveness watchdog.
    watch_seconds: Option<u64>,
    retention: Option<liveness::Options>,
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
    let mut root = None;
    let mut site = None;
    let mut bindings = Vec::new();
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
            "--root" | "--site" | "--bind" => {
                let value = args
                    .get(i + 1)
                    .and_then(|value| value.to_str())
                    .ok_or("missing liveness option value")?
                    .to_owned();
                match flag {
                    "--root" if root.is_none() => root = Some(value),
                    "--site" if site.is_none() => site = Some(value),
                    "--bind" => bindings.push(value),
                    _ => return Err("duplicate --root or --site"),
                }
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
        return Err(
            "--owner-authorized is required (network discovery touches the LAN; the flag attests owner authorization)",
        );
    }
    Ok(Options {
        subnets,
        iface,
        beacon_seconds,
        standards_seconds,
        watch_seconds,
        retention: liveness::Options::parse(root, site, bindings)?,
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
    if let Some(retention) = &o.retention {
        retention.preflight(&cfg)?;
    }
    let report = discover(&cfg, &cancel).map_err(|_| "ERR-DISCOVER-CENSUS-001: census failed")?;
    Ok((report, cfg))
}

fn run(o: &Options) -> Result<String, &'static str> {
    let mut clock = SweepClock::new();
    let sweep_started_ns = clock.next_ns();
    let (report, cfg) = run_typed(o)?;
    let sweep_completed_ns = clock.next_ns();
    let mut lines = vec![format_report(&report, &cfg)];
    if let Some(retention) = &o.retention {
        lines.extend(retention.retain(&report, sweep_started_ns, sweep_completed_ns)?);
    }
    Ok(lines.join("\n"))
}

fn format_report(report: &DiscoverReport, cfg: &DiscoverConfig) -> String {
    let mut rows = Vec::new();
    for c in &report.candidates {
        let signals: Vec<String> = c
            .brand
            .signals
            .iter()
            .map(|s| match s {
                fss_reference::discovery::Signal::OuiVendor(v) => json_escape(&format!("oui:{v}")),
                fss_reference::discovery::Signal::PortSignature(p) => {
                    format!(
                        "\"ports:{}\"",
                        p.iter()
                            .map(|x| x.to_string())
                            .collect::<Vec<_>>()
                            .join("+")
                    )
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
    use fss_reference::discovery::watchdog::DeviceWatchdog;

    let mut watchdog = DeviceWatchdog::new();
    let period = std::time::Duration::from_secs(period_secs);
    // Wall-clock-free sweep clock: NTP adjustments must never shift the
    // watchdog's silence arithmetic (a backward jump would fake fresh
    // sightings; a forward jump would fake mass offline). Anchor once,
    // advance by monotonic Instant deltas only.
    let mut clock = SweepClock::new();
    loop {
        let sweep_start = std::time::Instant::now();
        let sweep_started_ns = clock.next_ns();
        match run_typed(o) {
            Ok((report, cfg)) => {
                let now_ns = clock.next_ns();
                let retained = match &o.retention {
                    Some(retention) => match retention.retain(&report, sweep_started_ns, now_ns) {
                        Ok(retained) => retained,
                        Err(error) => {
                            eprintln!("{error}");
                            return ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code);
                        }
                    },
                    None => Vec::new(),
                };
                println!("{}", format_report(&report, &cfg));
                for record in retained {
                    println!("{record}");
                }
                update_watchdog_window(&mut watchdog, &report, sweep_started_ns, now_ns);
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

/// Zero-duration replay seam for the watchdog regression fixtures.
#[cfg(test)]
fn update_watchdog(
    watchdog: &mut fss_reference::discovery::watchdog::DeviceWatchdog,
    report: &DiscoverReport,
    now_ns: u64,
) {
    update_watchdog_window(watchdog, report, now_ns, now_ns);
}

/// Cached metadata is not a response. Age accepted responses from sweep start so
/// a long scan cannot report every response as if it just arrived at completion.
fn update_watchdog_window(
    watchdog: &mut fss_reference::discovery::watchdog::DeviceWatchdog,
    report: &DiscoverReport,
    sweep_started_ns: u64,
    now_ns: u64,
) {
    use fss_reference::discovery::Brand;
    use fss_reference::discovery::watchdog::DeviceClass;

    let fresh = report.fresh_candidate_ips();
    for candidate in &report.candidates {
        let id = candidate.host.ip.to_string();
        let class = match candidate.brand.brand {
            Brand::Tutk => DeviceClass::Tutk,
            Brand::Tuya => DeviceClass::Tuya,
            Brand::Standards => DeviceClass::Onvif,
            _ => DeviceClass::Unknown,
        };
        watchdog.register(&id, class, None);
        if fresh.contains(&candidate.host.ip) {
            watchdog.observe(&id, sweep_started_ns);
        }
    }
    watchdog.evaluate(now_ns);
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
                .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
                .unwrap_or(0),
            base_instant: std::time::Instant::now(),
        }
    }

    fn next_ns(&mut self) -> u64 {
        self.base_ns.saturating_add(
            u64::try_from(self.base_instant.elapsed().as_nanos()).unwrap_or(u64::MAX),
        )
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
        let o = parse(&args(&[
            "--subnet",
            "192.168.4.0/22",
            "--json",
            "--owner-authorized",
        ]))
        .unwrap();
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
            "--json",
            "--owner-authorized",
            "--subnet",
            "10.0.0.0/24",
            "--subnet",
            "10.0.1.0/24",
            "--subnet",
            "10.0.2.0/24",
            "--subnet",
            "10.0.3.0/24",
            "--subnet",
            "10.0.4.0/24",
            "--subnet",
            "10.0.5.0/24",
            "--subnet",
            "10.0.6.0/24",
            "--subnet",
            "10.0.7.0/24",
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
        assert!(
            parse(&args(&[
                "--subnet",
                "10.0.0.0/24",
                "--beacon-seconds",
                "0",
                "--json",
                "--owner-authorized"
            ]))
            .is_err()
        );
        assert!(
            parse(&args(&[
                "--subnet",
                "10.0.0.0/24",
                "--standards-seconds",
                "999",
                "--json",
                "--owner-authorized"
            ]))
            .is_err()
        );
    }

    #[test]
    fn refuses_unknown_flag() {
        assert!(parse(&args(&["--scan", "--json", "--owner-authorized"])).is_err());
    }

    #[test]
    fn json_escape_shapes() {
        assert_eq!(json_escape("a\"b"), "\"a\\\"b\"");
    }

    fn watchdog_report(port: Option<u16>) -> DiscoverReport {
        use fss_reference::discovery::{DeviceCandidate, HostObs, classify_host, dispatch};
        let host = HostObs {
            ip: Ipv4Addr::new(192, 168, 4, 10),
            mac: "00:11:22:33:44:55".to_owned(),
            oui_vendor: Some("cached vendor".to_owned()),
            open_ports: port.into_iter().collect(),
            rtt_ms: None,
        };
        let brand = classify_host(&host, &[], None);
        let dispatch = dispatch(&brand);
        DiscoverReport {
            candidates: vec![DeviceCandidate {
                host,
                brand,
                dispatch,
            }],
            ..DiscoverReport::default()
        }
    }

    #[test]
    fn repeated_arp_cache_entries_do_not_hide_a_camera_outage() {
        use fss_reference::discovery::watchdog::{
            DeviceClass, DeviceWatchdog, WatchOfflineReason, WatchState,
        };
        let id = "192.168.4.10";
        let mut watchdog = DeviceWatchdog::new();
        watchdog.register(id, DeviceClass::Unknown, Some((10, 20)));
        update_watchdog(&mut watchdog, &watchdog_report(Some(554)), 100);
        assert_eq!(watchdog.state_of(id), Some(&WatchState::Observable));
        watchdog.drain_changes();

        let mut cached = watchdog_report(None);
        // Classification metadata and unattributed probe totals must not refresh
        // the last accepted endpoint response at 100.
        cached.ssdp_responders = 1;
        cached.mdns_answers = 1;
        cached.wsd_matches = 1;
        update_watchdog(&mut watchdog, &cached, 109);
        assert!(watchdog.changes().is_empty());
        update_watchdog(&mut watchdog, &cached, 110);
        assert_eq!(
            watchdog.state_of(id),
            Some(&WatchState::Silent { silent_for_ns: 10 })
        );
        update_watchdog(&mut watchdog, &cached, 120);
        assert_eq!(
            watchdog.state_of(id),
            Some(&WatchState::NotObservable {
                reason: WatchOfflineReason::SilentBeyondThreshold,
            })
        );
        assert_eq!(watchdog.changes().len(), 2);

        // A new registered-port accept really does restore network liveness.
        update_watchdog(&mut watchdog, &watchdog_report(Some(554)), 121);
        assert_eq!(watchdog.state_of(id), Some(&WatchState::Observable));
        update_watchdog(&mut watchdog, &cached, 131);
        assert_eq!(
            watchdog.state_of(id),
            Some(&WatchState::Silent { silent_for_ns: 10 })
        );
    }

    #[test]
    fn only_fresh_responses_from_the_candidate_endpoint_refresh_watchdog() {
        use fss_reference::discovery::watchdog::{
            DeviceClass, DeviceWatchdog, WatchOfflineReason, WatchState,
        };
        let id = "192.168.4.10";
        let mut watchdog = DeviceWatchdog::new();
        watchdog.register(id, DeviceClass::Unknown, Some((10, 20)));
        let mut report = watchdog_report(Some(22)); // not a registered camera-port accept
        report.beacons = vec![
            ("192.168.4.11:6667".to_owned(), 7),
            ("not-an-endpoint".to_owned(), 7),
            ("[::1]:6667".to_owned(), 7),
        ];
        update_watchdog(&mut watchdog, &report, 100);
        assert_eq!(
            watchdog.state_of(id),
            Some(&WatchState::NotObservable {
                reason: WatchOfflineReason::NeverObserved,
            })
        );
        assert!(watchdog.changes().is_empty());
        assert!(report.fresh_candidate_ips().is_empty());

        report.beacons.push(("192.168.4.10:6667".to_owned(), 7));
        update_watchdog(&mut watchdog, &report, 101);
        assert_eq!(watchdog.state_of(id), Some(&WatchState::Observable));
        assert_eq!(
            report.fresh_candidate_ips(),
            std::collections::BTreeSet::from([Ipv4Addr::new(192, 168, 4, 10)])
        );
        report.beacons.clear();
        update_watchdog(&mut watchdog, &report, 111);
        assert_eq!(
            watchdog.state_of(id),
            Some(&WatchState::Silent { silent_for_ns: 10 })
        );
    }

    #[test]
    fn default_watch_ages_responses_across_the_whole_sweep() {
        use fss_reference::discovery::watchdog::{DeviceClass, DeviceWatchdog, WatchState};
        let mut watchdog = DeviceWatchdog::new();
        watchdog.register("192.168.4.10", DeviceClass::Unknown, Some((10, 20)));
        update_watchdog_window(&mut watchdog, &watchdog_report(Some(554)), 100, 130);
        assert!(matches!(
            watchdog.state_of("192.168.4.10"),
            Some(WatchState::NotObservable { .. })
        ));
    }
}
