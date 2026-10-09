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
    discover, DiscoverConfig, Readiness,
};

const HELP: &str = "fss-discover --subnet CIDR [--subnet CIDR ...] [--iface IP] [--beacon-seconds N]\n\
                    \x20 [--standards-seconds N] --owner-authorized --json\n\
                    \n\
                    Owner-network camera discovery: passive-first (beacons + mDNS/SSDP/\n\
                    WS-Discovery), then a bounded census (ping -> ARP -> OUI -> registered\n\
                    port connects), typed brand classification and adapter dispatch with\n\
                    the exact missing owner-auth ingredient per candidate. Owner-network\n\
                    scope only. Report: fss.discover_cli.v1 JSON on stdout.";

const MAX_ARGS: usize = 16;

#[derive(Debug)]
struct Options {
    subnets: Vec<String>,
    iface: Ipv4Addr,
    beacon_seconds: u64,
    standards_seconds: u64,
}

fn parse(args: &[std::ffi::OsString]) -> Result<Options, &'static str> {
    if args.is_empty() || args.len() > MAX_ARGS {
        return Err("argument bound exceeded");
    }
    let mut subnets = Vec::new();
    let mut iface = Ipv4Addr::new(192, 168, 4, 165);
    let mut beacon_seconds = 10u64;
    let mut standards_seconds = 5u64;
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
            _ => return Err("unknown flag; use fss-discover --help"),
        }
    }
    if subnets.is_empty() {
        return Err("at least one --subnet CIDR is required");
    }
    if subnets.len() > 8 {
        return Err("at most 8 subnets");
    }
    Ok(Options {
        subnets,
        iface,
        beacon_seconds,
        standards_seconds,
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

fn run(o: &Options) -> Result<String, &'static str> {
    let cfg = DiscoverConfig::for_subnets(o.subnets.clone(), o.iface);
    let cfg = DiscoverConfig {
        beacon_seconds: o.beacon_seconds,
        standards_seconds: o.standards_seconds,
        ..cfg
    };
    let cancel = AtomicBool::new(false);
    let report =
        discover(&cfg, &cancel).map_err(|_| "ERR-DISCOVER-CENSUS-001: census failed")?;
    let mut rows = Vec::new();
    for c in &report.candidates {
        let signals: Vec<String> = c
            .brand
            .signals
            .iter()
            .map(|s| match s {
                fss_reference::discovery::Signal::OuiVendor(v) => {
                    format!("\"oui:{v}\"")
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
    Ok(format!(
        "{{\"schema\":\"fss.discover_cli.v1\",\"subnets\":{:?},\"ping_targets\":{},\"beacons\":{},\"ssdp\":{},\"mdns\":{},\"wsd\":{},\"hosts\":[{}]}}",
        cfg.census.subnets,
        report.ping_targets,
        report.beacons.len(),
        report.ssdp_responders,
        report.mdns_answers,
        report.wsd_matches,
        rows.join(","),
    ))
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
        Ok(o) => match run(&o) {
            Ok(report) => {
                println!("{report}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
            }
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
        let o = parse(&args(&["--subnet", "192.168.4.0/22", "--json"])).unwrap();
        assert_eq!(o.subnets, vec!["192.168.4.0/22"]);
    }

    #[test]
    fn refuses_no_subnet() {
        assert!(parse(&args(&["--json"])).is_err());
    }

    #[test]
    fn refuses_bad_seconds() {
        assert!(parse(&args(&["--subnet", "10.0.0.0/24", "--beacon-seconds", "0", "--json"])).is_err());
        assert!(parse(&args(&["--subnet", "10.0.0.0/24", "--standards-seconds", "999", "--json"])).is_err());
    }

    #[test]
    fn refuses_unknown_flag() {
        assert!(parse(&args(&["--scan", "--json"])).is_err());
    }

    #[test]
    fn json_escape_shapes() {
        assert_eq!(json_escape("a\"b"), "\"a\\\"b\"");
    }
}
