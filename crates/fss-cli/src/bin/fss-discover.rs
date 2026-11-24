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
// Reuse the scoped laboratory probe without invoking a second process or
// promoting its unauthenticated observations to enrolled camera identities.
#[allow(dead_code)]
#[path = "fss-unifi-discover.rs"]
mod unifi_discovery;

const HELP: &str = "fss-discover --subnet CIDR [--subnet CIDR ...] [--iface IP] [--beacon-seconds N] [--watch N]\n\
                    \x20 [--standards-seconds N] [--unifi-only] [--unifi-principal PRINCIPAL --unifi-approval SHA256] --owner-authorized --json\n\
                    \n\
                    Owner-network camera discovery: passive-first (beacons + mDNS/SSDP/\n\
                    WS-Discovery + UniFi UDP-10001), then a pure-Rust bounded census (TCP\n\
                    liveness + /proc/net/arp where available -> OUI -> registered port\n\
                    connects + non-intrusive RTSP OPTIONS banner peek), typed brand\n\
                    classification and adapter dispatch with the exact missing owner-auth\n\
                    ingredient per candidate. Owner-network scope only (zero subprocess\n\
                    shell-outs). Report: fss.discover_cli.v1 JSON on stdout.\n\
                    The optional UniFi probe emits separate laboratory JSON records;\n\
                    camera claims are unauthenticated and setup is not performed.\n\
                    --unifi-only skips all other discovery probes and the census.\n\
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
    unifi: Vec<unifi_discovery::Options>,
    unifi_only: bool,
}

fn parse(args: &[std::ffi::OsString]) -> Result<Options, &'static str> {
    if args.is_empty() || args.len() > MAX_ARGS {
        return Err("argument bound exceeded");
    }
    let mut subnets = Vec::new();
    let mut iface = Ipv4Addr::UNSPECIFIED;
    let mut beacon_seconds = 10u64;
    let mut standards_seconds = 5u64;
    let mut watch_seconds: Option<u64> = None;
    let mut root = None;
    let mut site = None;
    let mut bindings = Vec::new();
    let mut unifi_principal = None;
    let mut unifi_approval = None;
    let mut unifi_only = false;
    let mut i = 0;
    while i < args.len() {
        let Some(flag) = args[i].to_str() else {
            return Err("non-UTF-8 argument");
        };
        match flag {
            "--unifi-only" if !unifi_only => {
                unifi_only = true;
                i += 1;
            }
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
            "--unifi-principal" | "--unifi-approval" => {
                let value = args
                    .get(i + 1)
                    .and_then(|value| value.to_str())
                    .ok_or("missing UniFi authority value")?
                    .to_owned();
                let slot = if flag == "--unifi-principal" {
                    &mut unifi_principal
                } else {
                    &mut unifi_approval
                };
                if slot.replace(value).is_some() {
                    return Err("duplicate UniFi authority option");
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
    let unifi = match (unifi_principal, unifi_approval) {
        (None, None) => Vec::new(),
        (Some(principal), Some(approval)) => {
            unifi_discovery::prepare_scopes(&subnets, &principal, &approval)?
        }
        _ => return Err("UniFi discovery requires both --unifi-principal and --unifi-approval"),
    };
    if unifi_only
        && (unifi.is_empty()
            || watch_seconds.is_some()
            || root.is_some()
            || site.is_some()
            || !bindings.is_empty()
            || args.iter().any(|arg| {
                matches!(
                    arg.to_str(),
                    Some("--iface" | "--beacon-seconds" | "--standards-seconds")
                )
            }))
    {
        return Err(
            "--unifi-only requires UniFi authority and does not support other probe, watch, or retained liveness options",
        );
    }
    Ok(Options {
        subnets,
        iface,
        beacon_seconds,
        standards_seconds,
        watch_seconds,
        retention: liveness::Options::parse(root, site, bindings)?,
        unifi,
        unifi_only,
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
    let mut report = discover(&cfg, &cancel).map_err(|error| match error {
        fss_reference::discovery::DiscoveryError::Census(_) => "ERR-DISCOVER-CENSUS-001: invalid census scope or resource bounds",
        fss_reference::discovery::DiscoveryError::InvalidProbeConfig => "ERR-DISCOVER-ARGUMENT-001: invalid probe timing or service questions",
        fss_reference::discovery::DiscoveryError::ObservationLimit => "ERR-DISCOVER-LIMIT-001: observation or service-hint bound exceeded; narrow the authorized subnet",
    })?;
    probe_tutk_listeners(&mut report, &cancel);
    Ok((report, cfg))
}

/// Credential-less TUTK `0x0601` LAN-search round over the candidates.
///
/// The classifier already scores a TUTK listener (`Signal::TutkListener`) but
/// nothing ever supplied one, so a Wyze-class unit — zero TCP ports, no OUI in
/// this host's ARP view — fell through as `Unknown`/`ImportOnly`. The probe is
/// the vendor's own discovery frame: no credentials, one bounded UDP round, and
/// the answer proves a TUTK listener before the brand is upgraded.
fn probe_tutk_listeners(report: &mut DiscoverReport, cancel: &AtomicBool) {
    use fss_reference::discovery::{Brand, BrandConfidence, Confidence, dispatch};
    use fss_tutk::oldproto::{ProbeResponse, build_probe, parse_response};
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};

    if report.candidates.is_empty() {
        return;
    }
    let Ok(sock) = UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)) else {
        return;
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(120)));
    // Empty UID is silent on this fleet; the vendor reply echoes our placeholder.
    let probe = build_probe(
        b"WYZE0123456789ABCDEF",
        0x0601,
        [0xF5, 0x05, 0x20, 0x26, 0x10, 0x08],
    );
    // Wi-Fi power-save swallows the first frames; the proven reference client
    // needs several spaced attempts before a sleeping camera answers.
    if std::env::var_os("FSS_DISCOVER_DEBUG").is_some() {
        let hex: String = probe.iter().map(|b| format!("{b:02x}")).collect();
        eprintln!("DEBUG tutk probe {hex}");
    }
    let mut answered = std::collections::BTreeMap::<std::net::Ipv4Addr, u16>::new();
    for _round in 0..8 {
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        for candidate in &report.candidates {
            let target = std::net::SocketAddr::from((candidate.host.ip, 32761));
            let _ = sock.send_to(&probe, target);
        }
        let drain_until = Instant::now() + Duration::from_millis(300);
        while Instant::now() < drain_until {
            let mut buf = [0u8; 512];
            let Ok((n, from)) = sock.recv_from(&mut buf) else {
                continue;
            };
            let std::net::IpAddr::V4(ip) = from.ip() else {
                continue;
            };
            let parsed = parse_response(&buf[..n]);
            if std::env::var_os("FSS_DISCOVER_DEBUG").is_some() {
                eprintln!("DEBUG tutk rx {ip}:{} n={n} {parsed:?}", from.port());
            }
            if matches!(parsed, ProbeResponse::Old { .. }) {
                answered.insert(ip, from.port());
            }
        }
    }
    for candidate in &mut report.candidates {
        let Some(port) = answered.get(&candidate.host.ip).copied() else {
            continue;
        };
        if !matches!(candidate.brand.brand, Brand::Unknown | Brand::Tutk) {
            continue;
        }
        if !candidate
            .brand
            .signals
            .iter()
            .any(|signal| matches!(signal, fss_reference::discovery::Signal::TutkListener(_)))
        {
            candidate
                .brand
                .signals
                .push(fss_reference::discovery::Signal::TutkListener(port));
        }
        let has_corroboration = candidate.brand.signals.iter().any(|s| {
            matches!(
                s,
                fss_reference::discovery::Signal::OuiVendor(_)
                    | fss_reference::discovery::Signal::PortSignature(_)
            )
        });
        candidate.brand = BrandConfidence {
            brand: Brand::Tutk,
            confidence: if has_corroboration {
                Confidence::Confirmed
            } else {
                Confidence::Likely
            },
            signals: candidate.brand.signals.clone(),
        };
        candidate.dispatch = dispatch(&candidate.brand);
    }
}

fn run(o: &Options) -> Result<String, &'static str> {
    if o.unifi_only {
        return Ok(o
            .unifi
            .iter()
            .map(unifi_discovery::scope_report)
            .collect::<Vec<_>>()
            .join("\n"));
    }
    let mut clock = SweepClock::new();
    let sweep_started_ns = clock.next_ns();
    let (report, cfg) = run_typed(o)?;
    let sweep_completed_ns = clock.next_ns();
    let mut lines = vec![format_report(&report, &cfg)];
    lines.extend(o.unifi.iter().map(unifi_discovery::scope_report));
    if let Some(retention) = &o.retention {
        lines.extend(retention.retain(&report, sweep_started_ns, sweep_completed_ns)?);
    }
    Ok(lines.join("\n"))
}

fn format_report(report: &DiscoverReport, cfg: &DiscoverConfig) -> String {
    let fresh = report.fresh_candidate_ips();
    let mut responses = std::collections::BTreeMap::<_, std::collections::BTreeSet<_>>::new();
    for response in &report.current_responses {
        responses
            .entry(response.endpoint)
            .or_default()
            .insert(response.kind.as_str());
    }
    let mut services = std::collections::BTreeMap::<_, Vec<_>>::new();
    for hint in &report.advertised_services {
        services.entry(hint.candidate).or_default().push(format!(
            "{{\"service\":{},\"responder\":{},\"port\":{}}}",
            json_escape(hint.service.as_str()),
            json_escape(&hint.responder.to_string()),
            hint.port
                .map_or_else(|| "null".into(), |port| port.to_string()),
        ));
    }
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
                fss_reference::discovery::Signal::AdvertisedService(service) => {
                    json_escape(&format!("advertised-service:{}", service.as_str()))
                }
                fss_reference::discovery::Signal::UniFiDiscovery { model, firmware } => {
                    json_escape(&format!(
                        "unifi-discovery:model={};fw={}",
                        model.as_deref().unwrap_or("unknown"),
                        firmware.as_deref().unwrap_or("unknown")
                    ))
                }
                fss_reference::discovery::Signal::RtspBanner {
                    port,
                    server,
                    realm,
                } => json_escape(&format!(
                    "rtsp-banner:{port}:server={};realm={}",
                    server.as_deref().unwrap_or(""),
                    realm.as_deref().unwrap_or("")
                )),
            })
            .collect();
        rows.push(format!(
            "{{\"ip\":\"{}\",\"mac\":\"{}\",\"vendor\":{},\"open_ports\":{:?},\"brand\":\"{:?}\",\"confidence\":\"{:?}\",\"signals\":[{}],\"adapter\":\"{:?}\",\"readiness\":\"{:?}\",\"missing\":{},\"blocked_reason\":{},\"observed_this_sweep\":{},\"response_kinds\":[{}],\"advertised_services\":[{}]}}",
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
            fresh.contains(&c.host.ip),
            responses.remove(&c.host.ip).unwrap_or_default().into_iter().map(json_escape).collect::<Vec<_>>().join(","),
            services.remove(&c.host.ip).unwrap_or_default().join(","),
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
    let watch_cancel = fss_runtime::asupersync_ops::WorkerCancelToken::new();
    loop {
        if watch_cancel.is_cancelled() {
            return ExitCode::SUCCESS;
        }
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
                for scope in &o.unifi {
                    println!("{}", unifi_discovery::scope_report(scope));
                }
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
        if elapsed < period
            && watch_cancel
                .sleep_cooperative(period - elapsed, std::time::Duration::from_millis(50))
                .is_err()
        {
            return ExitCode::SUCCESS;
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
            Brand::UniFiProtect | Brand::Tapo | Brand::Standards => DeviceClass::Onvif,
            Brand::Tutk => DeviceClass::Tutk,
            Brand::Tuya => DeviceClass::Tuya,
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
    fn unifi_probe_requires_both_authority_inputs_and_valid_scopes() {
        const APPROVAL: &str =
            "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let base = ["--subnet", "192.168.4.0/22", "--json", "--owner-authorized"];
        let mut supplied = base.to_vec();
        supplied.extend(["--unifi-principal", "principal:owner"]);
        assert!(parse(&args(&supplied)).is_err());
        supplied.extend(["--unifi-approval", APPROVAL]);
        let options = parse(&args(&supplied)).unwrap();
        assert_eq!(options.unifi.len(), 1);
        supplied.extend(["--subnet", "8.8.8.0/24"]);
        assert!(parse(&args(&supplied)).is_err());
        supplied.truncate(base.len());
        supplied.extend([
            "--unifi-principal",
            "principal:owner",
            "--unifi-approval",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ]);
        assert!(parse(&args(&supplied)).is_err());
    }

    #[test]
    fn unifi_only_refuses_without_authority_or_with_other_modes() {
        const APPROVAL: &str =
            "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let mut values = vec![
            "--subnet",
            "192.168.4.0/22",
            "--json",
            "--owner-authorized",
            "--unifi-only",
        ];
        assert!(parse(&args(&values)).is_err());
        values.extend([
            "--unifi-principal",
            "principal:owner",
            "--unifi-approval",
            APPROVAL,
        ]);
        assert!(parse(&args(&values)).unwrap().unifi_only);
        values.extend(["--watch", "300"]);
        assert!(parse(&args(&values)).is_err());
        values.truncate(values.len() - 2);
        values.extend(["--root", "/tmp/fss", "--site", "site:one"]);
        assert!(parse(&args(&values)).is_err());
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

    #[test]
    fn standards_report_and_watchdog_distinguish_proxy_from_advertised_camera()
    -> Result<(), Box<dyn std::error::Error>> {
        use fss_cli::json_input::{Value, parse};
        use fss_reference::discovery::watchdog::{DeviceClass, DeviceWatchdog, WatchState};
        use fss_reference::discovery::{
            CensusReport, MdnsAnswer, MdnsObservation, assemble_discovery,
        };
        let proxy = Ipv4Addr::new(192, 168, 4, 2);
        let camera = Ipv4Addr::new(192, 168, 4, 44);
        let cfg = DiscoverConfig::for_subnets(vec!["192.168.4.0/24".into()], proxy);
        let scope = cfg.census.plan()?;
        let report = assemble_discovery(
            &scope,
            CensusReport {
                hosts: Vec::new(),
                responders: Vec::new(),
                ping_targets: scope.ping_targets.len(),
            },
            &[],
            &[MdnsObservation {
                responder: proxy,
                answers: vec![
                    MdnsAnswer {
                        name: "Front._rtsp._tcp.local".into(),
                        rr_type: 33,
                        ttl: 120,
                        rdata: "front.local".into(),
                        srv_port: Some(8554),
                    },
                    MdnsAnswer {
                        name: "front.local".into(),
                        rr_type: 1,
                        ttl: 120,
                        rdata: camera.to_string(),
                        srv_port: None,
                    },
                ],
            }],
            &[],
            &[],
        )?;
        let encoded = parse(&format_report(&report, &cfg))?;
        let object = encoded.object().ok_or("report is not an object")?;
        assert_eq!(
            object.get("schema").and_then(Value::text),
            Some("fss.discover_cli.v1")
        );
        let rows = object
            .get("hosts")
            .and_then(Value::array)
            .ok_or("missing hosts")?;
        let row = |ip: &str| {
            rows.iter()
                .filter_map(Value::object)
                .find(|row| row.get("ip").and_then(Value::text) == Some(ip))
        };
        let camera_row = row("192.168.4.44").ok_or("missing camera")?;
        assert_eq!(
            camera_row
                .get("observed_this_sweep")
                .and_then(Value::boolean),
            Some(false)
        );
        assert_eq!(
            camera_row.get("missing").and_then(Value::text),
            Some("StandardsEndpointCredentials")
        );
        let hint = camera_row
            .get("advertised_services")
            .and_then(Value::array)
            .and_then(|hints| hints.first())
            .and_then(Value::object)
            .ok_or("missing service hint")?;
        assert_eq!(hint.get("port").and_then(Value::integer), Some(8554));
        assert_eq!(
            hint.get("responder").and_then(Value::text),
            Some("192.168.4.2")
        );
        let proxy_row = row("192.168.4.2").ok_or("missing proxy")?;
        assert_eq!(
            proxy_row
                .get("observed_this_sweep")
                .and_then(Value::boolean),
            Some(true)
        );
        assert_eq!(
            proxy_row.get("response_kinds").and_then(Value::array),
            Some([Value::Text("mdns_response".into())].as_slice())
        );
        let mut watchdog = DeviceWatchdog::new();
        watchdog.register("192.168.4.2", DeviceClass::Unknown, Some((10, 20)));
        watchdog.register("192.168.4.44", DeviceClass::Onvif, Some((10, 20)));
        update_watchdog_window(&mut watchdog, &report, 100, 105);
        assert_eq!(
            watchdog.state_of("192.168.4.2"),
            Some(&WatchState::Observable)
        );
        assert!(matches!(
            watchdog.state_of("192.168.4.44"),
            Some(WatchState::NotObservable { .. })
        ));
        Ok(())
    }

    #[test]
    fn format_report_renders_unifi_protect_tapo_and_rtsp_banner_signals()
    -> Result<(), Box<dyn std::error::Error>> {
        use fss_cli::json_input::{Value, parse};
        use fss_reference::discovery::{
            OUI_SNAPSHOT, OuiTable, assemble_discovery_with_probes, parse_proc_net_arp,
            parse_rtsp_options_response, parse_unifi_discovery_reply,
        };
        let cfg = DiscoverConfig::for_subnets(
            vec!["192.168.4.0/24".into()],
            Ipv4Addr::new(192, 168, 4, 2),
        );
        let scope = cfg.census.plan()?;
        let oui = OuiTable::parse_snapshot(OUI_SNAPSHOT);

        let arp_table = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.4.243    0x1         0x2         50:3d:d1:e3:e2:07     *        eth0
192.168.4.23     0x1         0x2         80:48:2c:52:59:05     *        eth0
";
        let neighbors = parse_proc_net_arp(arp_table);

        // Ubiquiti G4 Instant UDP-10001 TLV reply
        let g4_ip = Ipv4Addr::new(192, 168, 4, 177);
        let g4_mac: [u8; 6] = [0x00, 0x15, 0x6d, 0x12, 0x34, 0x56];
        let mut body = Vec::new();
        for &(tag, val) in &[
            (1u8, &g4_mac[..]),
            (3u8, &b"UVC.SAV530q.v4.72.38.67"[..]),
            (12u8, &b"UVC G4 Instant"[..]),
        ] {
            body.push(tag);
            body.extend_from_slice(&(val.len() as u16).to_be_bytes());
            body.extend_from_slice(val);
        }
        let mut pkt = vec![1, 0];
        pkt.extend_from_slice(&(body.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&body);
        let unifi_g4 = parse_unifi_discovery_reply(g4_ip, &pkt)?;

        let open_ports = std::collections::BTreeMap::from([
            (g4_ip, vec![443, 7442, 7447]),
            (Ipv4Addr::new(192, 168, 4, 243), vec![443, 8800]),
            (Ipv4Addr::new(192, 168, 4, 23), vec![554]),
        ]);
        let census = scope.assemble_report(neighbors, &[g4_ip], &open_ports, &oui);
        let rtsp = parse_rtsp_options_response(
            g4_ip,
            7447,
            b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nServer: UniFi Protect RTSP\r\nWWW-Authenticate: Digest realm=\"ubnt\"\r\n\r\n",
        )
        .ok_or("rtsp parse failed")?;

        let report = assemble_discovery_with_probes(
            &scope,
            census,
            &[],
            &[],
            &[],
            &[],
            &[unifi_g4],
            &[rtsp],
        )?;
        let encoded = parse(&format_report(&report, &cfg))?;
        let rows = encoded
            .object()
            .and_then(|o| o.get("hosts"))
            .and_then(Value::array)
            .ok_or("missing hosts")?;
        let row = |ip: &str| {
            rows.iter()
                .filter_map(Value::object)
                .find(|r| r.get("ip").and_then(Value::text) == Some(ip))
        };

        let g4_row = row("192.168.4.177").ok_or("missing G4 Instant")?;
        assert_eq!(
            g4_row.get("brand").and_then(Value::text),
            Some("UniFiProtect")
        );
        assert_eq!(
            g4_row.get("confidence").and_then(Value::text),
            Some("Confirmed")
        );
        assert_eq!(
            g4_row.get("adapter").and_then(Value::text),
            Some("UniFiProtect")
        );
        assert_eq!(
            g4_row.get("missing").and_then(Value::text),
            Some("UniFiProtectCredentials")
        );

        let tapo_row = row("192.168.4.243").ok_or("missing Tapo C460")?;
        assert_eq!(tapo_row.get("brand").and_then(Value::text), Some("Tapo"));
        assert_eq!(tapo_row.get("adapter").and_then(Value::text), Some("Tapo"));
        assert_eq!(
            tapo_row.get("missing").and_then(Value::text),
            Some("TapoLocalCredentials")
        );

        let wyze_row = row("192.168.4.23").ok_or("missing Wyze Cam v4")?;
        assert_eq!(wyze_row.get("brand").and_then(Value::text), Some("Tutk"));
        assert_eq!(
            wyze_row.get("confidence").and_then(Value::text),
            Some("Likely")
        );
        assert_eq!(
            wyze_row.get("adapter").and_then(Value::text),
            Some("Standards")
        );
        Ok(())
    }
}
