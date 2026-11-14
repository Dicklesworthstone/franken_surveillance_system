#![forbid(unsafe_code)]
//! Owner-scoped UniFi discovery laboratory command. Results are untrusted
//! observations, not authentication, setup authority, or evidence of absence.

use asupersync::runtime::RuntimeBuilder;
use fss_core::{
    BudgetVector, ContentDigest, DigestAlgorithm, OperationId, RegionId, RegionKind,
    RootAuthoritySpec, RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_reference::unifi_direct::discovery::{self, Config, Report, Stop};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};
use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, SocketAddrV4},
    process::ExitCode,
    time::{Duration, Instant},
};

const USAGE: &str = "fss-unifi-discover (--iface IPV4 --prefix 1..32 | --auto-scope NETWORK/PREFIX [--only-interface NAME] [--limited-broadcast] [--neighbor-cache] [--combined-v2]) [--target IPV4]... [--include-mac-claims] --principal PRINCIPAL --approval sha256:DIGEST --owner-authorized";
const MAX_AUTO_INTERFACES: usize = 4;
const MAX_AUTO_WINDOWS: usize = 4;
const MAX_NEIGHBOR_BYTES: usize = 128 * 1024;

struct Options {
    iface: Ipv4Addr,
    prefix: u8,
    targets: Vec<Ipv4Addr>,
    principal: String,
    approval: ContentDigest,
    auto: bool,
    only_interface: Option<String>,
    combined_v2: bool,
    limited_broadcast: bool,
    include_mac_claims: bool,
    neighbor_cache: bool,
}

fn options(args: &[String]) -> Result<Options, &'static str> {
    let (mut iface, mut prefix, mut principal, mut approval) = (None, None, None, None);
    let mut targets = Vec::new();
    let mut auto_scope = None;
    let mut only_interface = None;
    let mut combined_v2 = false;
    let mut limited_broadcast = false;
    let mut include_mac_claims = false;
    let mut neighbor_cache = false;
    let mut authorized = false;
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        if flag == "--owner-authorized" && !authorized {
            authorized = true;
            i += 1;
            continue;
        }
        if flag == "--combined-v2" && !combined_v2 {
            combined_v2 = true;
            i += 1;
            continue;
        }
        if flag == "--limited-broadcast" && !limited_broadcast {
            limited_broadcast = true;
            i += 1;
            continue;
        }
        if flag == "--include-mac-claims" && !include_mac_claims {
            include_mac_claims = true;
            i += 1;
            continue;
        }
        if flag == "--neighbor-cache" && !neighbor_cache {
            neighbor_cache = true;
            i += 1;
            continue;
        }
        let value = args.get(i + 1).ok_or("missing option value")?;
        match flag {
            "--iface" if iface.is_none() => {
                iface = Some(value.parse().map_err(|_| "invalid interface")?)
            }
            "--prefix" if prefix.is_none() => {
                prefix = Some(value.parse().map_err(|_| "invalid prefix")?)
            }
            "--target" => {
                let target = value.parse().map_err(|_| "invalid target")?;
                if targets.len() == 64 || targets.contains(&target) {
                    return Err("duplicate target or too many targets");
                }
                targets.push(target);
            }
            "--auto-scope" if auto_scope.is_none() => {
                auto_scope = Some(parse_scope(value)?);
            }
            "--only-interface" if only_interface.is_none() && valid_interface_name(value) => {
                only_interface = Some(value.clone());
            }
            "--principal"
                if principal.is_none() && value.starts_with("principal:") && value.len() <= 128 =>
            {
                principal = Some(value.clone())
            }
            "--approval" if approval.is_none() => {
                let digest = ContentDigest::parse(value).map_err(|_| "invalid approval digest")?;
                if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
                    return Err("invalid approval digest");
                }
                approval = Some(digest);
            }
            _ => return Err("unknown, duplicate, or invalid option"),
        }
        i += 2;
    }
    if !authorized {
        return Err("owner authorization is required");
    }
    if combined_v2 && include_mac_claims {
        return Err("combined-v2 cannot include v3 MAC claims");
    }
    let (iface, prefix, targets, auto) = match (iface, prefix, auto_scope) {
        (None, None, Some((network, prefix))) => {
            if targets.len() + 1 + usize::from(limited_broadcast) > 64
                || targets
                    .iter()
                    .any(|target| !scope_host(network, prefix, *target))
            {
                return Err("automatic targets must be distinct hosts in the authorized subnet");
            }
            (network, prefix, targets, true)
        }
        (Some(iface), Some(prefix), None) => (
            iface,
            prefix,
            if targets.is_empty() {
                vec![Ipv4Addr::BROADCAST]
            } else {
                targets
            },
            false,
        ),
        _ => return Err("choose one interface or one automatic subnet scope"),
    };
    if !auto && (only_interface.is_some() || combined_v2 || limited_broadcast || neighbor_cache) {
        return Err("automatic-only option used with an explicit interface");
    }
    if limited_broadcast && only_interface.is_none() {
        return Err("limited broadcast requires an explicitly selected interface");
    }
    if neighbor_cache && only_interface.is_none() {
        return Err("neighbor cache requires an explicitly selected interface");
    }
    Ok(Options {
        iface,
        prefix,
        targets,
        principal: principal.ok_or("principal is required")?,
        approval: approval.ok_or("approval digest is required")?,
        auto,
        only_interface,
        combined_v2,
        limited_broadcast,
        include_mac_claims,
        neighbor_cache,
    })
}

fn valid_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn parse_scope(value: &str) -> Result<(Ipv4Addr, u8), &'static str> {
    let (address, prefix) = value.split_once('/').ok_or("invalid subnet scope")?;
    let network: Ipv4Addr = address.parse().map_err(|_| "invalid subnet scope")?;
    let prefix: u8 = prefix.parse().map_err(|_| "invalid subnet scope")?;
    if !(1..=30).contains(&prefix) {
        return Err("invalid subnet scope");
    }
    let mask = u32::MAX << (32 - prefix);
    let broadcast = Ipv4Addr::from(u32::from(network) | !mask);
    if u32::from(network) & mask != u32::from(network)
        || !((network.is_private() && broadcast.is_private())
            || (network.is_link_local() && broadcast.is_link_local()))
    {
        return Err("subnet scope must be a canonical private or link-local network");
    }
    Ok((network, prefix))
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AutoInterface {
    address: Ipv4Addr,
    prefix: u8,
}

// Restrict each interface to the intersection of its actual subnet and the
// operator's configured subnet. Invalid netmasks and non-host addresses cannot
// expand the authorized network or cause a directed broadcast outside it.
fn select_auto_interface(
    network: Ipv4Addr,
    scope_prefix: u8,
    address: Ipv4Addr,
    netmask: Ipv4Addr,
) -> Option<AutoInterface> {
    let scope_mask = u32::MAX << (32 - scope_prefix);
    if u32::from(address) & scope_mask != u32::from(network) {
        return None;
    }
    let mask = u32::from(netmask);
    let actual_prefix = u8::try_from(mask.leading_ones()).ok()?;
    if !(1..=30).contains(&actual_prefix) || mask != u32::MAX << (32 - actual_prefix) {
        return None;
    }
    let prefix = actual_prefix.max(scope_prefix);
    let effective_mask = u32::MAX << (32 - prefix);
    let host_bits = u32::from(address) & !effective_mask;
    if host_bits == 0 || host_bits == !effective_mask {
        return None;
    }
    Some(AutoInterface { address, prefix })
}

#[cfg(unix)]
fn auto_interfaces(
    network: Ipv4Addr,
    prefix: u8,
    only: Option<&str>,
) -> Result<Vec<AutoInterface>, &'static str> {
    use nix::{ifaddrs::getifaddrs, net::if_::InterfaceFlags};

    let mut selected = Vec::new();
    for entry in getifaddrs().map_err(|_| "interface enumeration failed")? {
        if only.is_some_and(|name| entry.interface_name != name) {
            continue;
        }
        if !entry
            .flags
            .contains(InterfaceFlags::IFF_UP | InterfaceFlags::IFF_BROADCAST)
            || entry
                .flags
                .intersects(InterfaceFlags::IFF_LOOPBACK | InterfaceFlags::IFF_POINTOPOINT)
        {
            continue;
        }
        let Some(address) = entry.address.as_ref().and_then(|a| a.as_sockaddr_in()) else {
            continue;
        };
        let Some(netmask) = entry.netmask.as_ref().and_then(|a| a.as_sockaddr_in()) else {
            continue;
        };
        let Some(candidate) = select_auto_interface(network, prefix, address.ip(), netmask.ip())
        else {
            continue;
        };
        if !selected.contains(&candidate) {
            if selected.len() == MAX_AUTO_INTERFACES {
                return Err("too many matching interfaces; narrow the authorized scope");
            }
            selected.push(candidate);
        }
    }
    selected.sort_unstable();
    if selected.is_empty() {
        return Err("no active broadcast interface in authorized scope");
    }
    Ok(selected)
}

#[cfg(not(unix))]
fn auto_interfaces(
    _: Ipv4Addr,
    _: u8,
    _: Option<&str>,
) -> Result<Vec<AutoInterface>, &'static str> {
    Err("automatic interface discovery is unavailable on this platform")
}

fn directed_broadcast(interface: AutoInterface) -> Ipv4Addr {
    let mask = u32::MAX << (32 - interface.prefix);
    Ipv4Addr::from(u32::from(interface.address) | !mask)
}

fn scope_host(network: Ipv4Addr, prefix: u8, target: Ipv4Addr) -> bool {
    let mask = u32::MAX << (32 - prefix);
    let bits = u32::from(target);
    bits & mask == u32::from(network) & mask && bits & !mask != 0 && bits & !mask != !mask
}

// Validate the complete plan before any packet is sent. A target must be a
// host on at least one selected interface, not merely somewhere in the wider
// operator scope. Query it on each matching interface and keep the broadcast.
fn auto_targets(
    interfaces: &[AutoInterface],
    targets: &[Ipv4Addr],
    limited_broadcast: bool,
) -> Result<Vec<Vec<SocketAddrV4>>, &'static str> {
    if targets.iter().any(|target| {
        !interfaces.iter().any(|interface| {
            scope_host(interface.address, interface.prefix, *target) && *target != interface.address
        })
    }) {
        return Err("a target has no matching active authorized interface");
    }
    Ok(interfaces
        .iter()
        .map(|interface| {
            let mut chosen = vec![SocketAddrV4::new(directed_broadcast(*interface), 10001)];
            if limited_broadcast {
                chosen.push(SocketAddrV4::new(Ipv4Addr::BROADCAST, 10001));
            }
            chosen.extend(targets.iter().filter_map(|target| {
                (scope_host(interface.address, interface.prefix, *target)
                    && *target != interface.address)
                    .then_some(SocketAddrV4::new(*target, 10001))
            }));
            chosen
        })
        .collect())
}

// Neighbor entries are unauthenticated hints, not an inventory of all hosts.
// Only complete entries on the operator-selected interface and an admitted
// subnet become unicast destinations; missing entries never prove absence.
fn parse_neighbor_cache(
    input: &str,
    interface_name: &str,
    interfaces: &[AutoInterface],
) -> Result<Vec<Ipv4Addr>, &'static str> {
    let mut lines = input.lines();
    if !lines
        .next()
        .is_some_and(|line| line.starts_with("IP address"))
    {
        return Err("invalid neighbor cache header");
    }
    let mut addresses = BTreeSet::new();
    for line in lines {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() != 6 {
            return Err("invalid neighbor cache row");
        }
        if fields[5] != interface_name {
            continue;
        }
        let flags = fields[2]
            .strip_prefix("0x")
            .and_then(|value| u32::from_str_radix(value, 16).ok())
            .ok_or("invalid neighbor cache flags")?;
        if flags & 2 == 0 {
            continue;
        }
        let address: Ipv4Addr = fields[0].parse().map_err(|_| "invalid neighbor address")?;
        if interfaces.iter().any(|interface| {
            scope_host(interface.address, interface.prefix, address) && address != interface.address
        }) {
            addresses.insert(address);
        }
        if addresses.len() > MAX_AUTO_WINDOWS * 64 {
            return Err("neighbor cache exceeds bounded discovery capacity");
        }
    }
    Ok(addresses.into_iter().collect())
}

#[cfg(target_os = "linux")]
async fn read_neighbor_cache(
    owner: &fss_runtime::execution::TaskCx<'_>,
    cx: &asupersync::Cx,
    start: Instant,
    resource: &str,
    interface_name: &str,
    interfaces: &[AutoInterface],
) -> Result<Vec<Ipv4Addr>, &'static str> {
    use fss_runtime::drained_blocking::{self, WorkOutcome};
    use std::io::Read;
    cx.checkpoint()
        .map_err(|_| "neighbor inventory cancelled")?;
    let cost = BudgetVector::builder()
        .bytes((MAX_NEIGHBOR_BYTES + 1) as u64)
        .build()
        .map_err(|_| "neighbor inventory budget invalid")?;
    owner
        .checkpoint_for(RuntimeGrant::AdapterNet, resource, elapsed(start), &cost)
        .map_err(|_| "neighbor inventory authority refused")?;
    let interface_name = interface_name.to_owned();
    let interfaces = interfaces.to_vec();
    let work = move |child: asupersync::Cx| {
        child
            .checkpoint()
            .map_err(|_| "neighbor inventory cancelled")?;
        let file =
            std::fs::File::open("/proc/net/arp").map_err(|_| "neighbor cache unavailable")?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(MAX_NEIGHBOR_BYTES + 1)
            .map_err(|_| "neighbor inventory allocation failed")?;
        file.take((MAX_NEIGHBOR_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| "neighbor cache read failed")?;
        child
            .checkpoint()
            .map_err(|_| "neighbor inventory cancelled")?;
        if bytes.len() > MAX_NEIGHBOR_BYTES {
            return Err("neighbor cache exceeds bounded read size");
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| "invalid neighbor cache encoding")?;
        parse_neighbor_cache(text, &interface_name, &interfaces)
    };
    let mut running =
        drained_blocking::start(cx, work).map_err(|_| "neighbor inventory admission failed")?;
    let receipt = running
        .join()
        .await
        .ok_or("neighbor inventory completion unavailable")?;
    if receipt.runtime.is_err() {
        return Err("neighbor inventory runtime stopped");
    }
    owner
        .checkpoint_for(
            RuntimeGrant::AdapterNet,
            resource,
            elapsed(start),
            &BudgetVector::ZERO,
        )
        .map_err(|_| "neighbor inventory authority refused")?;
    match receipt.work {
        WorkOutcome::Finished(result) => result,
        _ => Err("neighbor inventory did not complete"),
    }
}

#[cfg(not(target_os = "linux"))]
async fn read_neighbor_cache(
    _: &fss_runtime::execution::TaskCx<'_>,
    _: &asupersync::Cx,
    _: Instant,
    _: &str,
    _: &str,
    _: &[AutoInterface],
) -> Result<Vec<Ipv4Addr>, &'static str> {
    Err("neighbor cache discovery is only available on Linux")
}

fn auto_neighbor_plans(
    interfaces: &[AutoInterface],
    targets: &[Ipv4Addr],
    neighbors: &[Ipv4Addr],
    limited_broadcast: bool,
) -> Result<Vec<(AutoInterface, Vec<SocketAddrV4>)>, &'static str> {
    // Validate explicitly requested targets before merging untrusted hints.
    auto_targets(interfaces, targets, limited_broadcast)?;
    let mut plans = Vec::new();
    for interface in interfaces {
        let mut hosts = BTreeSet::new();
        hosts.extend(targets.iter().chain(neighbors).copied().filter(|target| {
            scope_host(interface.address, interface.prefix, *target) && *target != interface.address
        }));
        let hosts: Vec<_> = hosts.into_iter().collect();
        let capacity = 64 - 1 - usize::from(limited_broadcast);
        let count = hosts.len().div_ceil(capacity).max(1);
        if plans
            .len()
            .checked_add(count)
            .is_none_or(|total| total > MAX_AUTO_WINDOWS)
        {
            return Err("neighbor targets exceed bounded discovery windows");
        }
        for window in 0..count {
            let mut chosen = vec![SocketAddrV4::new(directed_broadcast(*interface), 10001)];
            if limited_broadcast {
                chosen.push(SocketAddrV4::new(Ipv4Addr::BROADCAST, 10001));
            }
            let from = window * capacity;
            let to = (from + capacity).min(hosts.len());
            chosen.extend(
                hosts[from..to]
                    .iter()
                    .map(|host| SocketAddrV4::new(*host, 10001)),
            );
            plans.push((*interface, chosen));
        }
    }
    Ok(plans)
}

fn elapsed(start: Instant) -> TimestampNs {
    TimestampNs(i128::try_from(start.elapsed().as_nanos()).unwrap_or(i128::MAX))
}

struct Window {
    interface: AutoInterface,
    report: Result<Report, &'static str>,
}

fn execute(options: &Options) -> Result<Vec<Window>, &'static str> {
    let start = Instant::now();
    let resource = if options.auto {
        format!(
            "unifi-discovery:{}:scope:{}/{}",
            options.approval, options.iface, options.prefix
        )
    } else {
        format!(
            "unifi-discovery:{}:{}/{}",
            options.approval, options.iface, options.prefix
        )
    };
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = if options.auto { 2_400_000 } else { 600_000 };
    budget.bytes = budget.network_bytes;
    let root = RootAuthoritySpec {
        trace_id: "trace:unifi-discovery-operator".into(),
        operation_id: OperationId::parse("operation:unifi-discovery-operator")
            .map_err(|_| "invalid operation")?,
        principal: options.principal.clone(),
        capabilities: vec![RuntimeGrant::AdapterNet.as_str().into()],
        deadline: Some(TimestampNs(if options.auto {
            20_000_000_000
        } else {
            10_000_000_000
        })),
        priority: 10,
        budgets: budget,
        privacy_scope: "privacy:owner-local-network".into(),
        retention_scope: "retention:operator-output".into(),
        anchor_universe: options.approval,
        generation: 1,
    };
    let (mut authority, mut tree) = AuthorityCx::root(
        root,
        RegionId::new("region:unifi-discovery-operator").map_err(|_| "invalid region")?,
        RegionKind::Process,
        budget,
        elapsed(start),
    )
    .map_err(|_| "authority refused")?;
    let grants = authority
        .grants()
        .clone()
        .with_scope(RuntimeGrant::AdapterNet, BTreeSet::from([resource.clone()]));
    authority
        .narrow_grants(grants)
        .map_err(|_| "authority scope refused")?;
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()
        .map_err(|_| "runtime unavailable")?;
    let run = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("runtime context unavailable")?;
        let spec = TaskSpec {
            task_id: TaskId::new("task:unifi-discovery-operator").map_err(|_| "invalid task")?,
            started_at: elapsed(start),
        };
        run_owned_async(
            &mut authority,
            &mut tree,
            spec,
            &cx,
            async |owner, runtime_cx| {
                let output = async {
                    let interfaces = if options.auto {
                        runtime_cx
                            .checkpoint()
                            .map_err(|_| "interface inventory cancelled")?;
                        owner
                            .checkpoint_for(
                                RuntimeGrant::AdapterNet,
                                &resource,
                                elapsed(start),
                                &BudgetVector::ZERO,
                            )
                            .map_err(|_| "interface inventory authority refused")?;
                        auto_interfaces(
                            options.iface,
                            options.prefix,
                            options.only_interface.as_deref(),
                        )?
                    } else {
                        vec![AutoInterface {
                            address: options.iface,
                            prefix: options.prefix,
                        }]
                    };
                    let plans: Vec<_> = if options.auto && options.neighbor_cache {
                        let neighbors = read_neighbor_cache(
                            owner,
                            runtime_cx,
                            start,
                            &resource,
                            options
                                .only_interface
                                .as_deref()
                                .ok_or("neighbor interface missing")?,
                            &interfaces,
                        )
                        .await?;
                        auto_neighbor_plans(
                            &interfaces,
                            &options.targets,
                            &neighbors,
                            options.limited_broadcast,
                        )?
                    } else if options.auto {
                        let targets =
                            auto_targets(&interfaces, &options.targets, options.limited_broadcast)?;
                        interfaces.into_iter().zip(targets).collect()
                    } else {
                        vec![(
                            interfaces[0],
                            options
                                .targets
                                .iter()
                                .map(|ip| SocketAddrV4::new(*ip, 10001))
                                .collect(),
                        )]
                    };
                    let mut windows = Vec::with_capacity(plans.len());
                    for (interface, targets) in plans {
                        let report = match Config::new_many(
                            interface.address,
                            interface.prefix,
                            &targets,
                            &resource,
                            Duration::from_secs(3),
                            64,
                        ) {
                            Ok(config) => {
                                discovery::discover(owner, runtime_cx, elapsed(start), &config)
                                    .await
                                    .map_err(|_| "discovery window failed")
                            }
                            Err(_) => Err("invalid network scope"),
                        };
                        windows.push(Window { interface, report });
                    }
                    Ok::<_, &'static str>(windows)
                }
                .await;
                let outcome = if output.as_ref().is_ok_and(|windows| {
                    if options.auto {
                        combine_windows(windows).is_ok()
                    } else {
                        windows.iter().all(|window| {
                            window.report.as_ref().is_ok_and(|report| {
                                matches!(report.stop, Stop::WindowElapsed | Stop::PacketLimit)
                            })
                        })
                    }
                }) {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("discovery stopped or failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: elapsed(start),
                }
            },
        )
        .await
        .map_err(|_| "task admission failed")
    })?;
    run.receipt.map_err(|_| "task receipt refused")?;
    run.output
}

fn json(value: &str) -> String {
    let mut result = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            c if c <= '\u{1f}' => result.push_str(&format!("\\u{:04x}", c as u32)),
            c => result.push(c),
        }
    }
    result.push('"');
    result
}

fn report_json(report: &Report, include_mac_claims: bool) -> String {
    let cameras = report.cameras.iter().enumerate().map(|(index, c)| {
                let claims = report.assess_claims(index).expect("enumerated candidate exists");
                let mac = if include_mac_claims {
                    let value = c.mac().map_or_else(|| "null".to_owned(), |bytes| json(&bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>()));
                    format!(",\"mac_claim\":{value}")
                } else { String::new() };
                format!("{{\"address\":{},\"platform\":{},\"firmware\":{},\"source_advertised\":{},\"identity\":\"unverified\",\"setup\":\"unavailable\"{mac},\"claim_issues\":{{\"missing_or_invalid_mac\":{},\"conflicting_macs_at_address\":{},\"same_mac_at_multiple_addresses\":{},\"conflicting_metadata\":{},\"source_not_advertised\":{},\"incomplete_claim_at_address\":{}}}}}", json(&c.source().ip().to_string()), json(c.platform()), c.firmware().map_or_else(|| "null".into(), json), c.source_advertised(), claims.missing_or_invalid_mac, claims.conflicting_macs_at_address, claims.same_mac_at_multiple_addresses, claims.conflicting_metadata, claims.source_not_advertised, claims.incomplete_claim_at_address)
            }).collect::<Vec<_>>().join(",");
    format!(
        "{{\"schema\":\"fss.unifi_discovery_lab.v{}\",\"datagrams\":{},\"malformed\":{},\"out_of_scope\":{},\"stop\":{},\"absence_proven\":false,\"cameras\":[{}]}}",
        if include_mac_claims { 3 } else { 2 },
        report.datagrams,
        report.malformed,
        report.out_of_scope,
        json(&format!("{:?}", report.stop)),
        cameras
    )
}

fn combine_windows(windows: &[Window]) -> Result<Report, &'static str> {
    let reports: Result<Vec<_>, _> = windows
        .iter()
        .map(|window| window.report.as_ref())
        .collect();
    let reports = reports.map_err(|_| "window_failed")?;
    Report::combine_completed(&reports).map_err(|error| match error {
        discovery::CombineError::Incomplete => "incomplete_window",
        _ => "combination_refused",
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!(
            "{USAGE}\nAutomatic selection scans only active broadcast interfaces inside the supplied authorized subnet, with at most four bounded windows. On Linux, --neighbor-cache adds complete cached neighbors on the explicitly selected interface; the cache is not a complete host inventory. Setup and authentication are not implemented. The approval digest must identify the operator's existing authorization."
        );
        return ExitCode::SUCCESS;
    }
    let result = options(&args).and_then(|options| {
        execute(&options).map(|windows| {
            (
                options.auto,
                options.combined_v2,
                options.include_mac_claims,
                options.neighbor_cache,
                windows,
            )
        })
    });
    match result {
        Ok((false, _, include_mac_claims, _, mut windows)) => match windows
            .pop()
            .expect("explicit interface has one window")
            .report
        {
            Ok(report) => {
                println!("{}", report_json(&report, include_mac_claims));
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("UniFi discovery: {error}; {USAGE}");
                ExitCode::FAILURE
            }
        },
        Ok((true, true, include_mac_claims, _, windows)) => match combine_windows(&windows) {
            Ok(report) => {
                println!("{}", report_json(&report, include_mac_claims));
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("UniFi discovery: {error}");
                ExitCode::FAILURE
            }
        },
        Ok((true, false, include_mac_claims, neighbor_cache, windows)) => {
            let (combined, combination, success) = match combine_windows(&windows) {
                Ok(report) => (report_json(&report, include_mac_claims), "complete", true),
                Err(error) => ("null".to_owned(), error, false),
            };
            let results = windows
                .iter()
                .map(|window| {
                    let (report, error) = match &window.report {
                        Ok(report) => (report_json(report, include_mac_claims), "null".to_owned()),
                        Err(error) => ("null".to_owned(), json(error)),
                    };
                    format!(
                        "{{\"interface\":{},\"prefix\":{},\"report\":{},\"error\":{}}}",
                        json(&window.interface.address.to_string()),
                        window.interface.prefix,
                        report,
                        error
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            let cache = if neighbor_cache {
                ",\"neighbor_cache\":true,\"neighbor_cache_completeness\":\"unknown\""
            } else {
                ""
            };
            println!(
                "{{\"schema\":\"fss.unifi_discovery_auto_lab.v1\",\"absence_proven\":false,\"windows_ok\":{success},\"combination\":{},\"combined\":{combined},\"windows\":[{results}]{cache}}}",
                json(combination)
            );
            if success {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("UniFi discovery: {error}; {USAGE}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authorization_and_scope_are_explicit() {
        let args = [
            "--iface",
            "127.0.0.1",
            "--prefix",
            "8",
            "--principal",
            "principal:owner",
            "--approval",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        ]
        .map(str::to_owned)
        .to_vec();
        assert!(options(&args).is_err());
        let mut authorized = args;
        authorized.push("--owner-authorized".into());
        assert!(options(&authorized).is_ok());
        authorized.extend(["--iface".into(), "127.0.0.2".into()]);
        assert!(options(&authorized).is_err());
    }
    #[test]
    fn json_escapes_device_control_characters() {
        assert_eq!(json("a\"\n\\"), "\"a\\\"\\u000a\\\\\"");
    }

    #[test]
    fn targets_are_scoped_and_duplicates_are_rejected() {
        let mut args = [
            "--iface",
            "192.168.1.4",
            "--prefix",
            "24",
            "--principal",
            "principal:owner",
            "--approval",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "--owner-authorized",
            "--target",
            "192.168.1.20",
        ]
        .map(str::to_owned)
        .to_vec();
        let selected = options(&args).expect("valid unicast target");
        assert_eq!(selected.targets, [Ipv4Addr::new(192, 168, 1, 20)]);
        assert!(
            Config::new(
                selected.iface,
                selected.prefix,
                SocketAddrV4::new(selected.targets[0], 10001),
                "fixture",
                Duration::from_secs(1),
                1
            )
            .is_ok()
        );
        args[10] = "192.168.2.20".into();
        let outside = options(&args).expect("well-formed address");
        assert!(
            Config::new(
                outside.iface,
                outside.prefix,
                SocketAddrV4::new(outside.targets[0], 10001),
                "fixture",
                Duration::from_secs(1),
                1
            )
            .is_err()
        );
        args.extend(["--target".into(), "192.168.1.21".into()]);
        assert_eq!(options(&args).expect("distinct targets").targets.len(), 2);
        args.extend(["--target".into(), "192.168.1.21".into()]);
        assert!(options(&args).is_err());
    }

    #[test]
    fn automatic_scope_must_be_private_canonical_and_explicit() {
        let mut args = [
            "--auto-scope",
            "192.168.4.0/22",
            "--principal",
            "principal:owner",
            "--approval",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "--owner-authorized",
        ]
        .map(str::to_owned)
        .to_vec();
        let chosen = options(&args).expect("owner-scoped automatic discovery");
        assert!(chosen.auto);
        assert_eq!(chosen.iface, Ipv4Addr::new(192, 168, 4, 0));
        assert_eq!(chosen.prefix, 22);
        for invalid in [
            "0.0.0.0/0",
            "192.168.5.0/22",
            "8.8.8.0/24",
            "10.0.0.0/7",
            "192.168.4.0/31",
        ] {
            assert!(
                parse_scope(invalid).is_err(),
                "unexpected scope admission: {invalid}"
            );
        }
        args.extend(["--target".into(), "192.168.4.2".into()]);
        assert_eq!(
            options(&args).unwrap().targets,
            [Ipv4Addr::new(192, 168, 4, 2)]
        );
        for invalid in [
            "192.168.8.2",
            "192.168.4.0",
            "192.168.7.255",
            "255.255.255.255",
        ] {
            let mut invalid_args = args.clone();
            *invalid_args.last_mut().unwrap() = invalid.into();
            assert!(options(&invalid_args).is_err());
        }
    }

    #[test]
    fn scheduled_automatic_mode_can_bind_interface_and_keep_v2_output() {
        let mut args = [
            "--auto-scope",
            "192.168.4.0/22",
            "--only-interface",
            "eno1",
            "--combined-v2",
            "--target",
            "192.168.4.2",
            "--principal",
            "principal:owner",
            "--approval",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "--owner-authorized",
        ]
        .map(str::to_owned)
        .to_vec();
        let chosen = options(&args).unwrap();
        assert!(chosen.auto && chosen.combined_v2);
        assert_eq!(chosen.only_interface.as_deref(), Some("eno1"));
        args.push("--limited-broadcast".into());
        assert!(options(&args).unwrap().limited_broadcast);
        let mut without_interface = args.clone();
        without_interface.drain(2..4);
        assert!(options(&without_interface).is_err());
        args[3] = "bad/name".into();
        assert!(options(&args).is_err());
        assert!(!valid_interface_name(&"a".repeat(16)));
        assert!(valid_interface_name("en0.100"));
        let manual = [
            "--iface",
            "192.168.4.1",
            "--prefix",
            "22",
            "--combined-v2",
            "--principal",
            "principal:owner",
            "--approval",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "--owner-authorized",
        ]
        .map(str::to_owned)
        .to_vec();
        assert!(options(&manual).is_err());
        let mut duplicate = manual;
        duplicate.push("--combined-v2".into());
        assert!(options(&duplicate).is_err());
    }

    #[test]
    fn automatic_targets_follow_actual_interfaces_and_preflight_all_hosts() {
        let left = AutoInterface {
            address: Ipv4Addr::new(192, 168, 4, 10),
            prefix: 24,
        };
        let right = AutoInterface {
            address: Ipv4Addr::new(192, 168, 5, 10),
            prefix: 24,
        };
        let first = Ipv4Addr::new(192, 168, 4, 20);
        let second = Ipv4Addr::new(192, 168, 5, 20);
        let plans = auto_targets(&[left, right], &[first, second], false).unwrap();
        assert_eq!(
            plans[0],
            [
                SocketAddrV4::new(Ipv4Addr::new(192, 168, 4, 255), 10001),
                SocketAddrV4::new(first, 10001)
            ]
        );
        assert_eq!(
            plans[1],
            [
                SocketAddrV4::new(Ipv4Addr::new(192, 168, 5, 255), 10001),
                SocketAddrV4::new(second, 10001)
            ]
        );
        assert!(auto_targets(&[left], &[first, second], false).is_err());
        assert!(auto_targets(&[left], &[left.address], false).is_err());
        assert!(auto_targets(&[left], &[Ipv4Addr::new(192, 168, 4, 255)], false).is_err());
        assert_eq!(auto_targets(&[left], &[], false).unwrap()[0].len(), 1);
        let limited = auto_targets(&[left], &[first], true).unwrap();
        assert_eq!(
            limited[0],
            [
                SocketAddrV4::new(Ipv4Addr::new(192, 168, 4, 255), 10001),
                SocketAddrV4::new(Ipv4Addr::BROADCAST, 10001),
                SocketAddrV4::new(first, 10001)
            ]
        );
        let overlap = AutoInterface {
            address: Ipv4Addr::new(192, 168, 4, 11),
            prefix: 24,
        };
        let plans = auto_targets(&[left, overlap], &[first], false).unwrap();
        assert_eq!(plans[0][1], plans[1][1]);
    }

    #[test]
    fn neighbor_hints_require_the_selected_interface_and_scope() {
        let interface = AutoInterface {
            address: Ipv4Addr::new(192, 168, 4, 10),
            prefix: 24,
        };
        let input = "IP address HW type Flags HW address Mask Device\n\
192.168.4.21 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0\n\
192.168.4.21 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0\n\
192.168.4.22 0x1 0x0 00:00:00:00:00:00 * eth0\n\
192.168.4.23 0x1 0x2 aa:bb:cc:dd:ee:ff * eth1\n\
192.168.5.24 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0\n\
192.168.4.10 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0\n";
        assert_eq!(
            parse_neighbor_cache(input, "eth0", &[interface]).unwrap(),
            [Ipv4Addr::new(192, 168, 4, 21)]
        );
        assert!(parse_neighbor_cache("not a cache\n", "eth0", &[interface]).is_err());
        assert!(parse_neighbor_cache("IP address\nmalformed\n", "eth0", &[interface]).is_err());
        assert!(
            parse_neighbor_cache(
                "IP address\n192.168.4.21 0x1 bad aa * eth0\n",
                "eth0",
                &[interface]
            )
            .is_err()
        );
    }

    #[test]
    fn neighbor_targets_are_batched_without_silent_truncation() {
        let interface = AutoInterface {
            address: Ipv4Addr::new(192, 168, 4, 1),
            prefix: 22,
        };
        let hosts: Vec<_> = (2..=131).map(|n| Ipv4Addr::new(192, 168, 4, n)).collect();
        let plans = auto_neighbor_plans(&[interface], &[hosts[0]], &hosts, true).unwrap();
        assert_eq!(plans.len(), 3);
        assert!(
            plans
                .iter()
                .all(|(_, targets)| targets.len() <= 64 && targets[1].ip() == &Ipv4Addr::BROADCAST)
        );
        let unique: BTreeSet<_> = plans
            .iter()
            .flat_map(|(_, targets)| targets.iter().skip(2).map(|target| *target.ip()))
            .collect();
        assert_eq!(unique.len(), hosts.len());
        assert!(hosts.iter().all(|host| unique.contains(host)));
        let too_many: Vec<_> = (2_u32..=250)
            .map(|n| Ipv4Addr::from(u32::from(Ipv4Addr::new(192, 168, 4, 0)) + n))
            .collect();
        assert!(auto_neighbor_plans(&[interface], &[], &too_many, true).is_err());
        assert!(
            auto_neighbor_plans(&[interface], &[Ipv4Addr::new(192, 168, 8, 2)], &[], false)
                .is_err()
        );
    }

    #[test]
    fn neighbor_mode_requires_an_authorized_selected_interface() {
        let mut args = [
            "--auto-scope",
            "192.168.4.0/22",
            "--neighbor-cache",
            "--principal",
            "principal:owner",
            "--approval",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "--owner-authorized",
        ]
        .map(str::to_owned)
        .to_vec();
        assert!(options(&args).is_err());
        args.extend(["--only-interface".into(), "eth0".into()]);
        assert!(options(&args).unwrap().neighbor_cache);
        args.retain(|arg| arg != "--owner-authorized");
        assert!(options(&args).is_err());
    }

    #[test]
    fn interface_selection_intersects_actual_and_authorized_subnets() {
        let network = Ipv4Addr::new(192, 168, 4, 0);
        let address = Ipv4Addr::new(192, 168, 5, 10);
        let narrow =
            select_auto_interface(network, 22, address, Ipv4Addr::new(255, 255, 255, 0)).unwrap();
        assert_eq!(narrow.prefix, 24);
        assert_eq!(directed_broadcast(narrow), Ipv4Addr::new(192, 168, 5, 255));
        let wide =
            select_auto_interface(network, 22, address, Ipv4Addr::new(255, 255, 0, 0)).unwrap();
        assert_eq!(wide.prefix, 22);
        assert_eq!(directed_broadcast(wide), Ipv4Addr::new(192, 168, 7, 255));
        assert!(
            select_auto_interface(
                network,
                22,
                Ipv4Addr::new(192, 168, 8, 2),
                Ipv4Addr::new(255, 255, 0, 0)
            )
            .is_none()
        );
        assert!(
            select_auto_interface(network, 22, address, Ipv4Addr::new(255, 0, 255, 0)).is_none()
        );
        assert!(
            select_auto_interface(
                network,
                22,
                Ipv4Addr::new(192, 168, 5, 0),
                Ipv4Addr::new(255, 255, 255, 0)
            )
            .is_none()
        );
        assert!(
            select_auto_interface(
                network,
                22,
                Ipv4Addr::new(192, 168, 5, 255),
                Ipv4Addr::new(255, 255, 255, 0)
            )
            .is_none()
        );
    }

    #[test]
    fn automatic_combination_refuses_failed_or_truncated_windows() {
        let interface = AutoInterface {
            address: Ipv4Addr::new(192, 168, 4, 2),
            prefix: 22,
        };
        let report = |stop| Report {
            cameras: Vec::new(),
            datagrams: 0,
            malformed: 0,
            out_of_scope: 0,
            stop,
        };
        let completed = [Window {
            interface,
            report: Ok(report(Stop::WindowElapsed)),
        }];
        assert_eq!(
            combine_windows(&completed).unwrap().stop,
            Stop::WindowElapsed
        );
        let truncated = [Window {
            interface,
            report: Ok(report(Stop::PacketLimit)),
        }];
        assert!(matches!(
            combine_windows(&truncated),
            Err("incomplete_window")
        ));
        let failed = [Window {
            interface,
            report: Err("synthetic failure"),
        }];
        assert!(matches!(combine_windows(&failed), Err("window_failed")));
        assert!(matches!(combine_windows(&[]), Err("combination_refused")));
    }
}
