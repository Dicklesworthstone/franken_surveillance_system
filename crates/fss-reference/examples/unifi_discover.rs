#![forbid(unsafe_code)]
//! Bounded owner-authorized UniFi LAN discovery without camera credentials.
//!
//! Replies are untrusted network claims. This diagnostic does not enroll,
//! authenticate, log into, configure, or take over a camera, and no result
//! establishes that all devices on the network were found.

use std::{
    collections::BTreeSet,
    error::Error,
    net::{Ipv4Addr, SocketAddrV4},
    time::{Duration, Instant},
};

use asupersync::runtime::RuntimeBuilder;
use fss_core::{
    BudgetVector, ContentDigest, DigestAlgorithm, OperationId, RegionId, RegionKind,
    RootAuthoritySpec, RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_reference::unifi_direct::{discovery, metered::MeteredClock};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !(args.len() == 5 || args.len() == 6)
        || args.last().map(String::as_str) != Some("--owner-authorized")
    {
        return Err("usage: unifi_discover BIND_IPV4 PREFIX PRINCIPAL APPROVAL_SHA256 [UNICAST_HINT] --owner-authorized".into());
    }
    let bind: Ipv4Addr = args[0].parse()?;
    let prefix: u8 = args[1].parse()?;
    let principal = &args[2];
    if !principal.starts_with("principal:") || principal.len() > 128 {
        return Err("invalid principal".into());
    }
    let approval = ContentDigest::parse(&args[3])?;
    if approval.algorithm() != DigestAlgorithm::Sha256
        || approval.bytes() == [0; 32]
        || approval.is_laboratory()
    {
        return Err("invalid approval digest".into());
    }
    if !(1..=32).contains(&prefix) {
        return Err("prefix must be between 1 and 32".into());
    }
    let mut targets = vec![SocketAddrV4::new(Ipv4Addr::BROADCAST, 10001)];
    if args.len() == 6 {
        let hint: Ipv4Addr = args[4].parse()?;
        let address = SocketAddrV4::new(hint, 10001);
        if !targets.contains(&address) {
            targets.push(address);
        }
    }
    let resource = format!("unifi-discovery:{approval}:{bind}/{prefix}");
    let config = discovery::Config::new_many(
        bind,
        prefix,
        &targets,
        &resource,
        Duration::from_secs(3),
        128,
    )?;
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 2 * 1024 * 1024;
    budget.bytes = budget.network_bytes;
    let start = Instant::now();
    let elapsed = || TimestampNs(i128::try_from(start.elapsed().as_nanos()).unwrap_or(i128::MAX));
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:unifi-discover".into(),
            operation_id: OperationId::parse("operation:unifi-discover")?,
            principal: principal.clone(),
            capabilities: vec![RuntimeGrant::AdapterNet.as_str().into()],
            deadline: Some(TimestampNs(30_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:local".into(),
            retention_scope: "retention:omitted".into(),
            anchor_universe: approval,
            generation: 1,
        },
        RegionId::new("region:unifi-discover")?,
        RegionKind::Process,
        budget,
        elapsed(),
    )?;
    let grants = authority
        .grants()
        .clone()
        .with_scope(RuntimeGrant::AdapterNet, BTreeSet::from([resource]));
    authority.narrow_grants(grants)?;
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("runtime context unavailable")?;
        let result = run_owned_async(&mut authority, &mut tree,
            TaskSpec { task_id: TaskId::new("task:unifi-discover")?, started_at: elapsed() },
            &cx, async |task, cx| {
                let output: Result<_, Box<dyn Error>> = async {
                    let clock = MeteredClock::new(task, cx, elapsed())?;
                    Ok(discovery::discover(task, cx, clock.now()?, &config).await?)
                }.await;
                let outcome = if output.is_ok() { TaskOutcome::Success } else { TaskOutcome::Failed("discovery stopped".into()) };
                TaskCompletion { output, outcome, completed_at: elapsed() }
            }).await?;
        result.receipt?;
        let report = result.output?;
        println!("discovery stop={:?} candidates={} datagrams={} malformed={} out_of_scope={} identity=unverified absence=unproven", report.stop, report.cameras.len(), report.datagrams, report.malformed, report.out_of_scope);
        for (index, candidate) in report.cameras.iter().enumerate() {
            let eligible = candidate.mac().is_some_and(|mac| report.select_mac_claim(mac) == Ok(index));
            let mac = candidate.mac().map(|value| value.iter().map(|byte| format!("{byte:02x}")).collect::<String>());
            println!("candidate index={index} source={} mac_claim={mac:?} platform_claim={:?} firmware_claim={:?} source_advertised={} unconflicted={eligible} authenticated=false", candidate.source(), candidate.platform(), candidate.firmware(), candidate.source_advertised());
        }
        Ok(())
    })
}

fn main() {
    if let Err(error) = run() {
        eprintln!("unifi_discover_failed: {error}");
        std::process::exit(1);
    }
}
