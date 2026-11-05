#![forbid(unsafe_code)]
//! Owner-scoped UniFi discovery laboratory command. Results are untrusted
//! observations, not authentication, setup authority, or evidence of absence.

use asupersync::runtime::RuntimeBuilder;
use fss_core::{
    BudgetVector, ContentDigest, DigestAlgorithm, OperationId, RegionId, RegionKind,
    RootAuthoritySpec, RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_reference::unifi_direct::discovery::{self, Config, Report};
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

const USAGE: &str = "fss-unifi-discover --iface IPV4 --prefix 1..32 --principal PRINCIPAL --approval sha256:DIGEST --owner-authorized";

struct Options {
    iface: Ipv4Addr,
    prefix: u8,
    principal: String,
    approval: ContentDigest,
}

fn options(args: &[String]) -> Result<Options, &'static str> {
    let (mut iface, mut prefix, mut principal, mut approval) = (None, None, None, None);
    let mut authorized = false;
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        if flag == "--owner-authorized" && !authorized {
            authorized = true;
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
    Ok(Options {
        iface: iface.ok_or("interface is required")?,
        prefix: prefix.ok_or("prefix is required")?,
        principal: principal.ok_or("principal is required")?,
        approval: approval.ok_or("approval digest is required")?,
    })
}

fn elapsed(start: Instant) -> TimestampNs {
    TimestampNs(i128::try_from(start.elapsed().as_nanos()).unwrap_or(i128::MAX))
}

fn execute(options: &Options) -> Result<Report, &'static str> {
    let start = Instant::now();
    let resource = format!(
        "unifi-discovery:{}:{}/{}",
        options.approval, options.iface, options.prefix
    );
    let config = Config::new(
        options.iface,
        options.prefix,
        SocketAddrV4::new(Ipv4Addr::BROADCAST, 10001),
        &resource,
        Duration::from_secs(3),
        64,
    )
    .map_err(|_| "invalid network scope")?;
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 600_000;
    budget.bytes = 600_000;
    let root = RootAuthoritySpec {
        trace_id: "trace:unifi-discovery-operator".into(),
        operation_id: OperationId::parse("operation:unifi-discovery-operator")
            .map_err(|_| "invalid operation")?,
        principal: options.principal.clone(),
        capabilities: vec![RuntimeGrant::AdapterNet.as_str().into()],
        deadline: Some(TimestampNs(10_000_000_000)),
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
        .with_scope(RuntimeGrant::AdapterNet, BTreeSet::from([resource]));
    authority
        .narrow_grants(grants)
        .map_err(|_| "authority scope refused")?;
    let runtime = RuntimeBuilder::current_thread()
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
                let output = discovery::discover(owner, runtime_cx, elapsed(start), &config).await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("discovery failed".into())
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
    run.output.map_err(|_| "discovery failed")
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

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!(
            "{USAGE}\nSends one bounded local broadcast; setup and authentication are not implemented. The approval digest must identify the operator's existing authorization."
        );
        return ExitCode::SUCCESS;
    }
    let report = options(&args).and_then(|options| execute(&options));
    match report {
        Ok(report) => {
            let cameras = report.cameras.iter().map(|c| format!("{{\"address\":{},\"platform\":{},\"firmware\":{},\"source_advertised\":{},\"identity\":\"unverified\",\"setup\":\"unavailable\"}}", json(&c.source().ip().to_string()), json(c.platform()), c.firmware().map_or_else(|| "null".into(), json), c.source_advertised())).collect::<Vec<_>>().join(",");
            println!(
                "{{\"schema\":\"fss.unifi_discovery_lab.v1\",\"datagrams\":{},\"malformed\":{},\"out_of_scope\":{},\"stop\":{},\"absence_proven\":false,\"cameras\":[{}]}}",
                report.datagrams,
                report.malformed,
                report.out_of_scope,
                json(&format!("{:?}", report.stop)),
                cameras
            );
            ExitCode::SUCCESS
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
}
