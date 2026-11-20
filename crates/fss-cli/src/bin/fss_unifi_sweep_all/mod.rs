#![forbid(unsafe_code)]
//! Explicit one-shot, all-page discovery; no camera setup or scheduling.

use super::*;
use fss_reference::unifi_direct::{
    discovery::sweep::{Batch, Runner, Step},
    metered::MeteredClock,
};

enum Observation {
    Complete(Batch),
    Partial {
        completed: Vec<Report>,
        incomplete: Option<Report>,
        reason: &'static str,
    },
}

fn execute(options: &Options) -> Result<Observation, &'static str> {
    let start = Instant::now();
    let resource = format!(
        "unifi-discovery:{}:scope:{}/{}",
        options.approval, options.iface, options.prefix
    );
    let mut budget = BudgetVector::ZERO;
    // At most 68 windows, each with 64 bounded receive reservations.
    budget.network_bytes = 50_000_000;
    budget.bytes = budget.network_bytes;
    let root = RootAuthoritySpec {
        trace_id: "trace:unifi-sweep-all".into(),
        operation_id: OperationId::parse("operation:unifi-sweep-all")
            .map_err(|_| "invalid operation")?,
        principal: options.principal.clone(),
        capabilities: vec![RuntimeGrant::AdapterNet.as_str().into()],
        deadline: Some(TimestampNs(240_000_000_000)),
        priority: 10,
        budgets: budget,
        privacy_scope: "privacy:owner-local-network".into(),
        retention_scope: "retention:operator-output".into(),
        anchor_universe: options.approval,
        generation: 1,
    };
    let (mut authority, mut tree) = AuthorityCx::root(
        root,
        RegionId::new("region:unifi-sweep-all").map_err(|_| "invalid region")?,
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
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("runtime context unavailable")?;
        let task = TaskSpec {
            task_id: TaskId::new("task:unifi-sweep-all").map_err(|_| "invalid task")?,
            started_at: elapsed(start),
        };
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            task,
            &cx,
            async |owner, runtime_cx| {
                let output = async {
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
                    let interfaces = auto_interfaces(
                        options.iface,
                        options.prefix,
                        options.only_interface.as_deref(),
                    )?;
                    let (page_count, _) =
                        auto_sweep_page(&interfaces, 0, options.limited_broadcast)?;
                    let mut plans = Vec::new();
                    plans
                        .try_reserve_exact(page_count)
                        .map_err(|_| "sweep allocation refused")?;
                    for page in 0..page_count {
                        let (_, windows) =
                            auto_sweep_page(&interfaces, page as u16, options.limited_broadcast)?;
                        let mut configs = Vec::new();
                        configs
                            .try_reserve_exact(windows.len())
                            .map_err(|_| "sweep allocation refused")?;
                        for (interface, targets) in windows {
                            configs.push(
                                Config::new_many(
                                    interface.address,
                                    interface.prefix,
                                    &targets,
                                    &resource,
                                    Duration::from_secs(3),
                                    64,
                                )
                                .map_err(|_| "invalid network scope")?,
                            );
                        }
                        plans.push(configs);
                    }
                    let scope = ContentDigest::sha256(
                        format!(
                            "fss.unifi-discovery.sweep.v1|{}|{}|{}|{}",
                            options.approval,
                            interfaces[0].address,
                            interfaces[0].prefix,
                            options
                                .only_interface
                                .as_deref()
                                .ok_or("interface missing")?
                        )
                        .as_bytes(),
                    );
                    let clock = MeteredClock::new(owner, runtime_cx, elapsed(start))
                        .map_err(|_| "clock refused")?;
                    let runner = Runner::new(
                        runtime_cx,
                        owner,
                        clock,
                        scope,
                        plans,
                        Duration::from_secs(1),
                    )
                    .map_err(|_| "sweep setup refused")?;
                    loop {
                        match runner.next(None).await {
                            Ok(Step::Progress { .. }) => (),
                            // No fleet is supplied, so the runner cannot refresh one.
                            Ok(Step::Finished { batch, .. }) => {
                                break Ok(Observation::Complete(batch));
                            }
                            Ok(Step::Incomplete { report, .. }) => {
                                let retired = runner.retire();
                                break Ok(Observation::Partial {
                                    completed: retired.completed,
                                    incomplete: Some(report),
                                    reason: "incomplete_window",
                                });
                            }
                            Err(_) => {
                                let retired = runner.retire();
                                break Ok(Observation::Partial {
                                    completed: retired.completed,
                                    incomplete: None,
                                    reason: "sweep_interrupted",
                                });
                            }
                        }
                    }
                }
                .await;
                let outcome = if matches!(&output, Ok(Observation::Complete(_))) {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("sweep incomplete".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: elapsed(start),
                }
            },
        )
        .await
        .map_err(|_| "task admission failed")?;
        run.receipt.map_err(|_| "task receipt refused")?;
        run.output
    })
}

pub(super) fn run(options: &Options) -> ExitCode {
    match execute(options) {
        Ok(Observation::Complete(batch)) => {
            let page_json = batch
                .page_reports()
                .iter()
                .enumerate()
                .map(|(index, report)| {
                    format!(
                        "{{\"index\":{index},\"report\":{}}}",
                        report_json(report, options.include_mac_claims)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            let windows = batch
                .windows()
                .iter()
                .map(|report| report_json(report, options.include_mac_claims))
                .collect::<Vec<_>>()
                .join(",");
            let combined = batch
                .pages()
                .ok()
                .and_then(|pages| Report::combine_sweep_pages(&pages).ok());
            let status = if combined.is_some() {
                "complete"
            } else {
                "combination_refused"
            };
            let combined_json = combined.as_ref().map_or_else(
                || "null".to_owned(),
                |report| report_json(report, options.include_mac_claims),
            );
            println!(
                "{{\"schema\":\"fss.unifi_discovery_sweep_lab.v1\",\"status\":{},\"absence_proven\":false,\"identity\":\"unverified\",\"setup\":\"unavailable\",\"combined\":{combined_json},\"pages\":[{page_json}],\"windows\":[{windows}]}}",
                json(status)
            );
            if combined.is_some() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Ok(Observation::Partial {
            completed,
            incomplete,
            reason,
        }) => {
            let windows = completed
                .iter()
                .map(|report| report_json(report, options.include_mac_claims))
                .collect::<Vec<_>>()
                .join(",");
            let partial = incomplete.as_ref().map_or_else(
                || "null".to_owned(),
                |report| report_json(report, options.include_mac_claims),
            );
            println!(
                "{{\"schema\":\"fss.unifi_discovery_sweep_lab.v1\",\"status\":\"incomplete\",\"reason\":{},\"absence_proven\":false,\"combined\":null,\"windows\":[{windows}],\"incomplete_window\":{partial}}}",
                json(reason)
            );
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("UniFi discovery: {error}");
            ExitCode::FAILURE
        }
    }
}
