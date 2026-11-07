#![forbid(unsafe_code)]
//! Read-only, locally scoped asynchronous system bus qualification probe.
#[cfg(not(target_os = "linux"))]
compile_error!("this probe is Linux-only");
use asupersync::{net::unix::UnixStream, runtime::RuntimeBuilder, time::timeout_at};
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_reference::unifi_direct::{
    bluez_bus::{self, Admission, Stage},
    metered::{MeteredClock, MeteredIo},
};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};
use std::{error::Error, os::unix::fs::MetadataExt, time::Duration};

struct LocalSystemBus;
impl Admission for LocalSystemBus {
    fn permits(&self, resource: &str, _: Stage) -> bool {
        resource == "local:system-bus"
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let uid = std::fs::metadata("/proc/self")?.uid();
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 65536;
    let (mut owner, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:bluez-observe".into(),
            operation_id: OperationId::parse("operation:bluez-observe")?,
            principal: "principal:local-probe".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::ObserveStatus.as_str().into(),
            ],
            deadline: Some(TimestampNs(30_000_000_000)),
            priority: 10,
            budgets: budget,
            privacy_scope: "privacy:local".into(),
            retention_scope: "retention:none".into(),
            anchor_universe: ContentDigest::sha256(b"local BlueZ bus qualification"),
            generation: 1,
        },
        RegionId::new("region:bluez-observe")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut owner,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:bluez-observe")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: Result<_, Box<dyn Error>> = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                    let resource = "local:system-bus";
                    task.checkpoint_for(
                        RuntimeGrant::AdapterNet,
                        resource,
                        clock.now()?,
                        &BudgetVector::ZERO,
                    )?;
                    task.checkpoint_for(
                        RuntimeGrant::ObserveStatus,
                        resource,
                        clock.now()?,
                        &BudgetVector::ZERO,
                    )?;
                    let stream = timeout_at(
                        cx.now() + Duration::from_secs(4),
                        UnixStream::connect("/run/dbus/system_bus_socket"),
                    )
                    .await
                    .map_err(|_| "socket connect timeout")??;
                    let io = MeteredIo::with_clock(stream, clock, resource, 4096)?;
                    let obs = bluez_bus::observe_inventory(
                        cx,
                        task,
                        clock,
                        io,
                        &LocalSystemBus,
                        uid,
                        Duration::from_secs(4),
                    )
                    .await?;
                    Ok(obs)
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("bus observation failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(29_000_000_000),
                }
            },
        )
        .await?;
        result.receipt?;
        let observed = result.output?;
        println!(
            "task_owned_async_inventory=passed bluez_owner={} signals_skipped={} objects={} adapters={} discovery_calls=none camera_calls=none",
            observed.bus.bluez_name_owned, observed.bus.signals_skipped, observed.objects, observed.adapter_paths.len()
        );
        Ok(())
    })
}
