#![forbid(unsafe_code)]
//! Bounded, task-owned BlueZ discovery diagnostic. Reports counts without addresses.
#[cfg(not(target_os = "linux"))]
compile_error!("this probe is Linux-only");
use asupersync::{net::unix::UnixStream, runtime::RuntimeBuilder, time::timeout_at};
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_reference::unifi_direct::{
    bluez_bus::{self, Admission, Stage},
    bluez_monitor::{Monitor, Stop},
    bluez_registry::Assessment,
    metered::{MeteredClock, MeteredIo},
};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};
use std::{
    error::Error,
    os::unix::fs::MetadataExt,
    time::{Duration, Instant},
};

struct LocalSystemBus;
impl Admission for LocalSystemBus {
    fn permits(&self, resource: &str, _: Stage) -> bool {
        matches!(resource, "local:system-bus" | "/org/bluez/hci1")
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let uid = std::fs::metadata("/proc/self")?.uid();
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 512 * 1024;
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
                    let watch = bluez_bus::open_watch(
                        cx,
                        task,
                        clock,
                        io,
                        &LocalSystemBus,
                        uid,
                        Duration::from_secs(4),
                    )
                    .await?;
                    let mut monitor = Monitor::start(watch, "/org/bluez/hci1", &["0c430d0c-00ef-4367-bc6f-ca7c51e6b61f"], Duration::from_secs(4), Duration::from_millis(300), Duration::from_secs(4)).await?;
                    let deadline = Instant::now() + Duration::from_secs(3);
                    let mut changes = 0usize;
                    while changes < 32 {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() { break; }
                        match monitor.next_change().await {
                            Ok((next, changed)) => { monitor = next; changes += usize::from(changed); }
                            Err(retired) => {
                                if retired.stop != Stop::Acknowledged { return Err("monitor stopped with uncertain cleanup".into()); }
                                return Ok((changes, retired.registry.len(), 0, true));
                            }
                        }
                    }
                    let devices = monitor.registry().len();
                    let candidates = (0..devices).filter(|&i| monitor.registry().assess(i) == Some(Assessment::CandidateClaim)).count();
                    let retired = monitor.stop().await;
                    if retired.stop != Stop::Acknowledged || !retired.registry.is_gapped() { return Err("monitor stop not acknowledged".into()); }
                    Ok((changes, devices, candidates, false))
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
        let (changes, devices, candidates, projection_gap) = result.output?;
        println!("task_owned_scan_start_and_stop=passed changes={changes} device_claims={devices} candidate_claims={candidates} projection_gap={projection_gap} camera_calls=none");
        Ok(())
    })
}
