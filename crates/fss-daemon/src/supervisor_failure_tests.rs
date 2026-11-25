#![forbid(unsafe_code)]
//! Accepted-control ownership across partial execution, tick failure, and shutdown.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fss_core::{ContentDigest, OperationId, PrincipalId, SensorId, TimestampNs};
use fss_ipc::{BoundedControlOp, IpcClient, IpcClientConfig, IpcResponse};

use crate::{
    DaemonControlDisposition, DaemonError, DaemonRuntimeDescriptor, DaemonShutdownReport,
    DaemonStartConfig, DaemonSupervisor, SensorDriver, SiteManifest, SyntheticCameraControl,
    SyntheticCameraDriver, control_op_approval_digest,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const START_NS: i128 = 1_700_000_000_000_000_000;
const SITE_ID: &str = "site-control-disposition";

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self, std::io::Error> {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path =
            PathBuf::from("/tmp").join(format!("fss-ctrl-{}-{sequence}", std::process::id()));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

type SupervisorFixture = (DaemonSupervisor, Vec<Arc<SyntheticCameraControl>>);

fn start_supervisor(
    dir: &TempDir,
    gop_frames: usize,
) -> Result<SupervisorFixture, Box<dyn std::error::Error>> {
    let camera = |name: &str| {
        format!(
            r#"{{
                "sensor_id":"sensor:{name}",
                "adapter":"synthetic",
                "endpoint":"synthetic://{name}",
                "priority_tier":"high_consequence_zone",
                "zone_id":"entry",
                "zones":["entry"],
                "dimensions":[32,32],
                "osd_ignore_rects":["0,0,4,4"],
                "failure_domains":["power:{name}"],
                "reconnect_min_ms":200,
                "reconnect_max_ms":2000,
                "stall_timeout_ms":5000,
                "ring_max_frames":64,
                "ring_max_bytes":32768,
                "gop_frames":{gop_frames}
            }}"#
        )
    };
    let root = crate::telemetry::escape_json(&dir.0.to_string_lossy());
    let manifest = SiteManifest::parse_json(&format!(
        r#"{{
            "schema":"fss.site_manifest.v1",
            "site_id":"{SITE_ID}",
            "deployment_root":"{root}",
            "ring_cap_bytes":67108864,
            "soft_watermark_pct":75,
            "hard_watermark_pct":95,
            "pack_target_bytes":65536,
            "scrub_budget_bytes_per_tick":1048576,
            "retain_hot_ns":86400000000000,
            "cameras":[{},{}]
        }}"#,
        camera("a"),
        camera("b"),
    ))?;
    let mut controls = Vec::new();
    let mut drivers: BTreeMap<SensorId, Box<dyn SensorDriver>> = BTreeMap::new();
    for entry in &manifest.cameras {
        let control = SyntheticCameraControl::new(entry.sensor_id.clone());
        drivers.insert(
            entry.sensor_id.clone(),
            Box::new(SyntheticCameraDriver::new(entry, Arc::clone(&control))),
        );
        controls.push(control);
    }
    let mut config = DaemonStartConfig::new(manifest);
    config.custom_drivers = drivers;
    config.started_at_ns = START_NS;
    config.enable_ipc = true;
    Ok((DaemonSupervisor::start(config)?, controls))
}

fn connect(root: &Path) -> Result<IpcClient, Box<dyn std::error::Error>> {
    let descriptor = DaemonRuntimeDescriptor::read_from_root(root)?;
    Ok(IpcClient::connect(IpcClientConfig {
        deployment_root: root.to_path_buf(),
        deployment_id: descriptor.site_id,
        contract_basis_digest: descriptor.contract_basis_digest,
        principal: PrincipalId::parse("principal:local-operator")?,
        capabilities: vec!["CAP-OBSERVE-STATUS-001".to_owned()],
        io_timeout: Duration::from_secs(3),
    })?)
}

fn enqueue(
    client: &mut IpcClient,
    op: BoundedControlOp,
    target: Option<&str>,
) -> Result<OperationId, Box<dyn std::error::Error>> {
    let request_id = client.next_request_id();
    let approval = control_op_approval_digest(SITE_ID, op, target);
    let response =
        client.submit_bounded_control(request_id, op, target.map(str::to_owned), approval)?;
    match response {
        IpcResponse::ControlAccepted { operation_id, .. } => Ok(operation_id),
        other => Err(format!("control was not accepted: {other:?}").into()),
    }
}

fn inject_stop_failure(supervisor: &mut DaemonSupervisor) -> TestResult {
    // The transport disconnect will happen before perception rejects this deliberately
    // missing registration. This injects a partial effect without production test hooks.
    let sid = SensorId::parse("sensor:a")?;
    supervisor
        .sensors
        .get_mut(&sid)
        .ok_or("missing synthetic camera")?
        .entry
        .sensor_id = SensorId::parse("sensor:missing-registration")?;
    Ok(())
}

fn assert_disposition(
    report: &DaemonShutdownReport,
    mut cancelled: Vec<OperationId>,
    mut indeterminate: Vec<OperationId>,
) {
    cancelled.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    indeterminate.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    assert_eq!(report.active_tasks, 0);
    assert_eq!(report.leaked_obligations, 0);
    assert_eq!(
        report.control_disposition.cancelled_before_execution,
        cancelled
    );
    assert_eq!(report.control_disposition.indeterminate, indeterminate);
    assert!(report.control_disposition.verify(report.receipt_digest));
}

#[test]
fn failed_control_preserves_later_commands_and_never_replays_partial_effects() -> TestResult {
    let dir = TempDir::new()?;
    let (mut supervisor, controls) = start_supervisor(&dir, 4)?;
    let mut client = connect(&dir.0)?;
    let scrub = enqueue(&mut client, BoundedControlOp::TriggerScrub, None)?;
    let failed = enqueue(&mut client, BoundedControlOp::StopCamera, Some("sensor:a"))?;
    let later = enqueue(&mut client, BoundedControlOp::StopCamera, Some("sensor:b"))?;
    drop(client);
    inject_stop_failure(&mut supervisor)?;

    let error = supervisor
        .step_tick(START_NS + 100_000_000)
        .err()
        .ok_or("partial control execution should fail")?;
    assert!(matches!(
        &error,
        DaemonError::ControlExecutionIndeterminate { operation_id, .. }
            if operation_id == &failed
    ));
    assert_eq!(error.error_id(), "ERR-EFFECT-INDETERMINATE-001");
    assert_eq!(
        controls
            .iter()
            .map(|control| control.active_session_count())
            .collect::<Vec<_>>(),
        vec![0, 1],
        "the later accepted stop must remain unexecuted"
    );
    let shared = supervisor
        .control_shared
        .as_ref()
        .ok_or("missing controls")?;
    assert_eq!(shared.queued_control_command_count()?, 1);
    assert!(supervisor.is_shutdown_requested());
    assert_eq!(supervisor.pending_scrub_operations, vec![scrub.clone()]);
    assert!(matches!(
        supervisor.step_tick(START_NS + 200_000_000),
        Err(DaemonError::ShutdownRequested)
    ));
    assert_eq!(
        supervisor
            .control_shared
            .as_ref()
            .ok_or("missing controls")?
            .queued_control_command_count()?,
        1,
        "a caller retry must not execute the failed command or consume the tail"
    );

    let report = supervisor.shutdown_graceful()?;
    assert_disposition(&report, vec![scrub, later], vec![failed]);
    assert!(
        controls
            .iter()
            .all(|control| control.active_session_count() == 0)
    );
    Ok(())
}

#[test]
fn run_loop_preserves_control_disposition_after_successful_error_cleanup() -> TestResult {
    let dir = TempDir::new()?;
    let (mut supervisor, controls) = start_supervisor(&dir, 4)?;
    let socket = supervisor
        .ipc_socket_path()
        .ok_or("missing IPC listener")?
        .to_path_buf();
    let mut client = connect(&dir.0)?;
    let failed = enqueue(&mut client, BoundedControlOp::StopCamera, Some("sensor:a"))?;
    let later = enqueue(&mut client, BoundedControlOp::StopCamera, Some("sensor:b"))?;
    drop(client);
    inject_stop_failure(&mut supervisor)?;

    let error = supervisor
        .run_until_stopped(Some(1), Duration::ZERO)
        .err()
        .ok_or("run must retain the failed control")?;
    let DaemonError::RunWithControlDisposition { run, shutdown } = &error else {
        return Err(format!("successful cleanup must retain control receipts: {error}").into());
    };
    assert!(matches!(
        run.as_ref(),
        DaemonError::ControlExecutionIndeterminate { operation_id, .. }
            if operation_id == &failed
    ));
    assert_eq!(error.error_id(), run.error_id());
    assert_eq!(
        std::error::Error::source(&error).map(ToString::to_string),
        Some(run.to_string())
    );
    assert_disposition(shutdown, vec![later], vec![failed]);
    assert!(
        controls
            .iter()
            .all(|control| control.active_session_count() == 0)
    );
    assert!(
        !socket.exists(),
        "failure cleanup must remove the IPC listener"
    );
    Ok(())
}

#[test]
fn requested_shutdown_cancels_all_queued_work_without_executing_a_tick() -> TestResult {
    let dir = TempDir::new()?;
    let (supervisor, controls) = start_supervisor(&dir, 4)?;
    let mut client = connect(&dir.0)?;
    let stop = enqueue(&mut client, BoundedControlOp::StopCamera, Some("sensor:a"))?;
    let scrub = enqueue(&mut client, BoundedControlOp::TriggerScrub, None)?;
    drop(client);
    supervisor.request_shutdown();
    let report = supervisor.run_until_stopped(None, Duration::ZERO)?;
    assert_eq!(report.ticks_executed, 0);
    assert_disposition(&report, vec![stop, scrub], Vec::new());
    assert!(
        controls
            .iter()
            .all(|control| control.active_session_count() == 0)
    );
    let json = report.to_json();
    assert!(json.contains(r#""schema":"fss.daemon_shutdown.v1""#));
    assert!(json.contains(r#""cancellation_reason":"shutdown_before_execution""#));
    assert!(json.contains(r#""durable":false"#));
    Ok(())
}

#[test]
fn source_failure_before_maintenance_retains_unstarted_scrub_on_cleanup_error() -> TestResult {
    let dir = TempDir::new()?;
    let (supervisor, controls) = start_supervisor(&dir, 1)?;
    let mut client = connect(&dir.0)?;
    let scrub = enqueue(&mut client, BoundedControlOp::TriggerScrub, None)?;
    drop(client);
    let socket = supervisor
        .ipc_socket_path()
        .ok_or("missing IPC listener")?
        .to_path_buf();
    // A real conflicting catalog publication fails the first media handoff and its
    // retry during cleanup. Deferred maintenance has not started in either path.
    let foreign_bytes = b"independent catalog publication";
    let foreign_digest = ContentDigest::sha256(foreign_bytes);
    let packs = Arc::clone(supervisor.storage().pack_store());
    packs.append_batch(&[fss_pack::PackObjectInput::new(
        fss_pack::PACK_KIND_METADATA,
        0,
        foreign_bytes,
    )])?;
    packs.publish_root(fss_pack::VirtualRootRecord::new(
        "gop:sensor_a:1:1",
        foreign_digest,
        "independent-publication",
        1,
        foreign_bytes.len() as u64,
        1,
        TimestampNs(START_NS),
        None,
    )?)?;
    drop(packs);

    let error = supervisor
        .run_until_stopped(Some(1), Duration::ZERO)
        .err()
        .ok_or("source publication and cleanup should fail")?;
    let DaemonError::RunAndShutdown { run, shutdown } = &error else {
        return Err(format!("both independent failures must remain inspectable: {error}").into());
    };
    let DaemonError::ShutdownWithControlDisposition {
        cause,
        cancelled_before_execution,
        indeterminate,
    } = shutdown.as_ref()
    else {
        return Err("cleanup failure lost accepted scrub ownership".into());
    };
    assert_eq!(cancelled_before_execution, &vec![scrub]);
    assert!(indeterminate.is_empty());
    assert_eq!(error.error_id(), run.error_id());
    assert!(run.to_string().contains("GOP publication conflicts"));
    assert!(cause.to_string().contains("GOP publication conflicts"));
    assert!(
        controls
            .iter()
            .all(|control| control.active_session_count() == 0)
    );
    assert!(!socket.exists(), "cleanup errors must still close IPC");
    Ok(())
}

#[test]
fn disposition_digest_binds_the_shutdown_and_each_cancellation_class() -> TestResult {
    let parent = ContentDigest::sha256(b"verified-shutdown");
    let a = OperationId::parse("op:ctrl:a")?;
    let b = OperationId::parse("op:ctrl:b")?;
    let c = OperationId::parse("op:ctrl:c")?;
    let receipt = DaemonControlDisposition::new(parent, vec![b.clone(), a.clone()], vec![c]);
    let reordered =
        DaemonControlDisposition::new(parent, vec![a, b], receipt.indeterminate.clone());
    assert_eq!(receipt, reordered, "receipt encoding must be canonical");
    assert_eq!(
        receipt.receipt_digest.bytes(),
        [
            0xce, 0x86, 0x4a, 0x4d, 0x73, 0x41, 0xad, 0x99, 0xa2, 0xb4, 0x27, 0xf6, 0x1f, 0x5a,
            0x7f, 0xce, 0x0f, 0xc7, 0xa1, 0xc9, 0x25, 0xb8, 0xd4, 0x3b, 0x9c, 0x91, 0x4d, 0xb8,
            0x6c, 0xa6, 0x4c, 0x09,
        ],
        "control disposition v1 known-answer vector"
    );
    assert!(receipt.verify(parent));
    let duplicate = OperationId::parse("op:ctrl:duplicate")?;
    let repeated = DaemonControlDisposition::new(
        parent,
        vec![duplicate.clone(), duplicate.clone()],
        Vec::new(),
    );
    assert!(
        !repeated.verify(parent),
        "duplicate operation IDs are not canonical"
    );
    let contradictory =
        DaemonControlDisposition::new(parent, vec![duplicate.clone()], vec![duplicate]);
    assert!(
        !contradictory.verify(parent),
        "one operation cannot be both unstarted and indeterminate"
    );
    assert!(!receipt.verify(ContentDigest::sha256(b"different-shutdown")));
    let mut altered = receipt.clone();
    let operation = altered
        .cancelled_before_execution
        .pop()
        .ok_or("missing test operation")?;
    altered.indeterminate.push(operation);
    assert!(
        !altered.verify(parent),
        "changed disposition must invalidate proof"
    );
    assert_ne!(
        receipt.receipt_digest,
        DaemonControlDisposition::new(parent, receipt.cancelled_before_execution, Vec::new(),)
            .receipt_digest
    );
    Ok(())
}
