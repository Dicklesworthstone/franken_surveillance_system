#![forbid(unsafe_code)]
//! Unix-socket UniFi direct IPC diagnostic contracts.
#![cfg(unix)]

use asupersync::runtime::RuntimeBuilder;
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_reference::unifi_direct::{
    camera_http, ipc_diagnostic, ipc_diagnostic_io, ipc_diagnostic_unix, metered::MeteredClock,
};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};
use std::{
    error::Error,
    io::{self, Read, Write},
    net::Ipv4Addr,
    os::unix::net::UnixListener,
    path::{Path, PathBuf},
    time::Duration,
};

type Test = Result<(), Box<dyn Error>>;
const RESOURCE: &str = "fixture:diagnostic-unix";
const RESPONSE: &[u8] = br#"{"from":"ubnt_streamer","functionName":"__response__","requestId":123,"statusCode":0,"to":"fss_fixture","payload":{"synthetic":true}}"#;

struct Camera(bool);
impl camera_http::Authority for Camera {
    fn permits(
        &self,
        camera: Ipv4Addr,
        generation: u64,
        operation: camera_http::Operation,
    ) -> bool {
        self.0
            && camera == Ipv4Addr::LOCALHOST
            && generation == 1
            && operation == camera_http::Operation::SettingsSerializers
    }
}
struct PathAccess {
    path: PathBuf,
    allow: std::cell::Cell<bool>,
}
impl ipc_diagnostic_unix::Admission for PathAccess {
    fn permits(&self, path: &Path, camera: Ipv4Addr, generation: u64) -> bool {
        self.allow.get() && path == self.path && camera == Ipv4Addr::LOCALHOST && generation == 1
    }
}
fn request() -> Result<ipc_diagnostic::Request, ipc_diagnostic::Error> {
    ipc_diagnostic::Request::new("fss_fixture", 123, "2026-11-16T03:14:22Z")
}

#[test]
fn unix_connection_is_admitted_and_revocation_prevents_dispatch() -> Test {
    let parent = std::env::temp_dir().join(format!("fss-ipc-unix-{}", std::process::id()));
    std::fs::create_dir(&parent)?;
    let path = parent.join("diagnostic.sock");
    let listener = UnixListener::bind(&path)?;
    listener.set_nonblocking(true)?;
    let policy = PathAccess {
        path: path.clone(),
        allow: std::cell::Cell::new(false),
    };
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 1024 * 1024;
    let (mut root, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:diagnostic-unix".into(),
            operation_id: OperationId::parse("operation:diagnostic-unix")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::ObserveStatus.as_str().into(),
            ],
            deadline: Some(TimestampNs(60_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"diagnostic unix fixture"),
            generation: 1,
        },
        RegionId::new("region:diagnostic-unix")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("runtime context")?;
        let result = run_owned_async(&mut root, &mut tree,
            TaskSpec { task_id: TaskId::new("task:diagnostic-unix")?, started_at: TimestampNs(2) }, &cx,
            async |task, cx| {
                let output: Test = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                    let camera = Camera(true);
                    let connect = |path: &Path| path.to_owned();
                    let relative = connect(Path::new("relative.sock"));
                    assert!(matches!(ipc_diagnostic_unix::connect(cx, task, clock, &camera, &policy,
                        Ipv4Addr::LOCALHOST, 1, &relative, RESOURCE, 1024, Duration::from_secs(5)).await,
                        Err(ipc_diagnostic_io::Error::Configuration)));
                    assert!(matches!(ipc_diagnostic_unix::connect(cx, task, clock, &camera, &policy,
                        Ipv4Addr::LOCALHOST, 1, &path, RESOURCE, 1024, Duration::from_secs(5)).await,
                        Err(ipc_diagnostic_io::Error::Denied)));
                    assert!(matches!(listener.accept(), Err(ref error) if error.kind() == io::ErrorKind::WouldBlock));
                    policy.allow.set(true);
                    let mut owner = ipc_diagnostic_unix::connect(cx, task, clock, &camera, &policy,
                        Ipv4Addr::LOCALHOST, 1, &path, RESOURCE, 1024, Duration::from_secs(5)).await?;
                    let (mut peer, _) = listener.accept()?;
                    peer.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let expected = request()?.bytes().to_vec();
                    let server = std::thread::spawn(move || -> io::Result<()> {
                        let mut received = vec![0; expected.len()];
                        peer.read_exact(&mut received)?;
                        if received != expected { return Err(io::Error::other("request mismatch")); }
                        let mut response = (RESPONSE.len() as u32).to_be_bytes().to_vec();
                        response.extend_from_slice(RESPONSE);
                        for part in response.chunks(3) { peer.write_all(part)?; }
                        Ok(())
                    });
                    let response = owner.observe(&request()?, Duration::from_secs(5)).await?;
                    assert_eq!(response.status(), 0);
                    assert!(owner.is_spent());
                    server.join().map_err(|_| "fixture thread panicked")??;
                    drop(owner);
                    let mut owner = ipc_diagnostic_unix::connect(cx, task, clock, &camera, &policy,
                        Ipv4Addr::LOCALHOST, 1, &path, RESOURCE, 1024, Duration::from_secs(5)).await?;
                    let (mut peer, _) = listener.accept()?;
                    peer.set_nonblocking(true)?;
                    policy.allow.set(false);
                    assert!(matches!(owner.observe(&request()?, Duration::from_secs(5)).await,
                        Err(ipc_diagnostic_io::Error::Denied)));
                    assert!(owner.is_spent());
                    let mut byte = [0];
                    assert!(matches!(peer.read(&mut byte), Err(ref error) if error.kind() == io::ErrorKind::WouldBlock));
                    Ok(())
                }.await;
                let outcome = if output.is_ok() { TaskOutcome::Success } else { TaskOutcome::Failed("diagnostic unix fixture failed".into()) };
                TaskCompletion { output, outcome, completed_at: TimestampNs(59_000_000_000) }
            }).await?;
        result.receipt?;
        result.output
    })?;
    assert!(root.finalize_report(&tree)?.is_empty());
    Ok(())
}

/// Opt-in interoperability with a caller-created synthetic firmware listener.
/// The listener must be confined away from real devices and supplies no reply.
#[test]
#[ignore = "requires an isolated synthetic firmware listener"]
fn unix_request_reaches_isolated_firmware_listener() -> Test {
    firmware_fixture(false)
}

/// Opt-in check against a copied streamer confined to a synthetic lab.
#[test]
#[ignore = "requires an isolated synthetic firmware streamer"]
fn unix_request_reaches_isolated_firmware_streamer() -> Test {
    firmware_fixture(true)
}

fn firmware_fixture(expect_response: bool) -> Test {
    let root = std::fs::canonicalize(std::env::temp_dir())?;
    let path = std::fs::canonicalize(
        std::env::var_os("FSS_SYNTHETIC_IPC_SOCKET").ok_or("fixture socket missing")?,
    )?;
    if !path.starts_with(&root)
        || path.file_name().and_then(|s| s.to_str()) != Some("ubnt_streamer")
    {
        return Err("fixture socket outside temporary root".into());
    }
    let policy = PathAccess {
        path: path.clone(),
        allow: std::cell::Cell::new(true),
    };
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 1024 * 1024;
    let (mut root, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:diagnostic-firmware-fixture".into(),
            operation_id: OperationId::parse("operation:diagnostic-firmware-fixture")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::ObserveStatus.as_str().into(),
            ],
            deadline: Some(TimestampNs(60_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"diagnostic firmware fixture"),
            generation: 1,
        },
        RegionId::new("region:diagnostic-firmware-fixture")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("runtime context")?;
        let result = run_owned_async(
            &mut root,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:diagnostic-firmware-fixture")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: Test = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                    let camera = Camera(true);
                    let mut owner = ipc_diagnostic_unix::connect(
                        cx,
                        task,
                        clock,
                        &camera,
                        &policy,
                        Ipv4Addr::LOCALHOST,
                        1,
                        &path,
                        RESOURCE,
                        1024,
                        Duration::from_secs(5),
                    )
                    .await?;
                    if expect_response {
                        let response = owner.observe(&request()?, Duration::from_secs(2)).await?;
                        let payload_object = response.payload().and_then(|value| value.object()).is_some();
                        println!("firmware_fixture_response=correlated status={} payload_object={payload_object}", response.status());
                        if response.status() != 0 || !payload_object {
                            return Err("streamer did not return a successful settings object".into());
                        }
                    } else {
                        assert!(matches!(
                            owner.observe(&request()?, Duration::from_secs(2)).await,
                            Err(ipc_diagnostic_io::Error::Deadline)
                        ));
                        println!("firmware_fixture_response=deadline owner=spent");
                    }
                    assert!(owner.is_spent());
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("diagnostic firmware fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(59_000_000_000),
                }
            },
        )
        .await?;
        result.receipt?;
        result.output
    })?;
    assert!(root.finalize_report(&tree)?.is_empty());
    Ok(())
}
