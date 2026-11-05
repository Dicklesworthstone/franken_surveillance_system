#![forbid(unsafe_code)]
//! Scoped Asupersync UDP discovery and optional owner-camera laboratory probe.

use asupersync::runtime::RuntimeBuilder;
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_reference::unifi_direct::discovery::{self, Config, Report, Stop};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};
use std::{
    error::Error,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    time::Duration,
};

type TestResult = Result<(), Box<dyn Error>>;

fn root() -> Result<(AuthorityCx, fss_core::RegionTree), Box<dyn Error>> {
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 1_000_000;
    budget.bytes = 1_000_000;
    let spec = RootAuthoritySpec {
        trace_id: "trace:unifi-discovery".into(),
        operation_id: OperationId::parse("operation:unifi-discovery")?,
        principal: "principal:owner".into(),
        capabilities: vec![RuntimeGrant::AdapterNet.as_str().into()],
        deadline: Some(TimestampNs(60_000_000_000)),
        priority: 10,
        budgets: budget,
        privacy_scope: "privacy:local".into(),
        retention_scope: "retention:approved".into(),
        anchor_universe: ContentDigest::sha256(b"unifi discovery contract"),
        generation: 1,
    };
    Ok(AuthorityCx::root(
        spec,
        RegionId::new("region:unifi-discovery")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?)
}

fn packet() -> Vec<u8> {
    let fields: &[(u8, &[u8])] = &[
        (1, &[0x10, 2, 3, 4, 5, 6]),
        (2, &[0x10, 2, 3, 4, 5, 6, 127, 0, 0, 1]),
        (3, b"UVC.v4.example"),
        (12, b"UVC G4 Instant"),
        (6, b"PRIVATE_USERNAME"),
    ];
    let mut body = Vec::new();
    for (kind, value) in fields {
        body.push(*kind);
        body.extend_from_slice(&(value.len() as u16).to_be_bytes());
        body.extend_from_slice(value);
    }
    let mut bytes = vec![1, 0];
    bytes.extend_from_slice(&(body.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&body);
    bytes
}

fn execute(config: &Config) -> Result<Report, Box<dyn Error>> {
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut authority, mut tree) = root()?;
    let run = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let spec = TaskSpec {
            task_id: TaskId::new("task:unifi-discovery")?,
            started_at: TimestampNs(2),
        };
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            spec,
            &cx,
            async |owner, runtime_cx| {
                let output = discovery::discover(owner, runtime_cx, TimestampNs(3), config).await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("discovery fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(4),
                }
            },
        )
        .await?;
        Ok::<_, Box<dyn Error>>(run)
    })?;
    let report = run.output?;
    run.receipt?;
    Ok(report)
}

#[test]
fn real_udp_discovery_deduplicates_and_never_exposes_unknown_fields() -> TestResult {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    server.set_read_timeout(Some(Duration::from_secs(5)))?;
    let destination = match server.local_addr()? {
        std::net::SocketAddr::V4(v) => v,
        _ => return Err("not IPv4".into()),
    };
    let worker = std::thread::spawn(move || -> std::io::Result<()> {
        let mut query = [0_u8; 32];
        let (len, peer) = server.recv_from(&mut query)?;
        if &query[..len] != [1, 0, 0, 0] {
            return Err(std::io::Error::other("wrong query"));
        }
        server.send_to(&packet(), peer)?;
        server.send_to(&packet(), peer)?;
        server.send_to(&[1, 0, 0, 5, 12], peer)?;
        Ok(())
    });
    let config = Config::new(
        Ipv4Addr::LOCALHOST,
        8,
        destination,
        "fixture:discovery",
        Duration::from_millis(300),
        8,
    )?;
    let report = execute(&config)?;
    worker.join().map_err(|_| "fixture thread panicked")??;
    assert_eq!(report.stop, Stop::WindowElapsed);
    assert_eq!(report.datagrams, 3);
    assert_eq!(report.malformed, 1);
    assert_eq!(report.cameras.len(), 1);
    let camera = &report.cameras[0];
    assert_eq!(camera.platform(), "UVC G4 Instant");
    assert!(camera.source_advertised());
    assert!(!format!("{report:?}").contains("PRIVATE_USERNAME"));
    Ok(())
}

#[test]
fn invalid_scope_and_unbounded_windows_are_rejected() {
    assert!(
        Config::new(
            Ipv4Addr::LOCALHOST,
            0,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10001),
            "r",
            Duration::from_secs(1),
            1
        )
        .is_err()
    );
    assert!(
        Config::new(
            Ipv4Addr::LOCALHOST,
            8,
            SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 10001),
            "r",
            Duration::from_secs(1),
            1
        )
        .is_err()
    );
    assert!(
        Config::new(
            Ipv4Addr::LOCALHOST,
            8,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10001),
            "r",
            Duration::from_secs(31),
            1
        )
        .is_err()
    );
    assert!(
        Config::new(
            Ipv4Addr::LOCALHOST,
            8,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10001),
            "r",
            Duration::from_secs(1),
            129
        )
        .is_err()
    );
}

#[test]
#[ignore = "owner-authorized live LAN probe; requires explicit interface and destination"]
fn owner_camera_live_discovery() -> TestResult {
    let bind: Ipv4Addr = std::env::var("FSS_UNIFI_TEST_BIND")?.parse()?;
    let target: Ipv4Addr = std::env::var("FSS_UNIFI_TEST_TARGET")?.parse()?;
    let prefix: u8 = std::env::var("FSS_UNIFI_TEST_PREFIX")?.parse()?;
    let config = Config::new(
        bind,
        prefix,
        SocketAddrV4::new(target, 10001),
        "fixture:owner-camera",
        Duration::from_secs(3),
        32,
    )?;
    let report = execute(&config)?;
    println!(
        "unifi_discovery_datagrams={} camera_candidates={} stop={:?}",
        report.datagrams,
        report.cameras.len(),
        report.stop
    );
    for camera in &report.cameras {
        println!(
            "platform={} source_advertised={}",
            camera.platform(),
            camera.source_advertised()
        );
    }
    if report.cameras.is_empty() {
        return Err("no UniFi camera candidate observed".into());
    }
    Ok(())
}
