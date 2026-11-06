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
    execution::{ExecutionError, TaskCompletion, TaskSpec, run_owned_async},
};
use std::{
    error::Error,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    time::Duration,
};

type TestResult = Result<(), Box<dyn Error>>;

fn root() -> Result<(AuthorityCx, fss_core::RegionTree), Box<dyn Error>> {
    root_with_deadline(TimestampNs(60_000_000_000))
}

fn root_with_deadline(
    deadline: TimestampNs,
) -> Result<(AuthorityCx, fss_core::RegionTree), Box<dyn Error>> {
    root_with_budget(deadline, 1_000_000)
}

fn root_with_budget(
    deadline: TimestampNs,
    network_bytes: u64,
) -> Result<(AuthorityCx, fss_core::RegionTree), Box<dyn Error>> {
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = network_bytes;
    budget.bytes = 1_000_000;
    let spec = RootAuthoritySpec {
        trace_id: "trace:unifi-discovery".into(),
        operation_id: OperationId::parse("operation:unifi-discovery")?,
        principal: "principal:owner".into(),
        capabilities: vec![RuntimeGrant::AdapterNet.as_str().into()],
        deadline: Some(deadline),
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

#[test]
fn multi_target_budget_exhaustion_reports_partial_send_without_more_queries() -> TestResult {
    let first = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 1), 0))?;
    let port = first.local_addr()?.port();
    let second = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), port))?;
    first.set_read_timeout(Some(Duration::from_secs(2)))?;
    second.set_read_timeout(Some(Duration::from_millis(250)))?;
    let targets = [
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port),
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), port),
    ];
    let config = Config::new_many(
        Ipv4Addr::new(127, 0, 0, 3),
        8,
        &targets,
        "fixture:discovery",
        Duration::from_secs(2),
        8,
    )?;
    let (mut authority, mut tree) = root_with_budget(TimestampNs(60_000_000_000), 4)?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    let run = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:discovery-budget")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |owner, runtime_cx| {
                let start = runtime_cx.now().as_nanos();
                let output = discovery::discover(owner, runtime_cx, TimestampNs(3), &config).await;
                let elapsed = runtime_cx
                    .now()
                    .as_nanos()
                    .checked_sub(start)
                    .expect("runtime clock regressed");
                TaskCompletion {
                    output,
                    outcome: TaskOutcome::Success,
                    completed_at: TimestampNs(3 + i128::from(elapsed)),
                }
            },
        )
        .await?;
        Ok::<_, Box<dyn Error>>(run)
    })?;
    assert!(matches!(
        run.output,
        Err(discovery::Error::IndeterminateSend)
    ));
    run.receipt?;
    let mut query = [0_u8; 32];
    let (count, _) = first.recv_from(&mut query)?;
    assert_eq!(
        &query[..count],
        fss_packet::unifi_discovery::V1_QUERY.as_slice()
    );
    let error = second
        .recv_from(&mut query)
        .expect_err("second query was emitted");
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    Ok(())
}

fn packet_with(mac: Option<[u8; 6]>, firmware: &[u8], advertised: bool) -> Vec<u8> {
    let address = [0x10, 2, 3, 4, 5, 6, 127, 0, 0, 1];
    let mut fields: Vec<(u8, &[u8])> = Vec::new();
    if let Some(ref mac) = mac {
        fields.push((1, mac));
    }
    if advertised {
        fields.push((2, &address));
    }
    fields.extend([
        (3, firmware),
        (12, b"UVC G4 Instant"),
        (6, b"PRIVATE_USERNAME"),
    ]);
    let mut body = Vec::new();
    for (kind, value) in fields {
        body.push(kind);
        body.extend_from_slice(&(value.len() as u16).to_be_bytes());
        body.extend_from_slice(value);
    }
    let mut bytes = vec![1, 0];
    bytes.extend_from_slice(&(body.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&body);
    bytes
}

fn packet() -> Vec<u8> {
    packet_with(Some([0x10, 2, 3, 4, 5, 6]), b"UVC.v4.example", true)
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
                let start = runtime_cx.now().as_nanos();
                let output = discovery::discover(owner, runtime_cx, TimestampNs(3), config).await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("discovery fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(
                        3 + i128::from(
                            runtime_cx
                                .now()
                                .as_nanos()
                                .checked_sub(start)
                                .expect("runtime clock regressed"),
                        ),
                    ),
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
fn multi_target_discovery_collects_and_cross_checks_both_peers() -> TestResult {
    let first = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 1), 0))?;
    let port = first.local_addr()?.port();
    let second = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), port))?;
    first.set_read_timeout(Some(Duration::from_secs(5)))?;
    second.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut second_packet = packet();
    let address = [0x10, 2, 3, 4, 5, 6, 127, 0, 0, 1];
    let offset = second_packet
        .windows(address.len())
        .position(|v| v == address.as_slice())
        .ok_or("fixture address missing")?;
    second_packet[offset + address.len() - 1] = 2;
    let workers: Vec<_> = [(first, packet()), (second, second_packet)]
        .into_iter()
        .map(|(socket, reply)| {
            std::thread::spawn(move || -> std::io::Result<()> {
                let mut query = [0_u8; 32];
                let (count, peer) = socket.recv_from(&mut query)?;
                if &query[..count] != fss_packet::unifi_discovery::V1_QUERY.as_slice() {
                    return Err(std::io::Error::other("unexpected discovery query"));
                }
                socket.send_to(&reply, peer)?;
                Ok(())
            })
        })
        .collect();
    let targets = [
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port),
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), port),
    ];
    let config = Config::new_many(
        Ipv4Addr::new(127, 0, 0, 3),
        8,
        &targets,
        "fixture:discovery",
        Duration::from_millis(300),
        8,
    )?;
    let report = execute(&config)?;
    for worker in workers {
        worker.join().map_err(|_| "fixture thread panicked")??;
    }
    assert_eq!(report.stop, Stop::WindowElapsed);
    assert_eq!(report.datagrams, 2);
    assert_eq!(report.cameras.len(), 2);
    assert!(
        report
            .cameras
            .iter()
            .all(|candidate| candidate.source_advertised())
    );
    assert!(
        report
            .assess_claims(0)
            .ok_or("first claim missing")?
            .same_mac_at_multiple_addresses
    );
    assert!(
        report
            .assess_claims(1)
            .ok_or("second claim missing")?
            .same_mac_at_multiple_addresses
    );
    Ok(())
}

#[test]
fn discovery_advances_the_owned_task_clock_during_the_window() -> TestResult {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    server.set_read_timeout(Some(Duration::from_secs(5)))?;
    let destination = match server.local_addr()? {
        std::net::SocketAddr::V4(v) => v,
        _ => return Err("not IPv4".into()),
    };
    let worker = std::thread::spawn(move || -> std::io::Result<()> {
        let mut query = [0_u8; 32];
        let (_, peer) = server.recv_from(&mut query)?;
        std::thread::sleep(Duration::from_millis(30));
        server.send_to(&packet(), peer)?;
        Ok(())
    });
    let config = Config::new(
        Ipv4Addr::LOCALHOST,
        8,
        destination,
        "fixture:discovery",
        Duration::from_millis(120),
        8,
    )?;
    let (mut authority, mut tree) = root()?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    let run = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:discovery-clock")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |owner, runtime_cx| {
                let start = runtime_cx.now().as_nanos();
                let report = discovery::discover(owner, runtime_cx, TimestampNs(3), &config).await;
                let stale = owner.checkpoint_for(
                    RuntimeGrant::AdapterNet,
                    "fixture:discovery",
                    TimestampNs(3),
                    &BudgetVector::ZERO,
                );
                let elapsed = runtime_cx
                    .now()
                    .as_nanos()
                    .checked_sub(start)
                    .expect("runtime clock regressed");
                TaskCompletion {
                    output: (report, stale),
                    outcome: TaskOutcome::Success,
                    completed_at: TimestampNs(3 + i128::from(elapsed)),
                }
            },
        )
        .await?;
        Ok::<_, Box<dyn Error>>(run)
    })?;
    worker.join().map_err(|_| "fixture thread panicked")??;
    assert_eq!(run.output.0?.cameras.len(), 1);
    assert!(matches!(
        run.output.1,
        Err(ExecutionError::ClockRegression { .. })
    ));
    run.receipt?;
    Ok(())
}

#[test]
fn task_deadline_stops_the_scan_before_a_late_reply() -> TestResult {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    server.set_read_timeout(Some(Duration::from_secs(5)))?;
    let destination = match server.local_addr()? {
        std::net::SocketAddr::V4(v) => v,
        _ => return Err("not IPv4".into()),
    };
    let worker = std::thread::spawn(move || -> std::io::Result<()> {
        let mut query = [0_u8; 32];
        let (_, peer) = server.recv_from(&mut query)?;
        server.send_to(&packet(), peer)?;
        std::thread::sleep(Duration::from_millis(400));
        server.send_to(
            &packet_with(Some([0x12, 2, 3, 4, 5, 6]), b"UVC.late", true),
            peer,
        )?;
        Ok(())
    });
    let config = Config::new(
        Ipv4Addr::LOCALHOST,
        8,
        destination,
        "fixture:discovery",
        Duration::from_secs(2),
        8,
    )?;
    let (mut authority, mut tree) = root_with_deadline(TimestampNs(200_000_003))?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    let run = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:discovery-deadline")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |owner, runtime_cx| {
                let start = runtime_cx.now().as_nanos();
                let output = discovery::discover(owner, runtime_cx, TimestampNs(3), &config).await;
                let elapsed = runtime_cx
                    .now()
                    .as_nanos()
                    .checked_sub(start)
                    .expect("runtime clock regressed");
                TaskCompletion {
                    output,
                    outcome: TaskOutcome::Failed("deadline stopped discovery".into()),
                    completed_at: TimestampNs(3 + i128::from(elapsed)),
                }
            },
        )
        .await?;
        Ok::<_, Box<dyn Error>>(run)
    })?;
    worker.join().map_err(|_| "fixture thread panicked")??;
    let report = run.output?;
    assert_eq!(report.stop, Stop::AuthorityDeadline);
    assert_eq!(report.cameras.len(), 1);
    assert_eq!(report.datagrams, 1);
    run.receipt?;
    Ok(())
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
    assert_eq!(report.assess_claims(0), Some(Default::default()));
    assert_eq!(report.assess_claims(1), None);
    assert!(!format!("{report:?}").contains("PRIVATE_USERNAME"));
    Ok(())
}

#[test]
fn conflicting_udp_claims_remain_separate_and_are_flagged() -> TestResult {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    server.set_read_timeout(Some(Duration::from_secs(5)))?;
    let destination = match server.local_addr()? {
        std::net::SocketAddr::V4(v) => v,
        _ => return Err("not IPv4".into()),
    };
    let worker = std::thread::spawn(move || -> std::io::Result<()> {
        let mut query = [0_u8; 32];
        let (_, peer) = server.recv_from(&mut query)?;
        for bytes in [
            packet(),
            packet_with(Some([0x12, 2, 3, 4, 5, 6]), b"UVC.v4.example", true),
            packet_with(Some([0x10, 2, 3, 4, 5, 6]), b"UVC.v5.example", true),
            packet_with(None, b"UVC.v4.example", false),
        ] {
            server.send_to(&bytes, peer)?;
        }
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
    assert_eq!(report.cameras.len(), 4);
    let first = report.assess_claims(0).ok_or("missing first claim")?;
    assert!(first.conflicting_macs_at_address && first.conflicting_metadata);
    assert!(first.incomplete_claim_at_address);
    assert!(!first.missing_or_invalid_mac && !first.same_mac_at_multiple_addresses);
    let missing = report.assess_claims(3).ok_or("missing fourth claim")?;
    assert!(missing.missing_or_invalid_mac && missing.source_not_advertised);
    Ok(())
}

#[test]
fn incomplete_same_address_udp_claim_marks_the_other_candidate() -> TestResult {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    server.set_read_timeout(Some(Duration::from_secs(5)))?;
    let destination = match server.local_addr()? {
        std::net::SocketAddr::V4(v) => v,
        _ => return Err("not IPv4".into()),
    };
    let worker = std::thread::spawn(move || -> std::io::Result<()> {
        let mut query = [0_u8; 32];
        let (_, peer) = server.recv_from(&mut query)?;
        server.send_to(&packet(), peer)?;
        server.send_to(&packet_with(None, b"UVC.v4.example", true), peer)?;
        Ok(())
    });
    let config = Config::new(
        Ipv4Addr::LOCALHOST,
        8,
        destination,
        "fixture:discovery",
        Duration::from_millis(300),
        4,
    )?;
    let report = execute(&config)?;
    worker.join().map_err(|_| "fixture thread panicked")??;
    assert_eq!(report.cameras.len(), 2);
    let first = report.assess_claims(0).ok_or("missing first claim")?;
    assert!(first.incomplete_claim_at_address);
    assert!(!first.missing_or_invalid_mac && !first.conflicting_macs_at_address);
    assert_ne!(first, Default::default());
    assert!(
        report
            .assess_claims(1)
            .ok_or("missing second claim")?
            .missing_or_invalid_mac
    );
    Ok(())
}

#[test]
fn directed_broadcast_accepts_reply_from_a_host_in_the_subnet() -> TestResult {
    let server = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    server.set_read_timeout(Some(Duration::from_secs(5)))?;
    let port = server.local_addr()?.port();
    let worker = std::thread::spawn(move || -> std::io::Result<()> {
        let mut query = [0_u8; 32];
        let (_, peer) = server.recv_from(&mut query)?;
        server.send_to(&packet(), peer)?;
        Ok(())
    });
    let config = Config::new(
        Ipv4Addr::LOCALHOST,
        8,
        SocketAddrV4::new(Ipv4Addr::new(127, 255, 255, 255), port),
        "fixture:discovery",
        Duration::from_millis(300),
        8,
    )?;
    let report = execute(&config)?;
    worker.join().map_err(|_| "fixture thread panicked")??;
    assert_eq!(report.cameras.len(), 1);
    assert_eq!(report.out_of_scope, 0);
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
    let flagged = (0..report.cameras.len())
        .filter_map(|index| report.assess_claims(index))
        .filter(|claims| *claims != Default::default())
        .count();
    println!("candidates_with_claim_issues={flagged}");
    if report.cameras.is_empty() {
        return Err("no UniFi camera candidate observed".into());
    }
    Ok(())
}
