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

#[test]
fn discovery_and_routing_pump_retains_inflight_scan_across_events() -> TestResult {
    use asupersync::time::timeout;
    use fss_reference::unifi_direct::{
        controller_listener,
        discovery::{fleet::{Enrollment, Fleet, RouteError, Router, RouterEvent, State}, pump::{Event, Pump}, scan::{Outcome, Phase, Scanner}},
        listener::Admission,
        metered::MeteredClock,
    };
    use std::{future::{Future, poll_fn}, sync::{Arc, atomic::{AtomicBool, Ordering}}, task::Poll};

    struct LocalAdmission;
    impl Admission for LocalAdmission {
        fn listener(&self, _: SocketAddrV4, _: Option<SocketAddrV4>) -> bool { true }
        fn peer(&self, _: SocketAddrV4, _: SocketAddrV4) -> bool { true }
    }

    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    server.set_read_timeout(Some(Duration::from_secs(5)))?;
    let destination = match server.local_addr()? {
        std::net::SocketAddr::V4(address) => address,
        _ => return Err("not IPv4".into()),
    };
    let query_seen = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&query_seen);
    let responder = std::thread::spawn(move || -> std::io::Result<()> {
        let mut query = [0u8; 32];
        let (_, peer) = server.recv_from(&mut query)?;
        server.send_to(&packet(), peer)?;
        observed.store(true, Ordering::Release);
        Ok(())
    });
    let config = Config::new(Ipv4Addr::LOCALHOST, 8, destination, "fixture:pump-discovery",
        Duration::from_secs(2), 8)?;
    let empty = Report { cameras: Vec::new(), datagrams: 0, malformed: 0,
        out_of_scope: 0, stop: Stop::WindowElapsed };
    let fleet = Fleet::from_report(empty.clone(), &[])?;
    let other = Fleet::from_report(empty, &[])?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut authority, mut tree) = root()?;
    let run = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let run = run_owned_async(&mut authority, &mut tree,
            TaskSpec { task_id: TaskId::new("task:discovery-pump")?, started_at: TimestampNs(2) },
            &cx, async |owner, cx| {
                let start = cx.now().as_nanos();
                let output: TestResult = async {
                    let clock = MeteredClock::new(owner, cx, TimestampNs(3))?;
                    let scanner = Scanner::new(cx, owner, clock, &fleet, config.clone(), Duration::from_secs(5))?;
                    let admission = LocalAdmission;
                    let listener = controller_listener::Listener::bind(owner, cx, clock, &admission,
                        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), "fixture:pump-controller", Duration::from_secs(5)).await?;
                    let mut wrong = Router::new(&other, &listener, 2, 4096, Duration::from_secs(5))?;
                    assert!(matches!(Pump::new(&scanner, &mut wrong), Err(discovery::scan::Error::Configuration)));
                    drop(wrong);
                    let mut router = Router::new(&fleet, &listener, 2, 4096, Duration::from_secs(5))?;
                    let mut pump = Pump::new(&scanner, &mut router)?;
                    let mut next = Box::pin(pump.next());
                    timeout(cx.now(), Duration::from_secs(5), poll_fn(|context| {
                        match next.as_mut().poll(context) {
                            Poll::Pending if scanner.phase() == Phase::Probing && query_seen.load(Ordering::Acquire) => Poll::Ready(()),
                            Poll::Pending => { context.waker().wake_by_ref(); Poll::Pending },
                            Poll::Ready(_) => panic!("pump completed before the early connection"),
                        }
                    })).await.map_err(|_| "scan did not begin")?;
                    drop(next);
                    assert_eq!(scanner.phase(), Phase::Probing);
                    pump.request_scan_stop();
                    assert!(!pump.scan_drained());
                    let client = asupersync::net::TcpStream::connect(listener.local_addr()).await?;
                    match pump.next().await {
                        Event::Route(RouterEvent::Refused { reason: RouteError::UnknownPeer, .. }) => (),
                        _ => return Err("expected unrecognized local connection".into()),
                    }
                    assert_eq!(scanner.phase(), Phase::Probing);
                    match pump.next().await {
                        Event::Discovery(Ok(Outcome::Updated(snapshot))) => {
                            assert_eq!(snapshot.report().cameras.len(), 1);
                            assert_eq!(snapshot.unknown_claims(), &[0]);
                            let enrollment = Enrollment::new(
                                [0x10, 2, 3, 4, 5, 6],
                                ContentDigest::sha256(b"live-pump camera"),
                                ContentDigest::sha256(b"live-pump admission"),
                                ContentDigest::sha256(b"live-pump certificate"),
                                ContentDigest::sha256(b"live-pump credential"),
                                1,
                            )?;
                            assert_eq!(fleet.add_enrollment(enrollment)?, 0);
                            assert_eq!(fleet.state(0), Some(State::Ready { candidate: 0 }));
                            assert!(fleet.latest_snapshot().unknown_claims().is_empty());
                            assert_eq!(snapshot.unknown_claims(), &[0]);
                        }
                        _ => return Err("scan outcome lost after routing".into()),
                    }
                    assert!(pump.scan_drained());
                    pump.resume_scanning()?;
                    pump.request_scan_stop();
                    assert!(pump.scan_drained());
                    drop(pump);
                    drop(client);
                    assert_eq!(scanner.phase(), Phase::Idle);

                    // A competing caller can still misuse the shared scanner.
                    // The pump must surface Busy and stop instead of retrying.
                    let scanner = Scanner::new(cx, owner, clock, &fleet, config, Duration::from_secs(5))?;
                    let mut router = Router::new(&fleet, &listener, 2, 4096, Duration::from_secs(5))?;
                    let mut pump = Pump::new(&scanner, &mut router)?;
                    let mut competing = Box::pin(scanner.next());
                    poll_fn(|context| match competing.as_mut().poll(context) {
                        Poll::Pending if scanner.phase() == Phase::Probing => Poll::Ready(()),
                        Poll::Pending => { context.waker().wake_by_ref(); Poll::Pending },
                        Poll::Ready(_) => panic!("competing scan unexpectedly completed"),
                    }).await;
                    assert!(matches!(pump.next().await, Event::Discovery(Err(discovery::scan::Error::Busy))));
                    assert!(pump.scan_drained());
                    assert!(matches!(pump.resume_scanning(), Err(discovery::scan::Error::Busy)));
                    drop(competing);
                    assert_eq!(scanner.phase(), Phase::Interrupted);
                    assert!(matches!(pump.resume_scanning(), Err(discovery::scan::Error::Interrupted)));
                    scanner.acknowledge_interruption()?;
                    pump.resume_scanning()?;
                    pump.request_scan_stop();
                    assert!(pump.scan_drained());
                    Ok(())
                }.await;
                let outcome = if output.is_ok() { TaskOutcome::Success } else { TaskOutcome::Failed("discovery pump fixture failed".into()) };
                TaskCompletion { output, outcome, completed_at: TimestampNs(3 + i128::from(cx.now().as_nanos() - start)) }
            }).await?;
        Ok::<_, Box<dyn Error>>(run)
    })?;
    responder.join().map_err(|_| "discovery responder panicked")??;
    run.output?;
    run.receipt?;
    Ok(())
}

#[test]
fn periodic_scanner_updates_fleet_and_preserves_cancelled_ownership() -> TestResult {
    use asupersync::time::{sleep, timeout};
    use fss_reference::unifi_direct::{
        discovery::{
            fleet::{Enrollment, Fleet, State},
            scan::{Error as ScanError, Outcome, Phase, Scanner},
        },
        metered::MeteredClock,
    };
    use std::{
        future::{Future, poll_fn},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::Poll,
    };

    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    server.set_read_timeout(Some(Duration::from_secs(8)))?;
    let destination = match server.local_addr()? {
        std::net::SocketAddr::V4(address) => address,
        _ => return Err("not IPv4".into()),
    };
    let observed = Arc::new(AtomicUsize::new(0));
    let worker_observed = Arc::clone(&observed);
    let worker = std::thread::spawn(move || -> std::io::Result<()> {
        for index in 0..3 {
            let mut query = [0_u8; 32];
            let (count, peer) = server.recv_from(&mut query)?;
            if &query[..count] != fss_packet::unifi_discovery::V1_QUERY.as_slice() {
                return Err(std::io::Error::other("unexpected discovery query"));
            }
            worker_observed.fetch_add(1, Ordering::Release);
            if index == 1 {
                server.send_to(&packet(), peer)?;
            }
        }
        Ok(())
    });
    let config = Config::new(
        Ipv4Addr::LOCALHOST,
        8,
        destination,
        "fixture:periodic-discovery",
        Duration::from_millis(100),
        8,
    )?;
    let enrollment = Enrollment::new(
        [0x10, 2, 3, 4, 5, 6],
        ContentDigest::sha256(b"periodic camera"),
        ContentDigest::sha256(b"periodic admission"),
        ContentDigest::sha256(b"periodic certificate"),
        ContentDigest::sha256(b"periodic credential"),
        1,
    )?;
    let initial = Report {
        cameras: Vec::new(),
        datagrams: 0,
        malformed: 0,
        out_of_scope: 0,
        stop: Stop::WindowElapsed,
    };
    let fleet = Fleet::from_report(initial.clone(), &[])?;
    let other_fleet = Fleet::from_report(initial, &[])?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut authority, mut tree) = root()?;
    let run = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:periodic-discovery")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |owner, cx| {
                let start = cx.now().as_nanos();
                let output: TestResult = async {
                    let clock = MeteredClock::new(owner, cx, TimestampNs(3))?;
                    assert!(matches!(
                        Scanner::new(cx, owner, clock, &fleet, config.clone(), Duration::ZERO),
                        Err(ScanError::Configuration)
                    ));
                    let scanner = Scanner::new(
                        cx,
                        owner,
                        clock,
                        &fleet,
                        config.clone(),
                        Duration::from_secs(1),
                    )?;
                    let first = match scanner.next().await? {
                        Outcome::Updated(snapshot) => snapshot,
                        Outcome::Incomplete(_) => return Err("first scan incomplete".into()),
                    };
                    assert_eq!(fleet.state(0), None);
                    assert!(first.report().cameras.is_empty());
                    assert_eq!(observed.load(Ordering::Acquire), 1);
                    let mut waiting = Box::pin(scanner.next());
                    poll_fn(|context| {
                        assert!(matches!(waiting.as_mut().poll(context), Poll::Pending));
                        Poll::Ready(())
                    })
                    .await;
                    assert_eq!(scanner.phase(), Phase::Waiting);
                    assert!(matches!(scanner.next().await, Err(ScanError::Busy)));
                    drop(waiting);
                    assert_eq!(scanner.phase(), Phase::Idle);
                    assert_eq!(observed.load(Ordering::Acquire), 1);
                    let parked = scanner.park();
                    let parked = match parked.resume(&other_fleet) {
                        Err((ScanError::WrongFleet, parked)) => parked,
                        _ => return Err("scanner accepted a different fleet".into()),
                    };
                    let scanner = parked.resume(&fleet).map_err(|_| "scanner resume refused")?;
                    let mut resumed_wait = Box::pin(scanner.next());
                    poll_fn(|context| {
                        assert!(matches!(resumed_wait.as_mut().poll(context), Poll::Pending));
                        Poll::Ready(())
                    }).await;
                    assert_eq!(scanner.phase(), Phase::Waiting);
                    assert_eq!(observed.load(Ordering::Acquire), 1);
                    drop(resumed_wait);
                    let second = match scanner.next().await? {
                        Outcome::Updated(snapshot) => snapshot,
                        Outcome::Incomplete(_) => return Err("second scan incomplete".into()),
                    };
                    assert_eq!(fleet.state(0), None);
                    assert_eq!(second.report().cameras[0].mac(), Some(enrollment.mac()));
                    assert_eq!(second.unknown_claims(), &[0]);
                    let parked = scanner.park();
                    let index = fleet.add_enrollment(enrollment)?;
                    assert_eq!(index, 0);
                    assert_eq!(fleet.state(0), Some(State::Ready { candidate: 0 }));
                    assert!(fleet.latest_snapshot().unknown_claims().is_empty());
                    assert_eq!(second.unknown_claims(), &[0]);
                    let scanner = parked.resume(&fleet).map_err(|_| "enrolled scanner resume refused")?;
                    assert!(first.report().cameras.is_empty());
                    sleep(cx.now(), Duration::from_millis(1100)).await;
                    let mut pending = Box::pin(scanner.next());
                    timeout(
                        cx.now(),
                        Duration::from_secs(3),
                        poll_fn(|context| match pending.as_mut().poll(context) {
                            Poll::Pending
                                if scanner.phase() == Phase::Probing
                                    && observed.load(Ordering::Acquire) == 3 =>
                            {
                                Poll::Ready(())
                            }
                            Poll::Pending => {
                                context.waker().wake_by_ref();
                                Poll::Pending
                            }
                            Poll::Ready(_) => panic!("third scan unexpectedly completed"),
                        }),
                    )
                    .await
                    .map_err(|_| "third query not observed")?;
                    drop(pending);
                    assert_eq!(scanner.phase(), Phase::Interrupted);
                    let scanner = scanner.park().resume(&fleet).map_err(|_| "interrupted scanner resume refused")?;
                    assert_eq!(scanner.phase(), Phase::Interrupted);
                    assert!(matches!(scanner.next().await, Err(ScanError::Interrupted)));
                    scanner.acknowledge_interruption()?;
                    assert_eq!(scanner.phase(), Phase::Idle);
                    let mut rearmed = Box::pin(scanner.next());
                    poll_fn(|context| {
                        assert!(matches!(rearmed.as_mut().poll(context), Poll::Pending));
                        Poll::Ready(())
                    })
                    .await;
                    assert_eq!(scanner.phase(), Phase::Waiting);
                    drop(rearmed);
                    assert_eq!(scanner.phase(), Phase::Idle);
                    assert_eq!(observed.load(Ordering::Acquire), 3);
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("periodic discovery fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(
                        3 + i128::from(
                            cx.now()
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
    worker.join().map_err(|_| "fixture thread panicked")??;
    run.output?;
    run.receipt?;
    Ok(())
}

#[test]
fn periodic_scanner_keeps_partial_report_without_replacing_fleet() -> TestResult {
    use fss_reference::unifi_direct::{
        discovery::{
            fleet::{Enrollment, Fleet, State},
            scan::{Outcome, Scanner},
        },
        metered::MeteredClock,
    };
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    server.set_read_timeout(Some(Duration::from_secs(5)))?;
    let destination = match server.local_addr()? {
        std::net::SocketAddr::V4(address) => address,
        _ => return Err("not IPv4".into()),
    };
    let worker = std::thread::spawn(move || -> std::io::Result<()> {
        let mut query = [0_u8; 32];
        let (_, peer) = server.recv_from(&mut query)?;
        server.send_to(&packet(), peer)?;
        Ok(())
    });
    let config = Config::new(
        Ipv4Addr::LOCALHOST,
        8,
        destination,
        "fixture:partial-discovery",
        Duration::from_secs(1),
        1,
    )?;
    let enrollment = Enrollment::new(
        [0x10, 2, 3, 4, 5, 6],
        ContentDigest::sha256(b"partial camera"),
        ContentDigest::sha256(b"partial admission"),
        ContentDigest::sha256(b"partial certificate"),
        ContentDigest::sha256(b"partial credential"),
        1,
    )?;
    let initial = Report {
        cameras: Vec::new(),
        datagrams: 0,
        malformed: 0,
        out_of_scope: 0,
        stop: Stop::WindowElapsed,
    };
    let fleet = Fleet::from_report(initial, &[enrollment])?;
    let before = fleet.latest_snapshot();
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut authority, mut tree) = root()?;
    let run = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:partial-discovery")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |owner, cx| {
                let start = cx.now().as_nanos();
                let output: TestResult = async {
                    let clock = MeteredClock::new(owner, cx, TimestampNs(3))?;
                    let scanner = Scanner::new(
                        cx,
                        owner,
                        clock,
                        &fleet,
                        config.clone(),
                        Duration::from_secs(1),
                    )?;
                    let partial = match scanner.next().await? {
                        Outcome::Incomplete(report) => report,
                        Outcome::Updated(_) => return Err("partial window was installed".into()),
                    };
                    assert_eq!(partial.stop, Stop::PacketLimit);
                    assert_eq!(partial.datagrams, 1);
                    assert_eq!(partial.cameras[0].mac(), Some(enrollment.mac()));
                    assert!(std::rc::Rc::ptr_eq(&before, &fleet.latest_snapshot()));
                    assert_eq!(fleet.state(0), Some(State::NotObserved));
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("partial discovery fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(
                        3 + i128::from(
                            cx.now()
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
    worker.join().map_err(|_| "fixture thread panicked")??;
    run.output?;
    run.receipt?;
    Ok(())
}

#[test]
fn periodic_scanner_wakes_and_drains_when_waiting_task_is_cancelled() -> TestResult {
    use asupersync::CancelKind;
    use fss_reference::unifi_direct::{
        discovery::{
            fleet::Fleet,
            scan::{Error as ScanError, Outcome, Phase, Scanner},
        },
        metered::MeteredClock,
    };
    use std::{
        future::{Future, poll_fn},
        task::Poll,
        time::Instant,
    };

    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    server.set_read_timeout(Some(Duration::from_secs(5)))?;
    let destination = match server.local_addr()? {
        std::net::SocketAddr::V4(address) => address,
        _ => return Err("not IPv4".into()),
    };
    let worker = std::thread::spawn(move || -> std::io::Result<()> {
        let mut query = [0_u8; 32];
        server.recv_from(&mut query)?;
        server.set_read_timeout(Some(Duration::from_millis(700)))?;
        match server.recv_from(&mut query) {
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
            Ok(_) => Err(std::io::Error::other("query sent after cancellation")),
        }
    });
    let config = Config::new(
        Ipv4Addr::LOCALHOST,
        8,
        destination,
        "fixture:cancelled-scanner",
        Duration::from_millis(80),
        8,
    )?;
    let initial = Report {
        cameras: Vec::new(),
        datagrams: 0,
        malformed: 0,
        out_of_scope: 0,
        stop: Stop::WindowElapsed,
    };
    let fleet = Fleet::from_report(initial, &[])?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut authority, mut tree) = root()?;
    let run = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:cancelled-scanner")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |owner, cx| {
                let start = cx.now().as_nanos();
                let output: TestResult = async {
                    let clock = MeteredClock::new(owner, cx, TimestampNs(3))?;
                    let scanner = Scanner::new(
                        cx,
                        owner,
                        clock,
                        &fleet,
                        config.clone(),
                        Duration::from_secs(10),
                    )?;
                    if !matches!(scanner.next().await?, Outcome::Updated(_)) {
                        return Err("initial scan incomplete".into());
                    }
                    let mut waiting = Box::pin(scanner.next());
                    poll_fn(|context| {
                        assert!(matches!(waiting.as_mut().poll(context), Poll::Pending));
                        Poll::Ready(())
                    })
                    .await;
                    assert_eq!(scanner.phase(), Phase::Waiting);
                    let now = clock.now()?;
                    owner.request_cancellation(now)?;
                    let cancellation_started = Instant::now();
                    let canceller = (*cx).clone();
                    let cancellation = std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(100));
                        canceller.cancel_with(CancelKind::User, None);
                    });
                    assert!(matches!(waiting.await, Err(ScanError::Authority)));
                    cancellation
                        .join()
                        .map_err(|_| "cancellation thread panicked")?;
                    assert!(cancellation_started.elapsed() < Duration::from_secs(2));
                    assert_eq!(scanner.phase(), Phase::Idle);
                    owner.begin_drain(now)?;
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Cancelled
                } else {
                    TaskOutcome::Failed("cancelled scanner fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(
                        3 + i128::from(
                            cx.now()
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
    worker.join().map_err(|_| "fixture thread panicked")??;
    run.output?;
    run.receipt?;
    Ok(())
}

#[test]
fn periodic_scanner_cancellation_during_probe_preserves_uncertainty() -> TestResult {
    use asupersync::CancelKind;
    use fss_reference::unifi_direct::{
        discovery::{
            fleet::Fleet,
            scan::{Error as ScanError, Outcome, Phase, Scanner},
        },
        metered::MeteredClock,
    };
    use std::{
        future::{Future, poll_fn},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::Poll,
        time::Instant,
    };
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    server.set_read_timeout(Some(Duration::from_secs(5)))?;
    let destination = match server.local_addr()? {
        std::net::SocketAddr::V4(address) => address,
        _ => return Err("not IPv4".into()),
    };
    let observed = Arc::new(AtomicBool::new(false));
    let worker_observed = Arc::clone(&observed);
    let worker = std::thread::spawn(move || -> std::io::Result<()> {
        let mut query = [0_u8; 32];
        server.recv_from(&mut query)?;
        worker_observed.store(true, Ordering::Release);
        server.set_read_timeout(Some(Duration::from_millis(700)))?;
        match server.recv_from(&mut query) {
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
            Ok(_) => Err(std::io::Error::other("query repeated after cancellation")),
        }
    });
    let config = Config::new(
        Ipv4Addr::LOCALHOST,
        8,
        destination,
        "fixture:cancelled-probe",
        Duration::from_secs(10),
        8,
    )?;
    let initial = Report {
        cameras: Vec::new(),
        datagrams: 0,
        malformed: 0,
        out_of_scope: 0,
        stop: Stop::WindowElapsed,
    };
    let fleet = Fleet::from_report(initial, &[])?;
    let before = fleet.latest_snapshot();
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut authority, mut tree) = root()?;
    let run = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:cancelled-probe")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |owner, cx| {
                let start = cx.now().as_nanos();
                let output: TestResult = async {
                    let clock = MeteredClock::new(owner, cx, TimestampNs(3))?;
                    let scanner = Scanner::new(
                        cx,
                        owner,
                        clock,
                        &fleet,
                        config.clone(),
                        Duration::from_secs(1),
                    )?;
                    let mut pending = Box::pin(scanner.next());
                    poll_fn(|context| match pending.as_mut().poll(context) {
                        Poll::Pending if observed.load(Ordering::Acquire) => Poll::Ready(()),
                        Poll::Pending => {
                            context.waker().wake_by_ref();
                            Poll::Pending
                        }
                        Poll::Ready(_) => panic!("probe unexpectedly completed"),
                    })
                    .await;
                    assert_eq!(scanner.phase(), Phase::Probing);
                    let now = clock.now()?;
                    owner.request_cancellation(now)?;
                    let cancellation_started = Instant::now();
                    let canceller = (*cx).clone();
                    let cancellation = std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(100));
                        canceller.cancel_with(CancelKind::User, None);
                    });
                    match pending.await {
                        Err(ScanError::Authority) => {
                            assert_eq!(scanner.phase(), Phase::Interrupted)
                        }
                        Ok(Outcome::Incomplete(report)) => assert_eq!(report.stop, Stop::Cancelled),
                        _ => return Err("cancelled probe reported a completed window".into()),
                    }
                    cancellation
                        .join()
                        .map_err(|_| "cancellation thread panicked")?;
                    assert!(cancellation_started.elapsed() < Duration::from_secs(2));
                    assert!(std::rc::Rc::ptr_eq(&before, &fleet.latest_snapshot()));
                    owner.begin_drain(now)?;
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Cancelled
                } else {
                    TaskOutcome::Failed("cancelled probe fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(
                        3 + i128::from(
                            cx.now()
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
    worker.join().map_err(|_| "fixture thread panicked")??;
    run.output?;
    run.receipt?;
    Ok(())
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
fn completed_windows_detect_conflicts_that_each_window_alone_cannot() -> TestResult {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    server.set_read_timeout(Some(Duration::from_secs(5)))?;
    let destination = match server.local_addr()? {
        std::net::SocketAddr::V4(address) => address,
        _ => return Err("not IPv4".into()),
    };
    let worker = std::thread::spawn(move || -> std::io::Result<()> {
        for reply in [
            packet(),
            packet_with(Some([0x12, 2, 3, 4, 5, 6]), b"UVC.v4.example", true),
        ] {
            let mut query = [0_u8; 32];
            let (count, peer) = server.recv_from(&mut query)?;
            if &query[..count] != fss_packet::unifi_discovery::V1_QUERY.as_slice() {
                return Err(std::io::Error::other("unexpected discovery query"));
            }
            server.send_to(&reply, peer)?;
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
    let first = execute(&config)?;
    let second = execute(&config)?;
    worker.join().map_err(|_| "fixture thread panicked")??;
    assert_eq!(first.assess_claims(0), Some(Default::default()));
    assert_eq!(second.assess_claims(0), Some(Default::default()));
    let combined = Report::combine_completed(&[&first, &first, &second])?;
    assert_eq!(combined.datagrams, 3);
    assert_eq!(combined.cameras.len(), 2);
    assert!(
        combined
            .assess_claims(0)
            .ok_or("missing combined claim")?
            .conflicting_macs_at_address
    );
    assert!(
        combined
            .assess_claims(1)
            .ok_or("missing combined claim")?
            .conflicting_macs_at_address
    );

    let incomplete = Report {
        cameras: Vec::new(),
        datagrams: 0,
        malformed: 0,
        out_of_scope: 0,
        stop: Stop::PacketLimit,
    };
    assert!(matches!(
        Report::combine_completed(&[&first, &incomplete]),
        Err(discovery::CombineError::Incomplete)
    ));
    assert!(matches!(
        Report::combine_completed(&[]),
        Err(discovery::CombineError::WindowCount)
    ));
    let invalid = Report {
        cameras: Vec::new(),
        datagrams: 1,
        malformed: 1,
        out_of_scope: 1,
        stop: Stop::WindowElapsed,
    };
    assert!(matches!(
        Report::combine_completed(&[&invalid]),
        Err(discovery::CombineError::InvalidReport)
    ));
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
fn local_discovery_rejects_public_targets_even_in_broad_subnet() {
    let local = Ipv4Addr::new(10, 1, 2, 3);
    let local_target = SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 4), 10001);
    let public_target = SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 10001);
    // Both addresses share the configured /1, but only one is local.
    assert!(Config::new(local, 1, public_target, "r", Duration::from_secs(1), 8).is_err());
    // A directed broadcast may also fall outside the local address ranges.
    let public_broadcast = SocketAddrV4::new(Ipv4Addr::new(11, 255, 255, 255), 10001);
    assert!(Config::new(local, 7, public_broadcast, "r", Duration::from_secs(1), 8).is_err());
    assert!(
        Config::new_many(
            local,
            1,
            &[local_target, public_target],
            "r",
            Duration::from_secs(1),
            8,
        )
        .is_err()
    );
    assert!(Config::new(local, 1, local_target, "r", Duration::from_secs(1), 8).is_ok());
    assert!(
        Config::new(
            local,
            8,
            SocketAddrV4::new(Ipv4Addr::new(10, 255, 255, 255), 10001),
            "r",
            Duration::from_secs(1),
            8,
        )
        .is_ok()
    );
    assert!(
        Config::new(
            local,
            1,
            SocketAddrV4::new(Ipv4Addr::BROADCAST, 10001),
            "r",
            Duration::from_secs(1),
            8,
        )
        .is_ok()
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

#[test]
#[ignore = "owner-authorized live LAN probe; requires explicit interface and destination"]
fn owner_camera_periodic_scanner_live() -> TestResult {
    use fss_reference::unifi_direct::{
        discovery::{
            fleet::Fleet,
            scan::{Outcome, Scanner},
        },
        metered::MeteredClock,
    };
    let bind: Ipv4Addr = std::env::var("FSS_UNIFI_TEST_BIND")?.parse()?;
    let target: Ipv4Addr = std::env::var("FSS_UNIFI_TEST_TARGET")?.parse()?;
    let prefix: u8 = std::env::var("FSS_UNIFI_TEST_PREFIX")?.parse()?;
    let config = Config::new(
        bind,
        prefix,
        SocketAddrV4::new(target, 10001),
        "fixture:owner-periodic",
        Duration::from_secs(3),
        32,
    )?;
    let initial = Report {
        cameras: Vec::new(),
        datagrams: 0,
        malformed: 0,
        out_of_scope: 0,
        stop: Stop::WindowElapsed,
    };
    let fleet = Fleet::from_report(initial, &[])?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut authority, mut tree) = root()?;
    let run = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let run = run_owned_async(
            &mut authority, &mut tree,
            TaskSpec { task_id: TaskId::new("task:owner-periodic")?, started_at: TimestampNs(2) },
            &cx, async |owner, cx| {
                let start = cx.now().as_nanos();
                let output: TestResult = async {
                    let clock = MeteredClock::new(owner, cx, TimestampNs(3))?;
                    let scanner = Scanner::new(cx, owner, clock, &fleet, config.clone(), Duration::from_millis(200))?;
                    for window in 1..=2 {
                        let snapshot = match scanner.next().await? {
                            Outcome::Updated(snapshot) => snapshot,
                            Outcome::Incomplete(_) => return Err("owner discovery window incomplete".into()),
                        };
                        let cameras = &snapshot.report().cameras;
                        let g4 = cameras.iter().filter(|candidate| candidate.platform() == "UVC G4 Instant").count();
                        let issues = (0..cameras.len()).filter_map(|index| snapshot.report().assess_claims(index))
                            .filter(|claims| *claims != Default::default()).count();
                        println!("owner_periodic_window={window} candidates={} g4_claims={g4} claim_issues={issues}", cameras.len());
                        if g4 == 0 { return Err("owner G4 claim was not observed".into()); }
                    }
                    Ok(())
                }.await;
                let outcome = if output.is_ok() { TaskOutcome::Success } else { TaskOutcome::Failed("owner periodic discovery failed".into()) };
                TaskCompletion { output, outcome, completed_at: TimestampNs(3 + i128::from(cx.now().as_nanos().checked_sub(start).expect("runtime clock regressed"))) }
            },
        ).await?;
        Ok::<_, Box<dyn Error>>(run)
    })?;
    run.output?;
    run.receipt?;
    Ok(())
}

#[test]
fn parked_discovery_rechecks_canonical_cancellation_and_drain() -> TestResult {
    use asupersync::time::timeout_at;
    use std::{
        future::{Future, poll_fn},
        task::Poll,
    };

    // The runtime Cx stays active in every case. Explicitly repoll the parked
    // operation: this tests admission, not a cancellation wake or quiescence.
    for cancel in [false, true] {
        for retain_prior in [false, true] {
            let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
            server.set_nonblocking(true)?;
            let destination = match server.local_addr()? {
                std::net::SocketAddr::V4(address) => address,
                _ => return Err("not IPv4".into()),
            };
            let config = Config::new(
                Ipv4Addr::LOCALHOST,
                8,
                destination,
                "fixture:parked-discovery",
                Duration::from_secs(5),
                8,
            )?;
            let (mut authority, mut tree) = root()?;
            let runtime = RuntimeBuilder::current_thread().build()?;
            let run = runtime.block_on(async {
                let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
                let run = run_owned_async(
                    &mut authority,
                    &mut tree,
                    TaskSpec {
                        task_id: TaskId::new("task:parked-discovery")?,
                        started_at: TimestampNs(2),
                    },
                    &cx,
                    async |owner, runtime_cx| {
                        let start = runtime_cx.now().as_nanos();
                        let output: Result<Report, Box<dyn Error>> = async {
                            let mut pending = std::pin::pin!(discovery::discover(
                                owner,
                                runtime_cx,
                                TimestampNs(3),
                                &config,
                            ));
                            let setup_deadline = runtime_cx.now() + Duration::from_secs(2);
                            let peer = timeout_at(
                                setup_deadline,
                                poll_fn(|context| {
                                    if let Poll::Ready(result) = pending.as_mut().poll(context) {
                                        panic!("discovery completed before receive parked: {result:?}");
                                    }
                                    let mut query = [0_u8; 32];
                                    match server.recv_from(&mut query) {
                                        Ok((length, peer)) => {
                                            assert_eq!(
                                                &query[..length],
                                                fss_packet::unifi_discovery::V1_QUERY.as_slice(),
                                            );
                                            Poll::Ready(Ok(peer))
                                        }
                                        Err(error)
                                            if error.kind() == std::io::ErrorKind::WouldBlock =>
                                        {
                                            context.waker().wake_by_ref();
                                            Poll::Pending
                                        }
                                        Err(error) => Poll::Ready(Err(error)),
                                    }
                                }),
                            )
                            .await
                            .map_err(|_| "discovery did not reach receive")??;
                            let receive_cost =
                                (fss_packet::unifi_discovery::MAX_DATAGRAM + 1) as u64;
                            let first_remaining = owner.remaining_budget()?.network_bytes;
                            assert_eq!(
                                first_remaining,
                                1_000_000
                                    - fss_packet::unifi_discovery::V1_QUERY.len() as u64
                                    - receive_cost,
                            );
                            if retain_prior {
                                server.send_to(&packet(), peer)?;
                                // The second receive reservation proves the first
                                // candidate was admitted before the next read parked.
                                timeout_at(
                                    setup_deadline,
                                    poll_fn(|context| {
                                        if let Poll::Ready(result) = pending.as_mut().poll(context) {
                                            panic!("discovery completed before second receive: {result:?}");
                                        }
                                        let remaining = owner
                                            .remaining_budget()
                                            .expect("live discovery budget")
                                            .network_bytes;
                                        if remaining == first_remaining - receive_cost {
                                            Poll::Ready(())
                                        } else {
                                            assert_eq!(remaining, first_remaining);
                                            context.waker().wake_by_ref();
                                            Poll::Pending
                                        }
                                    }),
                                )
                                .await
                                .map_err(|_| "discovery did not admit the first candidate")?;
                            }
                            let remaining = owner.remaining_budget()?.network_bytes;
                            let now = TimestampNs(
                                3 + i128::from(
                                    runtime_cx
                                        .now()
                                        .as_nanos()
                                        .checked_sub(start)
                                        .ok_or("runtime clock regressed")?,
                                ),
                            );
                            if cancel {
                                owner.request_cancellation(now)?;
                            } else {
                                owner.begin_drain(now)?;
                            }
                            assert!(!runtime_cx.is_cancelled());

                            // A new packet is available, but the resumed raw receive
                            // must not consume it after canonical admission closes.
                            server.send_to(
                                &packet_with(Some([0x12, 2, 3, 4, 5, 6]), b"UVC.late", true),
                                peer,
                            )?;
                            let polled =
                                poll_fn(|context| Poll::Ready(pending.as_mut().poll(context))).await;
                            let Poll::Ready(result) = polled else {
                                return Err("closed canonical owner left discovery pending".into());
                            };
                            let report = result?;
                            assert_eq!(report.stop, Stop::AuthorityStopped);
                            assert_eq!(report.datagrams, usize::from(retain_prior));
                            assert_eq!(report.cameras.len(), usize::from(retain_prior));
                            assert_eq!(report.malformed, 0);
                            assert_eq!(report.out_of_scope, 0);
                            assert_eq!(owner.remaining_budget()?.network_bytes, remaining);
                            if retain_prior {
                                assert_eq!(report.cameras[0].mac(), Some([0x10, 2, 3, 4, 5, 6]));
                            }
                            Ok(report)
                        }
                        .await;
                        let outcome = if cancel {
                            TaskOutcome::Cancelled
                        } else if output.is_ok() {
                            TaskOutcome::Success
                        } else {
                            TaskOutcome::Failed("parked discovery fixture failed".into())
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
            run.output?;
            run.receipt?;
        }
    }
    Ok(())
}
