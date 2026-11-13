#![forbid(unsafe_code)]
//! Source-owning startup name probes over real loopback TCP sockets.

use asupersync::runtime::RuntimeBuilder;
use fss_container::flv_avc::SourceKey;
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_packet::extended_flv::{
    Limits,
    stream::{Framer, NameProbeOwner},
};
use fss_reference::unifi_direct::{ingress, listener, metered::MeteredClock, pipeline, recording};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};
use std::{
    error::Error,
    future::{Future, poll_fn},
    io::Write,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    task::Poll,
    time::Duration,
};

type Test<T = ()> = Result<T, Box<dyn Error>>;

struct Policy;
impl listener::Admission for Policy {
    fn listener(&self, requested: SocketAddrV4, bound: Option<SocketAddrV4>) -> bool {
        requested.ip().is_loopback() && bound.is_none_or(|v| v.ip().is_loopback() && v.port() != 0)
    }
    fn peer(&self, bound: SocketAddrV4, source: SocketAddrV4) -> bool {
        bound.ip().is_loopback() && source.ip().is_loopback()
    }
}

fn media(name: &str) -> Vec<u8> {
    let mut payload = b"\x02\x00\x06event1\x03\x00\x0astreamName\x02\x00\x10".to_vec();
    payload.extend(name.as_bytes());
    payload.extend([0, 0, 9]);
    let n = payload.len();
    let mut out = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    out.extend([
        18,
        (n >> 16) as u8,
        (n >> 8) as u8,
        n as u8,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]);
    out.extend(payload);
    out.extend((11_u32 + n as u32).to_be_bytes());
    out
}

fn parts(connection: u64) -> Test<(Framer, recording::Recorder)> {
    Ok((
        Framer::new(Limits::default(), 4096)?,
        recording::Recorder::new(
            SourceKey {
                connection,
                generation: 1,
            },
            recording::Limits::default(),
        )?,
    ))
}

#[test]
fn pending_probe_resumes_and_preserves_source_while_mismatch_stops() -> Test {
    let mut budget = BudgetVector::ZERO;
    budget.bytes = 1_000_000;
    budget.network_bytes = 1_000_000;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:name-probe".into(),
            operation_id: OperationId::parse("operation:name-probe")?,
            principal: "principal:owner".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::ReadMedia.as_str().into(),
            ],
            deadline: Some(TimestampNs(60_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"name probe fixture"),
            generation: 1,
        },
        RegionId::new("region:name-probe")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    let run = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:name-probe")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let clock = MeteredClock::new(task, cx, TimestampNs(3)).expect("fixture clock");
                let result: Test = async {
                    let policy = Policy;
                    let mut listener = listener::Listener::bind(
                        task,
                        cx,
                        clock,
                        &policy,
                        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
                        "fixture:camera",
                        Duration::from_secs(5),
                    )
                    .await?;
                    let address = SocketAddr::V4(listener.local_addr());
                    let expected = media("0123456789abcdef");
                    let mut sent = expected.clone();
                    sent.extend([0x77; 20]);
                    let (tx, rx) = std::sync::mpsc::channel();
                    let peer = std::thread::spawn(move || -> std::io::Result<()> {
                        let mut socket =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        socket.write_all(&sent[..13])?;
                        rx.recv_timeout(Duration::from_secs(5))
                            .map_err(std::io::Error::other)?;
                        socket.write_all(&sent[13..])
                    });
                    let (framer, recorder) = parts(1)?;
                    let mut pipeline = listener
                        .accept_next(framer, recorder, 4096, 100_000, Duration::from_secs(5))
                        .await?;
                    assert!(matches!(
                        pipeline.probe_name_step(task, cx, clock.now()?).await,
                        Err(pipeline::NameProbeError::NotConfigured)
                    ));
                    let probe = NameProbeOwner::new(
                        "event1",
                        "0123456789abcdef",
                        expected.len(),
                        4,
                        1_000_000,
                    )?;
                    pipeline
                        .begin_name_probe(probe)
                        .map_err(|_| "probe refused")?;
                    let mut retained_header = 0;
                    while retained_header < 13 {
                        match pipeline.probe_name_step(task, cx, clock.now()?).await? {
                            ingress::NameProbeStep::Progress { appended } => {
                                retained_header += appended
                            }
                            other => {
                                return Err(format!("unexpected partial header: {other:?}").into());
                            }
                        }
                    }
                    assert_eq!(retained_header, 13);
                    let mut pending = Box::pin(pipeline.probe_name_step(task, cx, clock.now()?));
                    poll_fn(|cx| match pending.as_mut().poll(cx) {
                        Poll::Pending => Poll::Ready(()),
                        Poll::Ready(_) => panic!("probe did not wait"),
                    })
                    .await;
                    drop(pending);
                    assert!(pipeline.name_probe_work_remaining().ok_or("lost probe")? < 1_000_000);
                    tx.send(())?;
                    peer.join().map_err(|_| "peer panicked")??;
                    let mut matched = false;
                    for _ in 0..16 {
                        match pipeline.probe_name_step(task, cx, clock.now()?).await? {
                            ingress::NameProbeStep::Progress { .. } => (),
                            ingress::NameProbeStep::Matched { tag_index: 0 } => {
                                matched = true;
                                break;
                            }
                            other => return Err(format!("unexpected name probe: {other:?}").into()),
                        }
                    }
                    assert!(matched);
                    let probe = pipeline
                        .take_name_probe()
                        .ok_or("probe owner unavailable")?;
                    assert!(probe.work_remaining() < 1_000_000);
                    pipeline.enable_audio_tracking()?;
                    let mut retained = Vec::new();
                    let mut eof = false;
                    for _ in 0..16 {
                        match pipeline.step(task, cx, clock.now()?).await? {
                            pipeline::Step::Recording(recording::Push::Source {
                                record, ..
                            }) => retained.extend_from_slice(record.bytes()),
                            pipeline::Step::Progress { .. } => (),
                            pipeline::Step::Eof => {
                                eof = true;
                                break;
                            }
                            other => return Err(format!("unexpected media: {other:?}").into()),
                        }
                    }
                    assert!(eof);
                    assert_eq!(retained, expected);
                    let retired = pipeline.retire();
                    assert_eq!(retired.ingress.framing.bytes(), &[0x77; 20]);

                    let peer = std::thread::spawn(move || -> std::io::Result<()> {
                        let mut socket =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        socket.write_all(&media("ffffffffffffffff"))
                    });
                    let (framer, recorder) = parts(2)?;
                    let mut pipeline = listener
                        .accept_next(framer, recorder, 4096, 100_000, Duration::from_secs(5))
                        .await?;
                    pipeline
                        .begin_name_probe(NameProbeOwner::new(
                            "event1",
                            "0123456789abcdef",
                            4096,
                            4,
                            1_000_000,
                        )?)
                        .map_err(|_| "probe refused")?;
                    peer.join().map_err(|_| "peer panicked")??;
                    let mut mismatched = false;
                    for _ in 0..16 {
                        match pipeline.probe_name_step(task, cx, clock.now()?).await? {
                            ingress::NameProbeStep::Progress { .. } => (),
                            ingress::NameProbeStep::Mismatched { tag_index: 0 } => {
                                mismatched = true;
                                break;
                            }
                            other => {
                                return Err(format!("unexpected mismatch result: {other:?}").into());
                            }
                        }
                    }
                    assert!(mismatched);
                    assert!(matches!(
                        pipeline.step(task, cx, clock.now()?).await,
                        Err(pipeline::Error::Stopped)
                    ));
                    assert!(pipeline.take_name_probe().is_some());
                    let retired = pipeline.retire();
                    assert_eq!(retired.ingress.framing.bytes(), media("ffffffffffffffff"));

                    let peer = std::thread::spawn(move || -> std::io::Result<()> {
                        let mut socket =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        socket.write_all(&media("0123456789abcdef"))
                    });
                    let (framer, recorder) = parts(3)?;
                    let mut pipeline = listener
                        .accept_next(framer, recorder, 4096, 100_000, Duration::from_secs(5))
                        .await?;
                    pipeline
                        .begin_name_probe(NameProbeOwner::new(
                            "event1",
                            "0123456789abcdef",
                            13,
                            4,
                            1_000_000,
                        )?)
                        .map_err(|_| "probe refused")?;
                    peer.join().map_err(|_| "peer panicked")??;
                    let mut bounded = false;
                    for _ in 0..16 {
                        match pipeline.probe_name_step(task, cx, clock.now()?).await? {
                            ingress::NameProbeStep::Progress { .. } => (),
                            ingress::NameProbeStep::LimitReached { tags_scanned: 0 } => {
                                bounded = true;
                                break;
                            }
                            other => {
                                return Err(format!("unexpected bound result: {other:?}").into());
                            }
                        }
                    }
                    assert!(bounded);
                    let retired = pipeline.retire();
                    assert_eq!(
                        retired.ingress.framing.bytes(),
                        &media("0123456789abcdef")[..13]
                    );
                    if let Some(chunk) = retired.ingress.buffered {
                        let start = chunk.source.offset() as usize;
                        assert_eq!(
                            &chunk.source.bytes()[..chunk.appended],
                            &media("0123456789abcdef")[start..start + chunk.appended]
                        );
                    }

                    // A wrong-name connection cannot win selection, and its
                    // exact prefix remains owned while a later candidate wins.
                    let peer = std::thread::spawn(move || -> std::io::Result<()> {
                        let mut socket =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        socket.write_all(&media("ffffffffffffffff"))
                    });
                    let (framer, recorder) = parts(4)?;
                    let initial = listener
                        .accept_next(framer, recorder, 4096, 100_000, Duration::from_secs(5))
                        .await?;
                    peer.join().map_err(|_| "peer panicked")??;
                    let mut candidates = listener::MediaCandidates::new_validating(
                        listener,
                        initial,
                        2,
                        4096,
                        100_000,
                        Duration::from_secs(5),
                    )
                    .map_err(|_| "candidate setup refused")?;
                    assert!(matches!(
                        candidates.require_stream_name(
                            "event1",
                            "0123456789abcdef",
                            200_000,
                            4,
                            1_000_000
                        ),
                        Err(listener::CandidateError::Configuration)
                    ));
                    candidates.require_stream_name(
                        "event1",
                        "0123456789abcdef",
                        4096,
                        4,
                        1_000_000,
                    )?;
                    assert!(matches!(
                        candidates.require_flv_header(),
                        Err(listener::CandidateError::Configuration)
                    ));
                    let mut factory =
                        |_: usize| parts(5).map_err(|_| std::io::Error::other("fixture parts"));
                    for _ in 0..64 {
                        let mut wait = Box::pin(candidates.select(&mut factory));
                        poll_fn(|cx| match wait.as_mut().poll(cx) {
                            Poll::Pending => Poll::Ready(()),
                            Poll::Ready(result) => panic!("unexpected early selection: {result:?}"),
                        })
                        .await;
                        drop(wait);
                        if candidates.name_rejections() == 1 {
                            break;
                        }
                        asupersync::runtime::yield_now().await;
                    }
                    assert_eq!(candidates.name_rejections(), 1);
                    let peer = std::thread::spawn(move || -> std::io::Result<()> {
                        let mut socket =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        socket.write_all(&media("0123456789abcdef"))
                    });
                    candidates.select(&mut factory).await?;
                    peer.join().map_err(|_| "peer panicked")??;
                    assert_eq!(candidates.attempts(), 2);
                    let selected = candidates
                        .take_ready()
                        .ok_or("matching candidate missing")?;
                    assert_eq!(selected.source_key().connection, 5);
                    assert_eq!(
                        selected.retire().ingress.framing.bytes(),
                        media("0123456789abcdef")
                    );
                    let (mut listener, rejected, additional) = candidates.into_parts();
                    assert_eq!(
                        rejected
                            .ok_or("rejected candidate lost")?
                            .retire()
                            .ingress
                            .framing
                            .bytes(),
                        media("ffffffffffffffff")
                    );
                    assert!(additional.into_iter().all(|item| item.is_none()));

                    let peer = std::thread::spawn(move || -> std::io::Result<()> {
                        let mut socket =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        socket.write_all(&media("ffffffffffffffff"))
                    });
                    let (framer, recorder) = parts(6)?;
                    let initial = listener
                        .accept_next(framer, recorder, 4096, 100_000, Duration::from_secs(5))
                        .await?;
                    peer.join().map_err(|_| "peer panicked")??;
                    let mut candidates = listener::MediaCandidates::new_validating(
                        listener,
                        initial,
                        1,
                        4096,
                        100_000,
                        Duration::from_secs(5),
                    )
                    .map_err(|_| "candidate setup refused")?;
                    candidates.require_stream_name(
                        "event1",
                        "0123456789abcdef",
                        4096,
                        4,
                        1_000_000,
                    )?;
                    let mut factory =
                        |_: usize| parts(7).map_err(|_| std::io::Error::other("fixture parts"));
                    assert!(matches!(
                        candidates.select(&mut factory).await,
                        Err(listener::CandidateError::NoMatchingName)
                    ));
                    let (_listener, rejected, _) = candidates.into_parts();
                    assert_eq!(
                        rejected
                            .ok_or("exhausted candidate lost")?
                            .retire()
                            .ingress
                            .framing
                            .bytes(),
                        media("ffffffffffffffff")
                    );
                    Ok(())
                }
                .await;
                let outcome = if result.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("name probe fixture failed".into())
                };
                TaskCompletion {
                    output: result,
                    outcome,
                    completed_at: TimestampNs(59_000_000_000),
                }
            },
        )
        .await?;
        run.receipt?;
        run.output
    });
    run
}
