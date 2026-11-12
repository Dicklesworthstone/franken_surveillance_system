#![forbid(unsafe_code)]
//! Reuse a task-scoped media listener across separate candidate connections.

use asupersync::runtime::RuntimeBuilder;
use fss_container::flv_avc::SourceKey;
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_packet::extended_flv::{Limits, stream::Framer};
use fss_reference::unifi_direct::{ingress, listener, metered::MeteredClock, pipeline, recording};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};
use std::{
    cell::Cell,
    error::Error,
    future::{Future, poll_fn},
    io::Write,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    task::Poll,
    time::Duration,
};

type Test<T = ()> = Result<T, Box<dyn Error>>;
struct Policy {
    peer: Cell<bool>,
}
impl listener::Admission for Policy {
    fn listener(&self, requested: SocketAddrV4, bound: Option<SocketAddrV4>) -> bool {
        requested.ip().is_loopback() && bound.is_none_or(|v| v.ip().is_loopback() && v.port() != 0)
    }
    fn peer(&self, bound: SocketAddrV4, source: SocketAddrV4) -> bool {
        self.peer.get() && bound.ip().is_loopback() && source.ip().is_loopback()
    }
}
fn parts(connection: u64) -> Test<(Framer, recording::Recorder)> {
    Ok((
        Framer::new(Limits::default(), 1024 * 1024)?,
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
fn listener_retains_port_after_cancel_empty_peer_and_denied_peer() -> Test {
    let mut budget = BudgetVector::ZERO;
    budget.bytes = 1_000_000;
    budget.network_bytes = 1_000_000;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:listener-reconnect".into(),
            operation_id: OperationId::parse("operation:listener-reconnect")?,
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
            anchor_universe: ContentDigest::sha256(b"listener reconnect fixture"),
            generation: 1,
        },
        RegionId::new("region:listener-reconnect")?,
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
                task_id: TaskId::new("task:listener-reconnect")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let clock = MeteredClock::new(task, cx, TimestampNs(3)).expect("fixture clock");
                let result: Test = async {
                    let policy = Policy {
                        peer: Cell::new(true),
                    };
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
                    let (framer, recorder) = parts(1)?;
                    let mut wait = Box::pin(listener.accept_next(
                        framer,
                        recorder,
                        4096,
                        100_000,
                        Duration::from_secs(5),
                    ));
                    poll_fn(|cx| match wait.as_mut().poll(cx) {
                        Poll::Pending => Poll::Ready(()),
                        Poll::Ready(_) => panic!("accept did not wait"),
                    })
                    .await;
                    drop(wait);
                    let first = std::thread::spawn(move || {
                        std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))
                            .map(drop)
                    });
                    let (framer, recorder) = parts(2)?;
                    let mut empty = listener
                        .accept_next(framer, recorder, 4096, 100_000, Duration::from_secs(5))
                        .await?;
                    first.join().map_err(|_| "empty peer panicked")??;
                    assert_eq!(
                        empty.probe_first_byte(task, cx, clock.now()?).await?,
                        ingress::FirstByte::Empty
                    );
                    assert_eq!(empty.retire().ingress.source.received, 0);
                    policy.peer.set(false);
                    let denied = std::thread::spawn(move || {
                        std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))
                            .map(drop)
                    });
                    let (framer, recorder) = parts(3)?;
                    assert!(matches!(
                        listener
                            .accept_next(framer, recorder, 4096, 100_000, Duration::from_secs(5))
                            .await,
                        Err(listener::Error::Denied)
                    ));
                    denied.join().map_err(|_| "denied peer panicked")??;
                    policy.peer.set(true);
                    let (write_tx, write_rx) = std::sync::mpsc::channel();
                    let sender = std::thread::spawn(move || -> std::io::Result<()> {
                        let mut stream =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        write_rx
                            .recv_timeout(Duration::from_secs(5))
                            .map_err(std::io::Error::other)?;
                        stream.write_all(b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00")
                    });
                    let (framer, recorder) = parts(4)?;
                    let mut second = listener
                        .accept_next(framer, recorder, 4096, 100_000, Duration::from_secs(5))
                        .await?;
                    let before_probe = task.remaining_budget()?;
                    let now = clock.now()?;
                    let mut probe = Box::pin(second.probe_first_byte(task, cx, now));
                    poll_fn(|cx| match probe.as_mut().poll(cx) {
                        Poll::Pending => Poll::Ready(()),
                        Poll::Ready(_) => panic!("probe did not wait"),
                    })
                    .await;
                    drop(probe);
                    let after_cancel = task.remaining_budget()?;
                    assert_eq!(before_probe.bytes - after_cancel.bytes, 1);
                    assert_eq!(before_probe.network_bytes - after_cancel.network_bytes, 1);
                    write_tx.send(())?;
                    sender.join().map_err(|_| "media peer panicked")??;
                    assert_eq!(
                        second.probe_first_byte(task, cx, clock.now()?).await?,
                        ingress::FirstByte::Data
                    );
                    assert_eq!(task.remaining_budget()?, after_cancel);
                    assert!(matches!(
                        second.probe_first_byte(task, cx, clock.now()?).await,
                        Err(pipeline::ProbeError::NotFresh)
                    ));
                    second.enable_audio_tracking()?;
                    let mut eof = false;
                    let mut bytes = Vec::new();
                    for _ in 0..16 {
                        match second.step(task, cx, clock.now()?).await? {
                            pipeline::Step::Eof => {
                                eof = true;
                                break;
                            }
                            pipeline::Step::Recording(recording::Push::Source {
                                record, ..
                            }) => bytes.extend_from_slice(record.bytes()),
                            pipeline::Step::Progress { .. } => (),
                            other => return Err(format!("unexpected media step: {other:?}").into()),
                        }
                    }
                    assert!(eof);
                    assert_eq!(bytes, b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00");
                    assert_eq!(second.retire().ingress.source.received, 13);
                    assert_eq!(SocketAddr::V4(listener.local_addr()), address);

                    let empty_peer = std::thread::spawn(move || {
                        std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))
                            .map(drop)
                    });
                    let (framer, recorder) = parts(5)?;
                    let initial = listener
                        .accept_next(framer, recorder, 4096, 100_000, Duration::from_secs(5))
                        .await?;
                    empty_peer
                        .join()
                        .map_err(|_| "empty limit peer panicked")??;
                    let mut limited = listener::MediaCandidates::new(
                        listener,
                        initial,
                        1,
                        4096,
                        100_000,
                        Duration::from_secs(5),
                    )
                    .map_err(|_| "candidate setup refused")?;
                    let mut unused = |_: usize| -> std::io::Result<(Framer, recording::Recorder)> {
                        panic!("factory used beyond candidate limit")
                    };
                    assert!(matches!(
                        limited.select(&mut unused).await,
                        Err(listener::CandidateError::EmptyLimit)
                    ));
                    assert_eq!(limited.attempts(), 1);
                    let (mut listener, pending, additional) = limited.into_parts();
                    assert!(additional.iter().all(Option::is_none));
                    assert!(pending.is_none());

                    let empty_peer = std::thread::spawn(move || {
                        std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))
                            .map(drop)
                    });
                    let (framer, recorder) = parts(6)?;
                    let initial = listener
                        .accept_next(framer, recorder, 4096, 100_000, Duration::from_secs(5))
                        .await?;
                    empty_peer
                        .join()
                        .map_err(|_| "duplicate key peer panicked")??;
                    let mut candidates = listener::MediaCandidates::new(
                        listener,
                        initial,
                        2,
                        4096,
                        100_000,
                        Duration::from_secs(5),
                    )
                    .map_err(|_| "candidate setup refused")?;
                    let mut duplicate = |_: usize| {
                        parts(6).map_err(|_| std::io::Error::other("fixture parts refused"))
                    };
                    assert!(matches!(
                        candidates.select(&mut duplicate).await,
                        Err(listener::CandidateError::DuplicateSource)
                    ));
                    assert_eq!(candidates.attempts(), 1);
                    let (mut listener, pending, additional) = candidates.into_parts();
                    assert!(additional.iter().all(Option::is_none));
                    assert!(pending.is_none());

                    let (continue_tx, continue_rx) = std::sync::mpsc::channel();
                    let delayed = std::thread::spawn(move || -> std::io::Result<()> {
                        let mut stream =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        continue_rx
                            .recv_timeout(Duration::from_secs(5))
                            .map_err(std::io::Error::other)?;
                        stream.write_all(b"F")
                    });
                    let (framer, recorder) = parts(7)?;
                    let initial = listener
                        .accept_next(framer, recorder, 4096, 100_000, Duration::from_secs(5))
                        .await?;
                    let mut candidates = listener::MediaCandidates::new(
                        listener,
                        initial,
                        2,
                        4096,
                        100_000,
                        Duration::from_secs(5),
                    )
                    .map_err(|_| "candidate setup refused")?;
                    let mut unused = |_: usize| -> std::io::Result<(Framer, recording::Recorder)> {
                        panic!("factory called for pending candidate")
                    };
                    let mut wait = Box::pin(candidates.select(&mut unused));
                    poll_fn(|cx| match wait.as_mut().poll(cx) {
                        Poll::Pending => Poll::Ready(()),
                        Poll::Ready(_) => panic!("selection did not wait"),
                    })
                    .await;
                    drop(wait);
                    continue_tx.send(())?;
                    delayed.join().map_err(|_| "delayed peer panicked")??;
                    candidates.select(&mut unused).await?;
                    assert_eq!(candidates.attempts(), 1);
                    let selected = candidates.take_ready().ok_or("selected pipeline missing")?;
                    assert_eq!(selected.retire().ingress.framing.bytes(), b"F");
                    assert!(matches!(
                        candidates.select(&mut unused).await,
                        Err(listener::CandidateError::Configuration)
                    ));
                    let (mut listener, pending, additional) = candidates.into_parts();
                    assert!(additional.iter().all(Option::is_none));
                    assert!(pending.is_none());

                    // The first connection remains open and idle while a second
                    // one delivers data. Cancellation must preserve both owners.
                    let (start_tx, start_rx) = std::sync::mpsc::channel();
                    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
                    let peer = std::thread::spawn(move || -> std::io::Result<()> {
                        let mut idle =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        start_rx
                            .recv_timeout(Duration::from_secs(5))
                            .map_err(std::io::Error::other)?;
                        let mut media =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        media.write_all(b"F")?;
                        resume_rx
                            .recv_timeout(Duration::from_secs(5))
                            .map_err(std::io::Error::other)?;
                        idle.write_all(b"Z")?;
                        Ok(())
                    });
                    let (framer, recorder) = parts(20)?;
                    let initial = listener
                        .accept_next(framer, recorder, 4096, 100_000, Duration::from_secs(5))
                        .await?;
                    let mut candidates = listener::MediaCandidates::new(
                        listener,
                        initial,
                        2,
                        4096,
                        100_000,
                        Duration::from_secs(5),
                    )
                    .map_err(|_| "parallel setup refused")?;
                    candidates.enable_parallel()?;
                    let mut fresh = |_: usize| {
                        parts(21).map_err(|_| std::io::Error::other("fixture parts refused"))
                    };
                    let mut wait = Box::pin(candidates.select(&mut fresh));
                    poll_fn(|cx| match wait.as_mut().poll(cx) {
                        Poll::Pending => Poll::Ready(()),
                        Poll::Ready(_) => panic!("parallel selector did not wait"),
                    })
                    .await;
                    drop(wait);
                    start_tx.send(())?;
                    candidates.select(&mut fresh).await?;
                    assert_eq!(candidates.attempts(), 2);
                    let selected = candidates
                        .take_ready()
                        .ok_or("parallel candidate missing")?;
                    assert_eq!(selected.source_key().connection, 21);
                    assert_eq!(selected.retire().ingress.framing.bytes(), b"F");
                    let (mut listener, pending, additional) = candidates.into_parts();
                    assert!(additional.iter().all(Option::is_none));
                    let mut idle = pending.ok_or("idle connection ownership lost")?;
                    assert_eq!(idle.source_key().connection, 20);
                    resume_tx.send(())?;
                    peer.join().map_err(|_| "parallel peer panicked")??;
                    assert_eq!(
                        idle.probe_first_byte(task, cx, clock.now()?).await?,
                        ingress::FirstByte::Data
                    );
                    assert_eq!(idle.retire().ingress.framing.bytes(), b"Z");

                    // A malformed prefix and a partial valid prefix cannot
                    // hide a later complete header. Both remain owned.
                    let (release_tx, release_rx) = std::sync::mpsc::channel();
                    let peer = std::thread::spawn(move || -> std::io::Result<()> {
                        let mut malformed =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        malformed.write_all(b"X")?;
                        let mut partial =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        partial.write_all(b"F")?;
                        let mut valid =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        valid.write_all(b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00")?;
                        release_rx
                            .recv_timeout(Duration::from_secs(5))
                            .map_err(std::io::Error::other)?;
                        Ok(())
                    });
                    let (framer, recorder) = parts(30)?;
                    let initial = listener
                        .accept_next(framer, recorder, 4096, 100_000, Duration::from_secs(5))
                        .await?;
                    let refusal = match listener::MediaCandidates::new_validating(
                        listener,
                        initial,
                        3,
                        4096,
                        12,
                        Duration::from_secs(5),
                    ) {
                        Err(refusal) => refusal,
                        Ok(_) => return Err("short header limit accepted".into()),
                    };
                    assert_eq!(refusal.pipeline.source_key().connection, 30);
                    let mut candidates = listener::MediaCandidates::new_validating(
                        refusal.listener,
                        refusal.pipeline,
                        3,
                        4096,
                        100_000,
                        Duration::from_secs(5),
                    )
                    .map_err(|_| "header selection setup refused")?;
                    let mut fresh = |index: usize| {
                        parts(30 + index as u64)
                            .map_err(|_| std::io::Error::other("fixture parts refused"))
                    };
                    candidates.select(&mut fresh).await?;
                    assert_eq!(candidates.attempts(), 3);
                    let mut selected = candidates.take_ready().ok_or("valid header missing")?;
                    assert_eq!(selected.source_key().connection, 32);
                    selected.enable_audio_tracking()?;
                    assert_eq!(
                        selected.retire().ingress.framing.bytes(),
                        b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00"
                    );
                    let (mut listener, malformed, additional) = candidates.into_parts();
                    assert_eq!(
                        malformed
                            .ok_or("malformed prefix lost")?
                            .retire()
                            .ingress
                            .framing
                            .bytes(),
                        b"X"
                    );
                    let mut extra = additional.into_iter().flatten();
                    let partial = extra.next().ok_or("partial prefix lost")?;
                    assert_eq!(partial.source_key().connection, 31);
                    assert_eq!(partial.retire().ingress.framing.bytes(), b"F");
                    assert!(extra.next().is_none());
                    release_tx.send(())?;
                    peer.join().map_err(|_| "header peer panicked")??;

                    // Cancellation while waiting for the remainder preserves
                    // the already-read prefix and the pending reservation.
                    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
                    let peer = std::thread::spawn(move || -> std::io::Result<()> {
                        let mut stream =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        stream.write_all(b"F")?;
                        resume_rx
                            .recv_timeout(Duration::from_secs(5))
                            .map_err(std::io::Error::other)?;
                        stream.write_all(b"LV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00")
                    });
                    let (framer, recorder) = parts(40)?;
                    let initial = listener
                        .accept_next(framer, recorder, 4096, 100_000, Duration::from_secs(5))
                        .await?;
                    let mut candidates = listener::MediaCandidates::new(
                        listener,
                        initial,
                        1,
                        4096,
                        100_000,
                        Duration::from_secs(5),
                    )
                    .map_err(|_| "header cancellation setup refused")?;
                    candidates.enable_parallel()?;
                    candidates.require_flv_header()?;
                    let mut unused = |_: usize| -> std::io::Result<(Framer, recording::Recorder)> {
                        panic!("factory exceeded limit")
                    };
                    let mut wait = Box::pin(candidates.select(&mut unused));
                    poll_fn(|cx| match wait.as_mut().poll(cx) {
                        Poll::Pending => Poll::Ready(()),
                        Poll::Ready(_) => panic!("partial header did not wait"),
                    })
                    .await;
                    drop(wait);
                    resume_tx.send(())?;
                    peer.join().map_err(|_| "partial header peer panicked")??;
                    candidates.select(&mut unused).await?;
                    let selected = candidates.take_ready().ok_or("resumed header missing")?;
                    assert_eq!(
                        selected.retire().ingress.framing.bytes(),
                        b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00"
                    );
                    let (mut listener, remaining, additional) = candidates.into_parts();
                    assert!(remaining.is_none() && additional.iter().all(Option::is_none));

                    // Exhaustion returns the malformed source rather than
                    // dropping its bytes or treating it as empty.
                    let peer = std::thread::spawn(move || -> std::io::Result<()> {
                        let mut stream =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        stream.write_all(b"X")
                    });
                    let (framer, recorder) = parts(50)?;
                    let initial = listener
                        .accept_next(framer, recorder, 4096, 100_000, Duration::from_secs(5))
                        .await?;
                    peer.join()
                        .map_err(|_| "malformed header peer panicked")??;
                    let mut candidates = listener::MediaCandidates::new(
                        listener,
                        initial,
                        1,
                        4096,
                        100_000,
                        Duration::from_secs(5),
                    )
                    .map_err(|_| "header limit setup refused")?;
                    candidates.enable_parallel()?;
                    candidates.require_flv_header()?;
                    assert!(matches!(
                        candidates.select(&mut unused).await,
                        Err(listener::CandidateError::NoValidHeader)
                    ));
                    let (_listener, malformed, additional) = candidates.into_parts();
                    assert!(additional.iter().all(Option::is_none));
                    assert_eq!(
                        malformed
                            .ok_or("exhausted prefix lost")?
                            .retire()
                            .ingress
                            .framing
                            .bytes(),
                        b"X"
                    );
                    Ok(())
                }
                .await;
                let outcome = if result.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("listener fixture failed".into())
                };
                TaskCompletion {
                    output: result,
                    outcome,
                    completed_at: clock.now().expect("completion clock"),
                }
            },
        )
        .await?;
        run.receipt?;
        run.output
    });
    run
}
