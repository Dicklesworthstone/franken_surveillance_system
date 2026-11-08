#![forbid(unsafe_code)]
//! Task ownership, cancellation, and source-custody contracts for source publication.

use std::{
    error::Error,
    future::{Future, poll_fn},
    path::PathBuf,
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::Duration,
};

use asupersync::{
    runtime::{RuntimeBuilder, yield_now},
    time::timeout,
};
use fss_container::flv_avc::SourceKey;
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs, region::ContextAuthority,
};
use fss_geometry::WorkBudget;
use fss_object::{
    HostSpoolIo,
    effect_journal::{EffectJournalLimits, FileEffectJournal},
};
use fss_packet::extended_flv::{
    Limits as FlvLimits,
    stream::{Framer, MAX_BUFFER_BYTES, Next, RecordKind, SearchMode, SourceRecord},
};
use fss_reference::{
    ReferenceDeployment, ReplayCx,
    unifi_direct::{
        archive,
        av_session_inbox::Inbox,
        av_unknown_worker_guard::{Advance, Drive, SessionEvent, SessionObserver, Step},
        av_worker::StartError,
        metered::MeteredClock,
        pipeline,
        recording::{Push, SourceDisposition},
        source_handoff, source_worker, supervisor,
    },
};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};

type Test = Result<(), Box<dyn Error>>;
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Access {
    allow: AtomicBool,
    block: AtomicBool,
    entered: AtomicBool,
}
impl archive::RetainAuthority for Access {
    fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
        self.entered.store(true, Ordering::Release);
        for _ in 0..2500 {
            if !self.block.load(Ordering::Acquire) {
                return self.allow.load(Ordering::Acquire);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        false
    }
}
impl archive::ReadAuthority for Access {
    fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
        self.allow.load(Ordering::Acquire)
    }
}
struct Unblock(Arc<Access>);
impl Drop for Unblock {
    fn drop(&mut self) {
        self.0.block.store(false, Ordering::Release);
    }
}

fn header() -> Result<SourceRecord, Box<dyn Error>> {
    let mut framer = Framer::new(FlvLimits::default(), 1024)?;
    framer.append(0, b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00")?;
    match framer.take()? {
        Next::Record(record) => Ok(record),
        Next::NeedMore => Err("header missing".into()),
    }
}
fn source_event(record: SourceRecord, control: bool) -> SessionEvent {
    let disposition = if record.kind() == RecordKind::Header {
        SourceDisposition::Header
    } else {
        SourceDisposition::PreRoll
    };
    let step = supervisor::Step::Media(pipeline::Step::Recording(Push::Source {
        record,
        disposition,
    }));
    if control {
        SessionEvent::Advance(Advance::Archive(Drive::Control {
            step,
            completion: None,
        }))
    } else {
        SessionEvent::Advance(Advance::Source(Step::Supervisor(step)))
    }
}
fn key(connection: u64) -> SourceKey {
    SourceKey {
        connection,
        generation: 1,
    }
}

#[test]
fn source_worker_drains_cancelled_attempt_and_retries_exact_sources() -> Test {
    exercise_source_worker(header()?, header()?)
}

#[test]
#[ignore = "requires private bounded camera-derived replay input on stdin"]
fn source_worker_camera_replay_from_stdin() -> Test {
    use std::io::Read;
    let mut wire = Vec::new();
    std::io::stdin()
        .lock()
        .take((MAX_BUFFER_BYTES + 1) as u64)
        .read_to_end(&mut wire)?;
    if wire.len() > MAX_BUFFER_BYTES {
        return Err("camera replay exceeds input bound".into());
    }
    let mut framer = Framer::with_mode(
        FlvLimits::default(),
        MAX_BUFFER_BYTES,
        SearchMode::ZeroStreamId,
    )?;
    framer.append(0, &wire)?;
    let header = match framer.take()? {
        Next::Record(record) if record.kind() == RecordKind::Header => record,
        _ => return Err("camera replay header missing".into()),
    };
    match framer.take()? {
        Next::Record(record) if matches!(record.kind(), RecordKind::FirstTag { .. }) => (),
        _ => return Err("camera replay configuration missing".into()),
    }
    let sample = match framer.take()? {
        Next::Record(record) if matches!(record.kind(), RecordKind::Candidate { .. }) => record,
        _ => return Err("camera replay source candidate missing".into()),
    };
    exercise_source_worker(header, sample)?;
    println!("source_worker_camera_replay=passed records=2");
    Ok(())
}

fn exercise_source_worker(first_record: SourceRecord, second_record: SourceRecord) -> Test {
    let first_bytes = first_record.bytes().to_vec();
    let second_bytes = second_record.bytes().to_vec();
    let temp =
        Temp(std::env::temp_dir().join(format!("fss-unifi-source-worker-{}", std::process::id())));
    std::fs::create_dir(&temp.0)?;
    let budget = BudgetVector::builder()
        .bytes(128 * 1024 * 1024)
        .storage_operations(10_000)
        .build()?;
    let replay_authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:source-worker-replay".into(),
        operation_id: OperationId::parse("operation:source-worker-replay")?,
        principal: "principal:fixture".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 1,
        budgets: budget,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"site:source-worker"),
        generation: 1,
    })?;
    let replay = ReplayCx::from_context_authority(&replay_authority, temp.0.clone())?;
    let deployment =
        ReferenceDeployment::open(&temp.0.join("deployment"), "site:source-worker", &replay)?;
    let store = FileEffectJournal::create(
        temp.0.join("journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let journal = archive::journal::UnknownTimeJournal::create(
        Box::new(store),
        ContentDigest::sha256(b"source worker scope"),
        &replay,
    )?;
    let store = FileEffectJournal::create(
        temp.0.join("keeper"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let keeper =
        archive::journal::UnknownTimeAnchorKeeper::create(Box::new(store), &journal, &replay)?;
    let access = Arc::new(Access {
        allow: AtomicBool::new(false),
        block: AtomicBool::new(true),
        entered: AtomicBool::new(false),
    });
    let _unblock = Unblock(access.clone());
    let policy: Arc<dyn archive::RetainAuthority + Send + Sync> = access.clone();
    let mut worker = source_worker::Worker::new(source_worker::Parts {
        deployment,
        journal,
        keeper,
        replay,
        authority: policy,
        retention: ContentDigest::sha256(b"source worker retention"),
        limits: archive::Limits::default(),
        max_source_bytes: MAX_BUFFER_BYTES,
        work_limit: 4_000_000_000,
    })
    .map_err(|_| "worker configuration")?;
    let mut inbox = Inbox::new("operation:source-handoff", 1, 4, MAX_BUFFER_BYTES)
        .map_err(|_| "inbox configuration refused")?;
    inbox
        .observe(source_event(first_record, false))
        .map_err(|_| "inbox refused first source")?;
    let claim = ContentDigest::sha256(b"fixture camera claim");
    if !matches!(
        source_handoff::offer(
            &mut worker,
            inbox.take().ok_or("first event missing")?,
            key(1),
            claim
        ),
        source_handoff::Result::Accepted {
            origin: source_handoff::Origin::Source,
            ..
        }
    ) {
        return Err("first source handoff refused".into());
    }
    if !matches!(
        source_handoff::offer(
            &mut worker,
            SessionEvent::Advance(Advance::Source(Step::SourceQueued)),
            key(1),
            claim
        ),
        source_handoff::Result::Unhandled(SessionEvent::Advance(Advance::Source(
            Step::SourceQueued
        )))
    ) {
        return Err("unrelated event not returned".into());
    }
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:source-worker".into(),
            operation_id: OperationId::parse("operation:source-worker")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::ObjectStage.as_str().into(),
                RuntimeGrant::ObjectPublish.as_str().into(),
            ],
            deadline: None,
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"site:source-worker"),
            generation: 1,
        },
        RegionId::new("region:source-worker")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:source-worker")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: Result<(), String> = async {
                    let clock =
                        MeteredClock::new(task, cx, TimestampNs(3)).map_err(|e| e.to_string())?;
                    let cost = BudgetVector::builder()
                        .bytes(16 * 1024 * 1024)
                        .storage_operations(1000)
                        .build()
                        .map_err(|e| e.to_string())?;
                    let other = cx.clone();
                    if !matches!(
                        worker.start(task, &other, clock, "fixture:source", &cost),
                        Err(StartError::Context)
                    ) {
                        return Err("foreign context accepted".into());
                    }
                    worker
                        .start(task, cx, clock, "fixture:source", &cost)
                        .map_err(|e| format!("start: {e:?}"))?;
                    timeout(cx.now(), Duration::from_secs(5), async {
                        while !access.entered.load(Ordering::Acquire) {
                            yield_now().await;
                        }
                    })
                    .await
                    .map_err(|_| "source worker not entered")?;
                    inbox.observe(source_event(second_record, true)).map_err(|_| "inbox refused second source")?;
                    let second = match source_handoff::offer(&mut worker, inbox.take().ok_or("second event missing")?, key(2), claim) {
                        source_handoff::Result::Refused {origin: source_handoff::Origin::Control { completion: None }, refusal: source_worker::OfferRefusal::Busy(input)} => input,
                        _ => return Err("source backpressure failed".into()),
                    };
                    worker.abort();
                    timeout(cx.now(), Duration::from_secs(5), async {
                        while !worker.cancellation_observed() {
                            yield_now().await;
                        }
                    })
                    .await
                    .map_err(|_| "cancellation not observed")?;
                    let pending = poll_fn(|context| {
                        let mut wait = pin!(worker.join());
                        Poll::Ready(wait.as_mut().poll(context).is_pending())
                    })
                    .await;
                    if !pending {
                        return Err("joined before source closure drained".into());
                    }
                    worker = match worker.retire() {
                        Err(worker) => worker,
                        Ok(_) => return Err("retired before drain".into()),
                    };
                    access.block.store(false, Ordering::Release);
                    let cancelled = timeout(cx.now(), Duration::from_secs(5), worker.join())
                        .await
                        .map_err(|_| "drain timeout")?
                        .ok_or("missing cancellation")?;
                    if cancelled.runtime.is_err()
                        || !matches!(
                            cancelled.outcome,
                            source_worker::Outcome::Publication(
                                source_worker::Publication::Refused { .. }
                            )
                        )
                    {
                        return Err("unexpected cancellation outcome".into());
                    }
                    access.allow.store(true, Ordering::Release);
                    worker
                        .start(task, cx, clock, "fixture:source", &cost)
                        .map_err(|e| format!("retry: {e:?}"))?;
                    let first = worker.join().await.ok_or("first receipt missing")?;
                    if first.runtime.is_err() {
                        return Err("first runtime failure".into());
                    }
                    let first_pin = match first.outcome {
                        source_worker::Outcome::Publication(
                            source_worker::Publication::Published { pin, .. },
                        ) => pin,
                        _ => return Err("first source not published".into()),
                    };
                    if worker.offer(second).is_err() {
                        return Err("second source refused".into());
                    }
                    worker
                        .start(task, cx, clock, "fixture:source", &cost)
                        .map_err(|e| format!("second start: {e:?}"))?;
                    let second = worker.join().await.ok_or("second receipt missing")?;
                    if second.runtime.is_err() {
                        return Err("second runtime failure".into());
                    }
                    let second_pin = match second.outcome {
                        source_worker::Outcome::Publication(
                            source_worker::Publication::Published { pin, .. },
                        ) => pin,
                        _ => return Err("second source not published".into()),
                    };
                    if first_pin == second_pin {
                        return Err("source bindings collapsed".into());
                    }
                    let retired = worker.retire().map_err(|_| "worker retirement refused")?;
                    if retired.fenced || retired.pending.is_some() {
                        return Err("source remained pending".into());
                    }
                    let mut parts = retired.parts;
                    let mut last_recovered = None;
                    for (pin, connection, expected) in [
                        (first_pin, 1, first_bytes.as_slice()),
                        (second_pin, 2, second_bytes.as_slice()),
                    ] {
                        let recovered = archive::read_unknown_time_source(
                            &mut parts.deployment,
                            pin,
                            access.as_ref(),
                            archive::Limits::default(),
                            &mut WorkBudget::new(4_000_000_000),
                            &parts.replay,
                        )
                        .map_err(|e| e.to_string())?;
                        if recovered.key().connection != connection
                            || recovered.bytes() != expected
                        {
                            return Err("recovered source mismatch".into());
                        }
                        if connection == 2 {last_recovered=Some(recovered);}
                    }
                    let mut replay_worker=source_worker::Worker::new(parts).map_err(|_|"replay worker configuration")?;
                    if replay_worker.offer(source_worker::Input::Recovered(last_recovered.ok_or("recovered source missing")?)).is_err() {return Err("recovered source refused".into());}
                    replay_worker.start(task,cx,clock,"fixture:source",&cost).map_err(|e|format!("replay start: {e:?}"))?;
                    let replayed=replay_worker.join().await.ok_or("replay receipt missing")?;
                    if replayed.runtime.is_err() || !matches!(replayed.outcome,source_worker::Outcome::Publication(source_worker::Publication::Published {pin,..}) if pin==second_pin) {return Err("recovered source replay failed".into());}
                    let retired=replay_worker.retire().map_err(|_|"replay retirement refused")?;
                    if retired.fenced || retired.pending.is_some() {return Err("replay source remained pending".into());}
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("source worker fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(60_000_000_000),
                }
            },
        )
        .await?;
        run.receipt?;
        run.output.map_err(|e| -> Box<dyn Error> { e.into() })
    })?;
    Ok(())
}
