#![forbid(unsafe_code)]
#![cfg(unix)]
//! Cancellation, backpressure, and exact source custody for event publication.

use asupersync::{
    bytes::Bytes,
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
use fss_reference::{
    ReferenceDeployment, ReplayCx,
    unifi_direct::{
        archive,
        av_unknown_worker_guard::{Advance, Drive, SessionEvent, Step},
        event_handoff,
        event_worker::{self, Input},
        events::Frame,
        metered::MeteredClock,
        supervisor,
    },
};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};
use std::{
    error::Error,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

type Test = Result<(), Box<dyn Error>>;
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
fn frame(source: Bytes) -> Result<Frame, &'static str> {
    Frame::from_untrusted_source(source).map_err(|_| "invalid fixture event")
}
fn key(connection: u64) -> SourceKey {
    SourceKey {
        connection,
        generation: 1,
    }
}

#[test]
#[ignore = "requires a fresh private FSS_EVENT_WORKER_TEST_ROOT; retains all test files"]
fn event_worker_drains_cancellation_retries_and_preserves_exact_sources() -> Test {
    use std::os::unix::fs::PermissionsExt;
    let root =
        PathBuf::from(std::env::var_os("FSS_EVENT_WORKER_TEST_ROOT").ok_or("missing test root")?);
    if !root.is_absolute()
        || !root.is_dir()
        || std::fs::metadata(&root)?.permissions().mode() & 0o077 != 0
    {
        return Err("expected a private existing test root".into());
    }
    let budget = BudgetVector::builder()
        .bytes(128 * 1024 * 1024)
        .storage_operations(10_000)
        .build()?;
    let spec =
        |operation: &str, capabilities: Vec<String>| -> Result<RootAuthoritySpec, Box<dyn Error>> {
            Ok(RootAuthoritySpec {
                trace_id: format!("trace:{operation}"),
                operation_id: OperationId::parse(&format!("operation:{operation}"))?,
                principal: "principal:fixture".into(),
                capabilities,
                deadline: None,
                priority: 1,
                budgets: budget,
                privacy_scope: "privacy:test".into(),
                retention_scope: "retention:test".into(),
                anchor_universe: ContentDigest::sha256(b"event worker fixture"),
                generation: 1,
            })
        };
    let replay_authority =
        ContextAuthority::new_root(spec("event-worker-replay", vec!["ADP-REPLAY-001".into()])?)?;
    let replay = ReplayCx::from_context_authority(&replay_authority, root.clone())?;
    let deployment =
        ReferenceDeployment::open(&root.join("deployment"), "site:event-worker", &replay)?;
    let store = FileEffectJournal::create(
        root.join("journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let journal = archive::journal::UnknownTimeJournal::create(
        Box::new(store),
        ContentDigest::sha256(b"event worker scope"),
        &replay,
    )?;
    let store = FileEffectJournal::create(
        root.join("keeper"),
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
    let mut worker = event_worker::Worker::new(event_worker::Parts {
        deployment,
        journal,
        keeper,
        replay,
        authority: policy,
        retention: ContentDigest::sha256(b"fixture retention"),
        limits: archive::Limits::default(),
        max_event_bytes: 64 * 1024,
        work_limit: 4_000_000_000,
    })
    .map_err(|_| "worker configuration refused")?;
    let first = Bytes::from_static(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventSmartAudio","messageId":7,"responseExpected":false,"payload":{"levelDb":-40}}"#);
    let second = Bytes::from_static(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventSmartAudio","messageId":8,"responseExpected":false,"payload":{"levelDb":-35}}"#);
    let claim = ContentDigest::sha256(b"fixture camera");
    let unhandled =
        SessionEvent::Advance(Advance::Source(Step::Supervisor(supervisor::Step::Idle)));
    if !matches!(
        event_handoff::offer(&mut worker, unhandled, key(1), claim),
        event_handoff::Result::Unhandled(SessionEvent::Advance(Advance::Source(Step::Supervisor(
            supervisor::Step::Idle
        ))))
    ) {
        return Err("unrelated supervisor step was not returned".into());
    }
    let startup = SessionEvent::Advance(Advance::Source(Step::Supervisor(
        supervisor::Step::StartupRequest(frame(first.clone())?),
    )));
    match event_handoff::offer(&mut worker, startup, key(1), claim) {
        event_handoff::Result::Unhandled(SessionEvent::Advance(Advance::Source(
            Step::Supervisor(supervisor::Step::StartupRequest(returned)),
        ))) if returned.source() == first.as_ref() => (),
        _ => return Err("startup request was not returned intact".into()),
    }
    let first_step = SessionEvent::Advance(Advance::Source(Step::Supervisor(
        supervisor::Step::CameraEvent(frame(first.clone())?),
    )));
    if !matches!(
        event_handoff::offer(&mut worker, first_step, key(1), claim),
        event_handoff::Result::Accepted {
            origin: event_handoff::Origin::Source
        }
    ) {
        return Err("first event handoff refused".into());
    }
    if worker.status() != event_worker::Status::Pending {
        return Err("first event not held".into());
    }
    let (mut authority, mut tree) = AuthorityCx::root(
        spec(
            "event-worker",
            vec![
                RuntimeGrant::ObjectStage.as_str().into(),
                RuntimeGrant::ObjectPublish.as_str().into(),
            ],
        )?,
        RegionId::new("region:event-worker")?,
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
                task_id: TaskId::new("task:event-worker")?,
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
                    worker
                        .start(task, cx, clock, "fixture:event", &cost)
                        .map_err(|e| format!("start: {e:?}"))?;
                    timeout(cx.now(), Duration::from_secs(5), async {
                        while !access.entered.load(Ordering::Acquire) {
                            yield_now().await;
                        }
                    })
                    .await
                    .map_err(|_| "worker not entered")?;
                    let second_step = SessionEvent::Advance(Advance::Archive(Drive::Control {
                        step: supervisor::Step::CameraEvent(
                            frame(second.clone()).map_err(str::to_string)?,
                        ),
                        completion: None,
                    }));
                    let second_input = match event_handoff::offer(
                        &mut worker,
                        second_step,
                        key(2),
                        claim,
                    ) {
                        event_handoff::Result::Refused {
                            origin: event_handoff::Origin::Control { completion: None },
                            refusal:
                                event_worker::OfferRefusal::Busy(input @ Input::Original { .. }),
                        } => input,
                        _ => return Err("busy handoff lost event or context".into()),
                    };
                    worker.abort();
                    timeout(cx.now(), Duration::from_secs(5), async {
                        while !worker.cancellation_observed() {
                            yield_now().await;
                        }
                    })
                    .await
                    .map_err(|_| "cancellation not observed")?;
                    worker = match worker.retire() {
                        Err(worker) => worker,
                        Ok(_) => return Err("retired undrained worker".into()),
                    };
                    access.block.store(false, Ordering::Release);
                    let cancelled = timeout(cx.now(), Duration::from_secs(10), worker.join())
                        .await
                        .map_err(|_| "drain timeout")?
                        .ok_or("missing completion")?;
                    if cancelled.runtime.is_err()
                        || !matches!(
                            cancelled.outcome,
                            event_worker::Outcome::Publication(
                                event_worker::Publication::Refused { .. }
                            )
                        )
                        || worker.status() != event_worker::Status::Pending
                    {
                        return Err("cancelled event not retained".into());
                    }
                    access.allow.store(true, Ordering::Release);
                    worker
                        .start(task, cx, clock, "fixture:event", &cost)
                        .map_err(|e| format!("retry: {e:?}"))?;
                    let first_result = timeout(cx.now(), Duration::from_secs(10), worker.join())
                        .await
                        .map_err(|_| "retry timeout")?
                        .ok_or("missing first receipt")?;
                    if first_result.runtime.is_err() {
                        return Err("first runtime failed".into());
                    }
                    let first_pin = match first_result.outcome {
                        event_worker::Outcome::Publication(
                            event_worker::Publication::Published { pin, .. },
                        ) => pin,
                        _ => return Err("first event not published".into()),
                    };
                    worker
                        .offer(second_input)
                        .map_err(|_| "second offer refused")?;
                    worker
                        .start(task, cx, clock, "fixture:event", &cost)
                        .map_err(|e| format!("second start: {e:?}"))?;
                    let second_result = timeout(cx.now(), Duration::from_secs(10), worker.join())
                        .await
                        .map_err(|_| "second timeout")?
                        .ok_or("missing second receipt")?;
                    if second_result.runtime.is_err() {
                        return Err("second runtime failed".into());
                    }
                    let second_pin = match second_result.outcome {
                        event_worker::Outcome::Publication(
                            event_worker::Publication::Published { pin, .. },
                        ) => pin,
                        _ => return Err("second event not published".into()),
                    };
                    if first_pin == second_pin {
                        return Err("event identities collapsed".into());
                    }
                    let retired = worker.retire().map_err(|_| "retirement refused")?;
                    if retired.fenced || retired.pending.is_some() {
                        return Err("event remained pending".into());
                    }
                    let mut parts = retired.parts;
                    for (pin, connection, source) in [
                        (first_pin, 1, first.as_ref()),
                        (second_pin, 2, second.as_ref()),
                    ] {
                        let recovered = archive::read_unknown_time_event(
                            &mut parts.deployment,
                            pin,
                            access.as_ref(),
                            archive::Limits::default(),
                            &mut WorkBudget::new(4_000_000_000),
                            &parts.replay,
                        )
                        .map_err(|e| e.to_string())?;
                        if recovered.key().connection != connection
                            || recovered.frame().source() != source
                        {
                            return Err("recovered event mismatch".into());
                        }
                    }
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("event worker fixture failed".into())
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
