#![forbid(unsafe_code)]
//! Bounded video-only trial. This is not an unattended recording service.

use std::{
    future::{Future, poll_fn},
    path::Path,
    pin::pin,
    sync::Arc,
    task::Poll,
    time::Duration,
};

use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite},
};
use fss_container::{Mp4Limits, flv_avc::SourceKey};
use fss_core::{BudgetVector, ContentDigest, RuntimeGrant};
use fss_reference::unifi_direct::{
    archive, av_rollover_generation, av_rollover_supplies, av_worker, conversation, events,
    management, metered::MeteredClock, pipeline, recording_session, recording_storage,
    retirement_source, source_coordinator::ArchiveAdmission, source_worker, supervisor,
    video_bootstrap, video_owned_sink, video_provision, video_retained_provision, video_session,
    video_still, video_still_worker, video_worker,
};
use fss_runtime::{
    drained_blocking::{Receipt, WorkOutcome},
    execution::TaskCx,
};

use super::{Renewal, Retention, control, source_completion, source_control, still_export};

fn export_completion(
    receipt: Receipt<still_export::Job, still_export::Outcome>,
    stopping: bool,
) -> Result<(), &'static str> {
    let runtime_ok = receipt.runtime.is_ok();
    match receipt.work {
        WorkOutcome::Finished(still_export::Outcome::Published) => {
            println!("trial_owned_still_export=published durable=true runtime_ok={runtime_ok}");
            if runtime_ok || stopping {
                Ok(())
            } else {
                Err("still export runtime requires reconciliation")
            }
        }
        WorkOutcome::Finished(still_export::Outcome::PublishedNeedsInspection) => {
            eprintln!("trial_owned_still_export=published cleanup_or_durability=unverified");
            Err("still export publication requires reconciliation")
        }
        WorkOutcome::Finished(still_export::Outcome::Refused) | WorkOutcome::NotStarted(_) => {
            eprintln!("trial_owned_still_export=not_published");
            if stopping {
                Ok(())
            } else {
                Err("still export refused")
            }
        }
        WorkOutcome::Finished(still_export::Outcome::StagingNeedsInspection)
        | WorkOutcome::Finished(still_export::Outcome::LinkNeedsInspection)
        | WorkOutcome::Panicked
        | WorkOutcome::Indeterminate => {
            eprintln!("trial_owned_still_export=reconciliation_required");
            Err("still export requires reconciliation")
        }
    }
}

enum Phase<'scope, 'task, IO> {
    Bootstrap(Box<video_bootstrap::Bootstrap<'scope, 'task, IO>>),
    Recording(Box<video_session::Session<'scope, 'task, IO>>),
    Managed {
        session: Box<video_provision::ProvisioningSession<'scope, 'task, IO>>,
        custody: Vec<video_provision::SupplyCustody>,
        renewal: Option<Renewal>,
    },
    Retained {
        session: Box<video_retained_provision::RetainedSession<'scope, 'task, IO>>,
        custody: Vec<video_provision::SupplyCustody>,
        renewal: Option<Renewal>,
    },
    StoppedRollover(Box<video_session::RolloverParts<'scope, 'task, IO>>),
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> Phase<'scope, 'task, IO> {
    fn control(&mut self) -> Option<recording_session::Control<'_, 'scope, 'task, IO>> {
        match self {
            Self::Bootstrap(owner) => owner.control(),
            Self::Recording(owner) => owner.control(),
            Self::Managed { session, .. } => session.control(),
            Self::Retained { session, .. } => session.control(),
            Self::StoppedRollover(_) => None,
        }
    }
}

fn video_completion(
    completion: video_worker::Completion,
) -> Result<video_owned_sink::Published, &'static str> {
    if completion.runtime.is_err() {
        return Err("video worker runtime failed");
    }
    match completion.outcome {
        video_worker::Outcome::Publication(video_worker::Publication::Published(published)) => {
            Ok(published)
        }
        _ => Err("video publication requires reconciliation"),
    }
}

fn controller_retirement_unresolved(
    controller: &fss_reference::unifi_direct::Retirement,
    clock_trace_present: bool,
) -> bool {
    clock_trace_present
        || controller.previous_phase != fss_reference::unifi_direct::Phase::AgreementReplyObserved
        || controller.prepared.is_some()
        || controller.agreement_id.is_some()
        || controller.hello_request_id.is_some()
        || controller.time_sync_request_id.is_some()
        || controller.stream_request.is_some()
        || controller.stream_request_kind.is_some()
        || controller.motion_request.is_some()
        || controller.event_reply.is_some()
        || controller.event_reply_is_startup_request
        || controller.rejected_message.is_some()
        || controller.unhandled_requests != Default::default()
}

fn session_step(
    step: video_session::Step,
    event: &mut Option<events::Frame>,
    managed: bool,
) -> Result<Option<video_owned_sink::Published>, &'static str> {
    match step {
        video_session::Step::SourceOffered(_)
        | video_session::Step::VideoOffered
        | video_session::Step::SourceStarted
        | video_session::Step::VideoStarted => Ok(None),
        video_session::Step::Supervisor(step) => control(step, event).map(|_| None),
        video_session::Step::SourceArchive {
            control: Some(step),
            completion,
        } => source_control(step, completion, event).map(|_| None),
        video_session::Step::SourceArchive {
            control: None,
            completion: Some(completion),
        } => source_completion(completion).map(|_| None),
        video_session::Step::SourceArchive {
            control: None,
            completion: None,
        } => Ok(None),
        video_session::Step::VideoRetryRequired(step) if managed => {
            control(step, event).map(|_| None)
        }
        video_session::Step::VideoArchive {
            control: step,
            completion,
        } => {
            let published = match completion {
                Some(completion)
                    if managed
                        && completion.runtime.is_ok()
                        && matches!(
                            &completion.outcome,
                            video_worker::Outcome::Publication(
                                video_worker::Publication::Refused {
                                    pending: Some(_),
                                    reason: video_worker::Refusal::BeforePublication(
                                        av_worker::FailureReason::JournalCapacity
                                    )
                                }
                            )
                        ) =>
                {
                    println!("trial_owned_video_rollover=capacity_boundary");
                    Ok(None)
                }
                Some(completion) => video_completion(completion).map(Some),
                None => Ok(None),
            };
            let observed = step.map_or(Ok(()), |step| control(step, event));
            if published.as_ref().is_ok_and(Option::is_some) && observed.is_err() {
                eprintln!("trial_owned_video=published_control_requires_reconciliation");
            }
            published.and_then(|pin| observed.map(|_| pin))
        }
        _ => Err("video session stopped; reconcile source and archive"),
    }
}

async fn archive_tail<'scope, 'task>(
    worker: source_worker::Worker,
    media: pipeline::Retirement,
    key: SourceKey,
    camera_claim: ContentDigest,
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    access: &Retention,
    resource: &str,
    wait: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let plan = match retirement_source::Plan::new(media) {
        Ok(plan) => plan,
        Err(refusal) => {
            eprintln!(
                "trial_owned_tail=plan_refused reason={:?} source_not_persisted=true",
                refusal.reason
            );
            return Err("retired source ranges require reconciliation".into());
        }
    };
    let driver = retirement_source::Driver::begin(worker, plan, key, camera_claim)
        .map_err(|_| "tail worker unavailable; source requires reconciliation")?;
    archive_prepared_tail(
        driver,
        key,
        camera_claim,
        task,
        cx,
        clock,
        access,
        resource,
        wait,
    )
    .await
}

async fn archive_prepared_tail<'scope, 'task>(
    mut driver: retirement_source::Driver,
    key: SourceKey,
    camera_claim: ContentDigest,
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    access: &Retention,
    resource: &str,
    wait: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let plan = driver.plan();
    let start = plan.start;
    let end = plan.end;
    let received = plan.received;
    let count = plan.len();
    let fenced = plan.recorder_fenced;
    let audio_pending = plan.pending_audio.is_some();
    let admission = ArchiveAdmission {
        resource: "unifi:owned-source",
        cost: &BudgetVector::ZERO,
    };
    let deadline = cx.now() + wait;
    let mut pins = Vec::new();
    pins.try_reserve_exact(count)?;
    let mut current = None;
    let result: Result<(), &'static str> = loop {
        let remaining =
            Duration::from_nanos(deadline.as_nanos().saturating_sub(cx.now().as_nanos()));
        if remaining.is_zero() {
            break Err("tail archive deadline elapsed");
        }
        let step = match asupersync::time::timeout(
            cx.now(),
            remaining,
            driver.step(task, cx, clock, admission),
        )
        .await
        {
            Ok(step) => step,
            Err(_) => break Err("tail archive deadline elapsed"),
        };
        match step {
            retirement_source::DriverStep::Offered {
                offset,
                len,
                disposition,
            } => {
                if current.replace((offset, len, disposition)).is_some() {
                    break Err("tail source accounting mismatch");
                }
            }
            retirement_source::DriverStep::Started => (),
            retirement_source::DriverStep::Completed(completion) => {
                if completion.runtime.is_err() {
                    break Err("tail worker runtime failed");
                }
                let pin = match completion.outcome {
                    source_worker::Outcome::Publication(
                        source_worker::Publication::Published { pin, .. },
                    ) => pin,
                    _ => break Err("tail publication requires reconciliation"),
                };
                let Some((offset, len, disposition)) = current.take() else {
                    break Err("tail completion without source");
                };
                pins.push((pin, offset, len, disposition));
            }
            retirement_source::DriverStep::Finished => break Ok(()),
            _ => break Err("tail source requires reconciliation"),
        }
    };
    if let Err(reason) = result {
        driver.abort();
        let completion = driver.join().await;
        let parts = driver
            .into_parts()
            .map_err(|_| "tail worker did not drain")?;
        let pending = parts
            .worker
            .retire()
            .map_err(|_| "tail worker retirement refused")?;
        eprintln!(
            "trial_owned_tail=stopped reason={reason} remaining={} worker_pending={} completion_returned={} source_not_fully_persisted=true",
            parts.plan.len(),
            pending.pending.is_some(),
            completion.is_some()
        );
        return Err(reason.into());
    }
    let parts = driver
        .into_parts()
        .map_err(|_| "tail worker did not drain")?;
    if !parts.plan.is_empty() || current.is_some() || pins.len() != count {
        return Err("tail archive accounting incomplete".into());
    }
    let mut worker = parts
        .worker
        .retire()
        .map_err(|_| "tail worker retirement refused")?;
    if worker.pending.is_some() || worker.fenced {
        return Err("tail worker custody requires reconciliation".into());
    }
    for (pin, offset, len, disposition) in &pins {
        task.checkpoint_for(
            RuntimeGrant::ReadMedia,
            resource,
            clock.now()?,
            &BudgetVector::ZERO,
        )?;
        let record = archive::read_unknown_time_source(
            &mut worker.parts.deployment,
            *pin,
            access,
            archive::Limits::default(),
            &mut fss_geometry::WorkBudget::new(4_000_000_000),
            &worker.parts.replay,
        )?;
        if record.key() != key
            || record.camera_claim() != camera_claim
            || record.offset() != *offset
            || record.bytes().len() != *len
            || record.disposition() != *disposition
        {
            return Err("tail source readback mismatch".into());
        }
    }
    println!(
        "trial_owned_tail=archived records={count} start={start:?} end={end:?} received={received} socket_unread=unknown capture_bounds=unknown"
    );
    if fenced || audio_pending {
        return Err("retired recorder or audio observation requires reconciliation".into());
    }
    Ok(())
}

/// Run a bounded capture from an already admitted camera supervisor.
pub(super) async fn run<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>(
    supervisor: supervisor::Supervisor<'scope, 'task, IO>,
    owner: &mut conversation::Owner<'_, 'scope, 'task>,
    run_id: &super::super::trial_run_id::TrialRunId,
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    root: &Path,
    key: SourceKey,
    camera_claim: ContentDigest,
    retention: ContentDigest,
    access: Arc<Retention>,
    created: recording_storage::Created,
    wait: Duration,
    segment_limit: usize,
    management: management::Preconditions,
    reply_events: bool,
    decode_owned: bool,
    still_color: Option<video_still::Color>,
    still_export_path: Option<&Path>,
    inband: bool,
    mut plan: Option<av_rollover_generation::Plan>,
    renewal_batch: Option<u64>,
    mut retained_bootstrap: Option<av_rollover_generation::BootstrapWorker>,
    stop_after_retained_reservation: bool,
    auto_retained_generations: Option<u64>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let policy = video_bootstrap::Policy {
        inband,
        retention,
        media_limits: Mp4Limits::default(),
        evidence_limits: fss_reference::unifi_direct::evidence::Limits::default(),
    };
    let bootstrap = video_bootstrap::Bootstrap::begin(
        supervisor,
        created.coordinator.into_worker(),
        created.av,
        key,
        camera_claim,
        policy,
    )
    .map_err(|_| "video bootstrap refused; inspect archive")?;
    let mut phase = Some(Phase::Bootstrap(Box::new(bootstrap)));
    let video_admission = ArchiveAdmission {
        resource: "unifi:owned-av",
        cost: &BudgetVector::ZERO,
    };
    let source_admission = ArchiveAdmission {
        resource: "unifi:owned-source",
        cost: &BudgetVector::ZERO,
    };
    let deadline = cx.now() + wait;
    let mut count = 0u64;
    let mut pins = Vec::new();
    pins.try_reserve_exact(segment_limit)?;
    let resource = root.to_str().ok_or("archive path is not UTF-8")?;
    let mut live_still: Option<(video_still_worker::Worker, archive::UnknownTimePin)> = None;
    let mut still_completion: Option<video_still_worker::Completion> = None;
    let mut export_worker: Option<still_export::Worker> = None;
    let mut export_published = false;
    println!("trial_owned_driver=video_only capture_bounds=unknown audio_coverage=unknown");
    let mut result: Result<(), &'static str> = loop {
        let remaining =
            Duration::from_nanos(deadline.as_nanos().saturating_sub(cx.now().as_nanos()));
        let poll_wait = (remaining / 2).min(Duration::from_millis(100));
        let reply_wait = remaining
            .saturating_sub(poll_wait)
            .min(Duration::from_secs(5));
        if poll_wait.is_zero() || reply_wait.is_zero() {
            break Err("owned capture deadline elapsed");
        }
        let Some(current) = phase.as_mut() else {
            break Err("video phase missing");
        };
        let Some(mut handle) = current.control() else {
            break Err("video control unavailable");
        };
        if handle.set_time_sync_reply_wait(Some(reply_wait)).is_err() {
            break Err("clock reply budget refused");
        }
        count += 1;
        if count > 200_000 {
            break Err("owned capture step limit");
        }
        let operation = match run_id.owned_step(count) {
            Ok(operation) => operation,
            Err(_) => break Err("operation identity refused"),
        };
        let mut event = None;
        let mut transition = false;
        let outcome: Result<Option<video_owned_sink::Published>, &'static str> = match current {
            Phase::Bootstrap(bootstrap) => match Box::pin(bootstrap.step(
                owner,
                &operation,
                poll_wait,
                task,
                cx,
                clock,
                source_admission,
            ))
            .await
            {
                video_bootstrap::Step::SourceOffered(_)
                | video_bootstrap::Step::Configured
                | video_bootstrap::Step::SourceStarted => Ok(None),
                video_bootstrap::Step::Supervisor(step) => control(step, &mut event).map(|_| None),
                video_bootstrap::Step::SourceArchive {
                    control: Some(step),
                    completion,
                } => source_control(step, completion, &mut event).map(|_| None),
                video_bootstrap::Step::SourceArchive {
                    control: None,
                    completion: Some(completion),
                } => source_completion(completion).map(|_| None),
                video_bootstrap::Step::SourceArchive {
                    control: None,
                    completion: None,
                } => Ok(None),
                video_bootstrap::Step::Ready => {
                    transition = true;
                    Ok(None)
                }
                _ => Err("video bootstrap stopped; reconcile source and archive"),
            },
            Phase::Recording(session) => session_step(
                Box::pin(session.step(
                    owner,
                    &operation,
                    poll_wait,
                    task,
                    cx,
                    clock,
                    video_admission,
                    source_admission,
                ))
                .await,
                &mut event,
                false,
            ),
            Phase::StoppedRollover(_) => Err("stopped video rollover requires reconciliation"),
            Phase::Retained {
                session,
                custody,
                renewal,
            } => match Box::pin(session.step(
                owner,
                &operation,
                poll_wait,
                task,
                cx,
                clock,
                video_admission,
                source_admission,
                &BudgetVector::ZERO,
            ))
            .await
            {
                video_retained_provision::Step::BootstrapStarted => Ok(None),
                video_retained_provision::Step::BootstrapReady => {
                    println!("trial_owned_video_generation_bootstrap=ready");
                    Ok(None)
                }
                video_retained_provision::Step::ReservationStarted => Ok(None),
                video_retained_provision::Step::Reserved(identity) => {
                    println!(
                        "trial_owned_video_generation_reserved={} reconciliation=pending",
                        identity.generation
                    );
                    if stop_after_retained_reservation {
                        Err("laboratory stop after retained reservation")
                    } else {
                        Ok(None)
                    }
                }
                video_retained_provision::Step::Reconciled(pin) => {
                    println!(
                        "trial_owned_video_creator_observation=recorded journal_sequence={} trust=local",
                        pin.sequence
                    );
                    Ok(None)
                }
                video_retained_provision::Step::AutomaticExhausted(step) => {
                    let observed = match step {
                        video_provision::Step::Managed(
                            video_session::ManagedStep::SuppliesRequired(step),
                        ) => session_step(step, &mut event, true),
                        _ => Err("automatic retained capacity observation invalid"),
                    };
                    observed.and_then(|pin| {
                        if let Some((policy, count)) = renewal
                            .as_mut()
                            .and_then(|policy| policy.next().map(|count| (policy, count)))
                        {
                            if !session.renew_creator_observation(count) {
                                Err("retained video allowance renewal refused")
                            } else {
                                policy.committed(count);
                                println!("trial_owned_video_creator_allowance=renewed count={count} remaining={}", policy.remaining);
                                Ok(pin)
                            }
                        } else {
                            Err("automatic retained generation allowance exhausted")
                        }
                    })
                }
                video_retained_provision::Step::Session(video_provision::Step::SupplyStarted) => {
                    println!("trial_owned_video_supply=started");
                    Ok(None)
                }
                video_retained_provision::Step::Session(
                    video_provision::Step::SupplyInstalled(completion),
                ) if completion.runtime.is_ok()
                    && completion.outcome == av_rollover_supplies::Outcome::Ready =>
                {
                    if custody.len() >= 8 {
                        Err("video supply custody capacity exhausted")
                    } else if let Some(owner) = session.take_custody() {
                        custody.push(owner);
                        println!("trial_owned_video_supply=installed custody=retained");
                        Ok(None)
                    } else {
                        Err("video supply custody missing")
                    }
                }
                video_retained_provision::Step::Session(video_provision::Step::Managed(
                    video_session::ManagedStep::Session(step)
                    | video_session::ManagedStep::SuppliesRequired(step),
                )) => session_step(step, &mut event, true),
                video_retained_provision::Step::Session(video_provision::Step::Managed(
                    video_session::ManagedStep::RolloverBeginning,
                )) => {
                    println!("trial_owned_video_rollover=beginning");
                    Ok(None)
                }
                video_retained_provision::Step::Session(video_provision::Step::Managed(
                    video_session::ManagedStep::Rollover(
                        video_session::AutomaticRolloverStep::Started
                        | video_session::AutomaticRolloverStep::Rollover(
                            video_session::RolloverStep::PreflightReady,
                        ),
                    ),
                )) => Ok(None),
                video_retained_provision::Step::Session(video_provision::Step::Managed(
                    video_session::ManagedStep::Rollover(
                        video_session::AutomaticRolloverStep::Rollover(
                            video_session::RolloverStep::Control(step),
                        ),
                    ),
                )) => control(step, &mut event).map(|_| None),
                video_retained_provision::Step::Session(video_provision::Step::Managed(
                    video_session::ManagedStep::Resumed(receipt),
                )) => {
                    println!(
                        "trial_owned_video_rollover=resumed outcome={:?}",
                        receipt.outcome
                    );
                    Ok(None)
                }
                _ => Err("retained video session requires reconciliation"),
            },
            Phase::Managed {
                session,
                custody,
                renewal,
            } => match Box::pin(session.step(
                owner,
                &operation,
                poll_wait,
                task,
                cx,
                clock,
                video_admission,
                source_admission,
                &BudgetVector::ZERO,
            ))
            .await
            {
                video_provision::Step::SupplyPlanned(identity) => {
                    println!(
                        "trial_owned_video_supply=planned generation={}",
                        identity.generation
                    );
                    Ok(None)
                }
                video_provision::Step::SupplyStarted => Ok(None),
                video_provision::Step::SupplyInstalled(completion)
                    if completion.runtime.is_ok()
                        && completion.outcome == av_rollover_supplies::Outcome::Ready =>
                {
                    if custody.len() >= 8 {
                        Err("video supply custody capacity exhausted")
                    } else if let Some(owner) = session.take_custody() {
                        custody.push(owner);
                        println!("trial_owned_video_supply=installed custody=retained");
                        Ok(None)
                    } else {
                        Err("video supply custody missing")
                    }
                }
                video_provision::Step::PlanExhausted => {
                    if let Some((policy, count)) = renewal
                        .as_mut()
                        .and_then(|policy| policy.next().map(|count| (policy, count)))
                    {
                        if session.extend_plan(count).is_err() {
                            Err("video managed plan renewal refused")
                        } else {
                            policy.committed(count);
                            println!(
                                "trial_owned_video_supply=plan_renewed count={count} remaining={}",
                                policy.remaining
                            );
                            Ok(None)
                        }
                    } else {
                        println!("trial_owned_video_supply=plan_exhausted");
                        Ok(None)
                    }
                }
                video_provision::Step::Managed(
                    video_session::ManagedStep::Session(step)
                    | video_session::ManagedStep::SuppliesRequired(step),
                ) => session_step(step, &mut event, true),
                video_provision::Step::Managed(video_session::ManagedStep::RolloverBeginning) => {
                    println!("trial_owned_video_rollover=beginning");
                    Ok(None)
                }
                video_provision::Step::Managed(video_session::ManagedStep::Rollover(
                    video_session::AutomaticRolloverStep::Started,
                )) => Ok(None),
                video_provision::Step::Managed(video_session::ManagedStep::Rollover(
                    video_session::AutomaticRolloverStep::Rollover(
                        video_session::RolloverStep::PreflightReady,
                    ),
                )) => Ok(None),
                video_provision::Step::Managed(video_session::ManagedStep::Rollover(
                    video_session::AutomaticRolloverStep::Rollover(
                        video_session::RolloverStep::Control(step),
                    ),
                )) => control(step, &mut event).map(|_| None),
                video_provision::Step::Managed(video_session::ManagedStep::Resumed(receipt)) => {
                    println!(
                        "trial_owned_video_rollover=resumed outcome={:?}",
                        receipt.outcome
                    );
                    Ok(None)
                }
                _ => Err("managed video session requires reconciliation"),
            },
        };
        let publication = match outcome {
            Ok(publication) => publication,
            Err(reason) => break Err(reason),
        };
        if let Some(publication) = publication {
            let pin = publication.pin;
            if pins
                .iter()
                .any(|prior: &archive::UnknownTimePin| prior.root == pin.root)
            {
                break Err("duplicate video root requires reconciliation");
            }
            pins.push(pin);
            println!(
                "trial_stage=owned_segment_published count={} kind=VideoOnly",
                pins.len()
            );
            if let Some(color) = still_color.filter(|_| live_still.is_none()) {
                let limits = fss_codec_jpeg_encode::EncodeLimits::default();
                let mut worker = match video_still_worker::Worker::new(video_still_worker::Parts {
                    source: video_still_worker::Source::Published(publication.into_still_source()),
                    read: access.clone(),
                    color,
                    quality: 90,
                    limits,
                    pixel_work_limit: limits.maximum_pixels as u64,
                    encode_work_limit: limits.work_bound(fss_codec_jpeg_encode::PixelFormat::Rgb),
                }) {
                    Ok(worker) => worker,
                    Err(_) => break Err("live still worker configuration refused"),
                };
                if worker
                    .start(task, cx, clock, resource, &BudgetVector::ZERO)
                    .is_err()
                {
                    break Err("live still worker admission refused");
                }
                live_still = Some((worker, pin));
                println!("trial_owned_live_still=started source=confirmed_publication");
            }
        }
        if let Some(frame) = event {
            if !frame.response_expected() {
                println!(
                    "trial_owned_event=observed source_bytes_omitted={} identity=network_claim",
                    frame.source().len()
                );
            } else if !reply_events {
                break Err("event reply required; enable the authorized reply option");
            } else {
                let operation = match run_id.owned_event(count) {
                    Ok(value) => value,
                    Err(_) => break Err("event operation identity refused"),
                };
                let Some(wall) = owner.wall.observe() else {
                    break Err("event reply clock unavailable");
                };
                let Some(mut handle) = phase.as_mut().and_then(Phase::control) else {
                    break Err("event reply control unavailable");
                };
                let mut trace = match handle.prepare_journaled_event_reply(
                    owner,
                    &frame,
                    &wall.timestamp,
                    &operation,
                ) {
                    Ok(trace) => trace,
                    Err(_) => break Err("event reply preparation requires reconciliation"),
                };
                if Box::pin(handle.dispatch_event_reply_tracked(
                    owner,
                    management,
                    wait.min(Duration::from_secs(5)),
                    &mut trace,
                ))
                .await
                .is_err()
                {
                    break Err("event reply trace unavailable; reconcile journal");
                }
                match trace.take_outcome() {
                    Some(Ok(fss_reference::unifi_direct::receive::ManagementWrite::Written {
                        permit,
                    })) if permit.journal_backed() => println!(
                        "trial_owned_event_reply=written effects_require_reconciliation=true source_bytes_omitted={}",
                        frame.source().len()
                    ),
                    _ => break Err("event reply incomplete; reconcile journal"),
                }
            }
        }
        if transition {
            let Some(Phase::Bootstrap(bootstrap)) = phase.take() else {
                break Err("video bootstrap phase changed");
            };
            match bootstrap.into_session() {
                Ok(session) => {
                    phase = if let Some(bootstrap) = retained_bootstrap.take() {
                        let mut driver =
                            match video_retained_provision::RetainedSession::with_bootstrap(
                                video_session::ManagedSession::new(session),
                                bootstrap,
                            ) {
                                Ok(driver) => driver,
                                Err(_) => break Err("retained video bootstrap handoff refused"),
                            };
                        if let Some(additional) = auto_retained_generations {
                            if !driver.enable_creator_observation(additional) {
                                break Err("automatic retained video policy refused");
                            }
                            println!(
                                "trial_owned_video_automatic_generations={additional} trust=local"
                            );
                        }
                        println!("trial_owned_video_driver=retained pin_independence=unverified");
                        Some(Phase::Retained {
                            session: Box::new(driver),
                            custody: Vec::new(),
                            renewal: renewal_batch.map(|batch| Renewal {
                                batch,
                                remaining: 8 - (auto_retained_generations.unwrap_or(7) + 1),
                            }),
                        })
                    } else if let Some(mut generation) = plan.take() {
                        let (identity, worker) = match generation.next_worker() {
                            Ok(Some(value)) => value,
                            Ok(None) => break Err("video generation unavailable"),
                            Err(_) => break Err("video generation refused"),
                        };
                        let mut driver = video_provision::ProvisioningSession::new(
                            video_session::ManagedSession::new(session),
                            worker,
                        );
                        if driver.set_plan(generation).is_err() {
                            break Err("video generation plan unavailable");
                        }
                        println!(
                            "trial_owned_video_driver=managed first_generation={} pin_independence=unverified",
                            identity.generation
                        );
                        Some(Phase::Managed {
                            session: Box::new(driver),
                            custody: Vec::new(),
                            renewal: renewal_batch.map(|batch| Renewal {
                                batch,
                                remaining: 8 - batch,
                            }),
                        })
                    } else {
                        Some(Phase::Recording(Box::new(session)))
                    };
                    println!("trial_owned_video_bootstrap=ready");
                }
                Err(_) => break Err("video bootstrap handoff requires reconciliation"),
            }
        }
        if still_completion.is_none() {
            if let Some((worker, pin)) = live_still.as_mut() {
                let completion = poll_fn(|context| {
                    let mut join = pin!(worker.join());
                    Poll::Ready(match join.as_mut().poll(context) {
                        Poll::Ready(completion) => completion,
                        Poll::Pending => None,
                    })
                })
                .await;
                if let Some(completion) = completion {
                    let dimensions = match &completion.outcome {
                        video_still_worker::Outcome::Finished(Ok(still))
                            if completion.runtime.is_ok()
                                && still.pin() == *pin
                                && still.claimed_source() == key
                                && still.provenance()
                                    == video_still::Provenance::ConfirmedPublication =>
                        {
                            Some(still.still().jpeg().receipt().dimensions)
                        }
                        _ => None,
                    };
                    let export = match (&completion.outcome, still_export_path) {
                        (video_still_worker::Outcome::Finished(Ok(still)), Some(path))
                            if dimensions.is_some() =>
                        {
                            Some(still_export::start(
                                task,
                                cx,
                                clock,
                                resource,
                                path,
                                still,
                                access.clone(),
                            ))
                        }
                        _ => None,
                    };
                    still_completion = Some(completion);
                    let Some(dimensions) = dimensions else {
                        break Err("live still worker requires reconciliation");
                    };
                    if let Some(export) = export {
                        match export {
                            Ok(worker) => {
                                export_worker = Some(worker);
                                println!("trial_owned_still_export=started");
                            }
                            Err(reason) => break Err(reason),
                        }
                    }
                    println!(
                        "trial_owned_live_still=ready width={} height={} source=confirmed_publication capture_bounds=unknown export=none",
                        dimensions[0], dimensions[1]
                    );
                }
            }
        }
        if let Some(worker) = export_worker.as_mut() {
            let receipt = poll_fn(|context| {
                let mut join = pin!(worker.join());
                Poll::Ready(match join.as_mut().poll(context) {
                    Poll::Ready(receipt) => receipt,
                    Poll::Pending => None,
                })
            })
            .await;
            if let Some(receipt) = receipt {
                export_worker.take();
                if let Err(reason) = export_completion(receipt, false) {
                    break Err(reason);
                }
                export_published = true;
            }
        }
        if pins.len() == segment_limit {
            break Ok(());
        }
    };
    // The capture loop has a single exit. Drain the still before any of the
    // phase-specific shutdown paths can return or relinquish source custody.
    if let Some((mut worker, pin)) = live_still.take() {
        let completed_before_stop = still_completion.is_some();
        if result.is_err() && !completed_before_stop {
            worker.abort();
        }
        let completion = match still_completion.take() {
            Some(completion) => Some(completion),
            None => worker.join().await,
        };
        let retirement = worker.retire();
        match (completion, retirement) {
            (Some(completion), Ok(retirement)) => {
                let original = retirement.parts.source.into_published();
                let source_returned = original.as_ref().is_ok_and(|source| source.pin == pin);
                if !source_returned || retirement.report.is_some() {
                    result = Err("live still custody requires reconciliation");
                } else if result.is_ok() {
                    if completion.runtime.is_err() {
                        result = Err("live still runtime requires reconciliation");
                    } else {
                        match completion.outcome {
                            video_still_worker::Outcome::Finished(Ok(still))
                                if !retirement.fenced
                                    && archive::ReadAuthority::permits(
                                        access.as_ref(),
                                        pin.retention,
                                        pin.root,
                                    )
                                    && still.pin() == pin
                                    && still.claimed_source() == key
                                    && still.provenance()
                                        == video_still::Provenance::ConfirmedPublication =>
                            {
                                let dimensions = still.still().jpeg().receipt().dimensions;
                                if let Some(path) = still_export_path
                                    .filter(|_| export_worker.is_none() && !export_published)
                                {
                                    match still_export::start(
                                        task,
                                        cx,
                                        clock,
                                        resource,
                                        path,
                                        &still,
                                        access.clone(),
                                    ) {
                                        Ok(worker) => {
                                            export_worker = Some(worker);
                                            println!("trial_owned_still_export=started");
                                        }
                                        Err(reason) => result = Err(reason),
                                    }
                                }
                                println!(
                                    "trial_owned_live_still=complete width={} height={} source=confirmed_publication capture_bounds=unknown export={}",
                                    dimensions[0],
                                    dimensions[1],
                                    if still_export_path.is_some() {
                                        "requested"
                                    } else {
                                        "none"
                                    }
                                );
                            }
                            _ => result = Err("live still worker requires reconciliation"),
                        }
                    }
                } else {
                    let known = matches!(
                        &completion.outcome,
                        video_still_worker::Outcome::NotStarted
                            | video_still_worker::Outcome::Finished(Err(_))
                    ) || (completed_before_stop
                        && matches!(
                            &completion.outcome,
                            video_still_worker::Outcome::Finished(Ok(_))
                        ));
                    println!(
                        "trial_owned_live_still=drained_after_stop source_returned=true runtime_ok={} completed_before_stop={completed_before_stop} outcome_known={known}",
                        completion.runtime.is_ok()
                    );
                    if !known {
                        result = Err("live still outcome requires reconciliation");
                    }
                }
            }
            _ => result = Err("live still worker did not drain"),
        }
    }
    if let Some(mut worker) = export_worker.take() {
        let stopping = result.is_err();
        if stopping {
            worker.abort();
        }
        match worker.join().await {
            Some(receipt) => match export_completion(receipt, stopping) {
                Ok(()) => {
                    if !stopping {
                        export_published = true;
                    }
                }
                Err(reason) => result = Err(reason),
            },
            None => result = Err("still export worker did not drain"),
        }
    }
    if result.is_ok() && still_export_path.is_some() && !export_published {
        result = Err("still export was not published");
    }
    if let Err(reason) = result {
        eprintln!("trial_owned_capture_stop reason={reason}");
    }
    let mut supply_custody = Vec::new();
    let mut reservation_custody = None;
    let mut bootstrap_custody = None;
    let mut retained_unresolved = None;
    let final_phase = match phase.take().ok_or("video phase unavailable on shutdown")? {
        Phase::Retained {
            mut session,
            custody,
            renewal: _,
        } => {
            session.abort();
            let _ = session.join_bootstrap().await;
            let _ = session.join_reservation().await;
            let _ = session.join_supply().await;
            let _ = session.join_rollover().await;
            let operation = run_id.owned_step(count.saturating_add(1))?;
            let mut drained = false;
            for _ in 0..3 {
                match session
                    .step(
                        owner,
                        &operation,
                        Duration::from_millis(100),
                        task,
                        cx,
                        clock,
                        video_admission,
                        source_admission,
                        &BudgetVector::ZERO,
                    )
                    .await
                {
                    video_retained_provision::Step::BootstrapStopped(_)
                    | video_retained_provision::Step::ReservationStopped(_) => (),
                    video_retained_provision::Step::Aborted => {
                        drained = true;
                        break;
                    }
                    _ => return Err("retained video worker drain requires reconciliation".into()),
                }
            }
            if !drained {
                return Err("retained video workers did not drain".into());
            }
            reservation_custody = session.take_reservation();
            bootstrap_custody = session.take_bootstrap();
            let owners = session.into_parts();
            let outer_unresolved = owners.bootstrap.is_some()
                || owners.bootstrap_started
                || owners.bootstrap_completion.is_some()
                || owners.bootstrap_retirement.is_some()
                || owners.reservation.is_some()
                || owners.started
                || owners.completion.is_some()
                || owners.retirement.is_some()
                || owners
                    .automatic
                    .as_ref()
                    .is_some_and(|state| state.stopped || !state.custody.is_empty());
            let inner = owners.inner.into_parts();
            let inner_unresolved = inner.worker.is_some()
                || inner.started
                || inner.completion.is_some()
                || inner.ready.is_some()
                || inner.failed.is_some()
                || inner.custody.is_some()
                || inner.plan.is_some();
            let pending = reservation_custody
                .as_ref()
                .and_then(|value| value.inputs.plan.pending())
                .is_some();
            let observed = reservation_custody.as_ref().is_some_and(|value| {
                matches!(
                    &value.outcome,
                    Some(av_rollover_generation::ReservationOutcome::Reconciled(_))
                ) && value.inputs.plan.pending().is_none()
            });
            let expected_outcome = if auto_retained_generations.is_some() {
                observed
            } else {
                pending
            };
            let bootstrap_unresolved = !expected_outcome
                || bootstrap_custody.as_ref().is_none_or(|value| {
                    value.fenced
                        || value.outcome != Some(av_rollover_generation::BootstrapOutcome::Ready)
                });
            if outer_unresolved || inner_unresolved || bootstrap_unresolved {
                eprintln!("trial_owned_video_generation_shutdown=reconciliation_required");
                result = Err("retained video storage requires reconciliation");
            } else {
                if observed {
                    println!(
                        "trial_owned_video_generation_shutdown reservation=locally_observed restart_recovery=unverified"
                    );
                } else {
                    println!(
                        "trial_owned_video_generation_shutdown reservation=pending restart_recovery=unverified"
                    );
                }
            }
            let parts = inner.managed.into_parts();
            retained_unresolved = Some((
                owners.bootstrap,
                owners.bootstrap_completion,
                owners.bootstrap_retirement,
                owners.reservation,
                owners.completion,
                owners.retirement,
                owners.automatic,
                inner.worker,
                inner.completion,
                inner.ready,
                inner.failed,
                inner.custody,
                inner.plan,
                parts.supplies,
            ));
            supply_custody = custody;
            match parts.owner {
                Some(video_session::ManagedOwner::Recording(session)) => Phase::Recording(session),
                Some(video_session::ManagedOwner::Rollover(rollover)) => {
                    result = Err("retained video transition requires reconciliation");
                    let parts = rollover
                        .into_rollover()
                        .into_parts()
                        .map_err(|_| "retained video transition still running")?;
                    Phase::StoppedRollover(Box::new(parts))
                }
                Some(video_session::ManagedOwner::Halted(rollover)) => {
                    result = Err("retained video transition requires reconciliation");
                    let parts = rollover
                        .into_parts()
                        .map_err(|_| "retained video transition still running")?;
                    Phase::StoppedRollover(Box::new(parts))
                }
                None => return Err("retained video session owner missing".into()),
            }
        }
        Phase::Managed {
            mut session,
            custody,
            ..
        } => {
            session.abort();
            let _ = session.join_supply().await;
            let _ = session.join_rollover().await;
            let operation = run_id.owned_step(count.saturating_add(1))?;
            match session
                .step(
                    owner,
                    &operation,
                    Duration::from_millis(100),
                    task,
                    cx,
                    clock,
                    video_admission,
                    source_admission,
                    &BudgetVector::ZERO,
                )
                .await
            {
                video_provision::Step::Aborted => (),
                _ => return Err("video supply drain requires reconciliation".into()),
            }
            let owners = session.into_parts();
            if owners.started || owners.failed.is_some() || owners.custody.is_some() {
                return Err("video supply ownership requires reconciliation".into());
            }
            if let Some(worker) = owners.worker {
                let retired = worker
                    .retire()
                    .map_err(|_| "video supply worker still running")?;
                if retired.outcome.is_some() || retired.root_created || retired.pin_root_created {
                    return Err("video supply worker requires reconciliation".into());
                }
            }
            if owners.completion.is_some() != owners.ready.is_some() {
                return Err("video supply completion ownership mismatch".into());
            }
            let parts = owners.managed.into_parts();
            supply_custody = custody;
            println!(
                "trial_owned_video_supply_shutdown installed={} uninstalled={} restart_recovery=unverified",
                supply_custody.len(),
                owners.ready.is_some()
            );
            match parts.owner {
                Some(video_session::ManagedOwner::Recording(session)) => Phase::Recording(session),
                _ => return Err("video transition owners require reconciliation".into()),
            }
        }
        other => other,
    };
    match final_phase {
        Phase::Bootstrap(mut bootstrap) => {
            bootstrap.abort();
            let completion = bootstrap
                .join_source()
                .await
                .map(source_completion)
                .transpose();
            let parts = bootstrap
                .into_parts()
                .map_err(|_| "bootstrap source still running")?;
            let media = parts.supervisor.retire().media;
            let resource = root.to_str().ok_or("archive path is not UTF-8")?;
            let tail = Box::pin(archive_tail(
                parts.source,
                media,
                key,
                camera_claim,
                task,
                cx,
                clock,
                access.as_ref(),
                resource,
                wait,
            ))
            .await;
            if let Some(video) = parts.video {
                let video = video
                    .retire()
                    .map_err(|_| "bootstrap video retirement refused")?;
                if video.fenced || video.report.is_some() || video.parts.sink.has_pending() {
                    return Err("bootstrap video custody requires reconciliation".into());
                }
            }
            if tail.is_err() || completion.is_err() {
                return Err("bootstrap source custody requires reconciliation".into());
            }
        }
        Phase::Recording(mut session) => {
            session.abort();
            let source_result = session
                .join_source()
                .await
                .map(source_completion)
                .transpose();
            let video_result = session.join_video().await.map(video_completion).transpose();
            let parts = session
                .into_parts()
                .map_err(|_| "video workers still running")?;
            let resource = root.to_str().ok_or("archive path is not UTF-8")?;
            let (tail, video, controller, time_sync) = match parts.prepare_retirement() {
                Ok(retired) => {
                    let tail = Box::pin(archive_prepared_tail(
                        retired.tail,
                        key,
                        camera_claim,
                        task,
                        cx,
                        clock,
                        access.as_ref(),
                        resource,
                        wait,
                    ))
                    .await;
                    (tail, retired.video, retired.controller, retired.time_sync)
                }
                Err(video_session::RetirementRefusal::NotDrained(parts)) => {
                    // Preserve the previous tail-drain behavior for a fenced or
                    // unavailable video owner; it still requires reconciliation.
                    let retired = parts.supervisor.retire();
                    let tail = Box::pin(archive_tail(
                        parts.source,
                        retired.media,
                        key,
                        camera_claim,
                        task,
                        cx,
                        clock,
                        access.as_ref(),
                        resource,
                        wait,
                    ))
                    .await;
                    (tail, parts.video, retired.controller, retired.time_sync)
                }
                Err(video_session::RetirementRefusal::TailPlan { .. })
                | Err(video_session::RetirementRefusal::TailDriver { .. }) => {
                    eprintln!(
                        "trial_owned_video_shutdown=tail_preparation_refused source_not_persisted=true"
                    );
                    return Err("video source retirement requires reconciliation".into());
                }
            };
            let controller_unresolved =
                controller_retirement_unresolved(&controller, time_sync.is_some());
            println!(
                "trial_owned_controller_retirement=observed reconciliation_required={controller_unresolved} remote_effects=unverified"
            );
            let video = video.retire().map_err(|_| "video retirement refused")?;
            if tail.is_err()
                || controller_unresolved
                || video.fenced
                || video.report.is_some()
                || video.parts.sink.has_pending()
                || source_result.is_err()
                || video_result.is_err()
                || video_result.ok().flatten().is_some()
            {
                return Err("video archive custody requires reconciliation".into());
            }
            let mut rollover_custody = video.rollover_custody;
            let mut video = video.parts;
            if result.is_ok() {
                let resource = root.to_str().ok_or("archive path is not UTF-8")?;
                task.checkpoint_for(
                    RuntimeGrant::ReadMedia,
                    resource,
                    clock.now()?,
                    &BudgetVector::ZERO,
                )?;
                let snapshot = video.journal.anchor();
                if video.keeper.target() != snapshot {
                    return Err("video journal keeper is not at the current prefix".into());
                }
                let page = video
                    .journal
                    .confirmed_page(snapshot, 0, 128, &video.replay)?;
                let history_len = page.entries.len();
                if page.has_more
                    || page.pending.is_some()
                    || history_len == 0
                    || history_len > pins.len()
                    || !pins[pins.len() - history_len..]
                        .iter()
                        .copied()
                        .eq(page.entries.iter().map(|entry| entry.pin))
                {
                    return Err("video current-generation history mismatch".into());
                }
                println!(
                    "trial_owned_journal_readback confirmed={} scope=current_generation earlier_generations=not_enumerated",
                    history_len
                );
                if let Some(custody) = rollover_custody.as_mut() {
                    let history = custody.history(&video.journal, &video.keeper, &video.replay)?;
                    let page = history.page(None, 128, &video.replay)?;
                    if page.next.is_some()
                        || page.entries.len() != pins.len()
                        || !pins
                            .iter()
                            .copied()
                            .eq(page.entries.iter().map(|entry| entry.pin))
                    {
                        return Err("video rollover lineage history mismatch".into());
                    }
                    println!(
                        "trial_owned_lineage_readback generations={} confirmed={} boundary_duplicates=excluded",
                        history.generation_count(),
                        page.entries.len()
                    );
                }
                let mut samples = 0usize;
                let mut first = None;
                let mut first_samples = None;
                for pin in &pins {
                    task.checkpoint_for(
                        RuntimeGrant::ReadMedia,
                        resource,
                        clock.now()?,
                        &BudgetVector::ZERO,
                    )?;
                    let mut clip = archive::read_unknown_time_video_clip(
                        &mut video.deployment,
                        *pin,
                        access.as_ref(),
                        archive::Limits::default(),
                        &mut fss_geometry::WorkBudget::new(4_000_000_000),
                        &video.replay,
                    )?;
                    if clip.claimed_source() != key || clip.samples() == 0 {
                        return Err("video archive source mismatch".into());
                    }
                    if first_samples.is_none() {
                        if let Some(color) = still_color {
                            let limits = fss_codec_jpeg_encode::EncodeLimits::default();
                            let mut worker =
                                video_still_worker::Worker::new(video_still_worker::Parts {
                                    source: video_still_worker::Source::Recovered(clip),
                                    read: access.clone(),
                                    color,
                                    quality: 90,
                                    limits,
                                    pixel_work_limit: limits.maximum_pixels as u64,
                                    encode_work_limit: limits
                                        .work_bound(fss_codec_jpeg_encode::PixelFormat::Rgb),
                                })
                                .map_err(|_| "archive still worker configuration refused")?;
                            worker
                                .start(task, cx, clock, resource, &BudgetVector::ZERO)
                                .map_err(|_| "archive still worker admission refused")?;
                            let completion = worker
                                .join()
                                .await
                                .ok_or("archive still worker did not drain")?;
                            let retirement = worker
                                .retire()
                                .map_err(|_| "archive still worker retained running work")?;
                            if completion.runtime.is_err()
                                || retirement.fenced
                                || retirement.report.is_some()
                            {
                                return Err("archive still worker requires reconciliation".into());
                            }
                            let still = match completion.outcome {
                                video_still_worker::Outcome::Finished(Ok(still)) => still,
                                _ => return Err("archive still worker refused source".into()),
                            };
                            if still.pin() != *pin || still.claimed_source() != key {
                                return Err("archive still source binding mismatch".into());
                            }
                            let dimensions = still.still().jpeg().receipt().dimensions;
                            println!(
                                "trial_owned_archive_still=complete width={} height={} color={:?} root_binding=checked capture_bounds=unknown export=none",
                                dimensions[0], dimensions[1], color
                            );
                            clip = retirement
                                .parts
                                .source
                                .into_recovered()
                                .map_err(|_| "archive still source type changed")?;
                        }
                    }
                    samples = samples
                        .checked_add(clip.samples())
                        .ok_or("video sample count overflow")?;
                    if first_samples.is_none() {
                        first_samples = Some(clip.samples());
                    }
                    if decode_owned && first.is_none() {
                        let mut bytes = Vec::new();
                        bytes.try_reserve_exact(clip.bytes().len())?;
                        bytes.extend_from_slice(clip.bytes());
                        first = Some(bytes);
                    }
                }
                println!(
                    "trial_owned_readback segments={} video_samples={samples} audio_frames=0 capture_bounds=unknown",
                    pins.len()
                );
                if decode_owned {
                    task.checkpoint_for(
                        RuntimeGrant::MediaDecode,
                        resource,
                        clock.now()?,
                        &BudgetVector::ZERO,
                    )?;
                    let media = if pins.len() > 1 {
                        // Overlap one fragment so every adjacent boundary is verified,
                        // while keeping each sequence read and its working set bounded.
                        let mut start = 0usize;
                        let mut windows = 0usize;
                        let mut first_window = None;
                        loop {
                            let end = (start + 8).min(pins.len());
                            task.checkpoint_for(
                                RuntimeGrant::ReadMedia,
                                resource,
                                clock.now()?,
                                &BudgetVector::ZERO,
                            )?;
                            let sequence = archive::read_unknown_time_video_sequence(
                                &mut video.deployment,
                                &pins[start..end],
                                access.as_ref(),
                                archive::Limits::default(),
                                archive::AvSequenceLimits {
                                    max_fragments: 8,
                                    max_bytes: 128 * 1024 * 1024,
                                },
                                &mut fss_geometry::WorkBudget::new(100_000_000_000),
                                &video.replay,
                            )?;
                            if sequence.parts().len() != end - start {
                                return Err("video archive sequence incomplete".into());
                            }
                            if first_window.is_none() {
                                first_window = Some(sequence.into_bytes());
                            }
                            windows += 1;
                            if end == pins.len() {
                                break;
                            }
                            start = end - 1;
                        }
                        println!(
                            "trial_owned_sequence segments={} capture_bounds=unknown",
                            pins.len()
                        );
                        println!(
                            "trial_owned_sequence_windows count={windows} max_fragments=8 overlap=1"
                        );
                        first_window.ok_or("archive video sequence missing")?
                    } else {
                        first.ok_or("archive video decode missing")?
                    };
                    let movie = fss_container::demux::AvcMp4::parse_inband(
                        &media,
                        None,
                        fss_container::demux::DemuxLimits::default(),
                    )?;
                    if pins.len() > 1 {
                        let next = first_samples.ok_or("first video sample count missing")?;
                        if next == 0 || next >= movie.samples().len() {
                            return Err("cross-fragment sample missing".into());
                        }
                        // Decode the complete bounded prefix through the first sample of the
                        // second fragment. Drain pictures as they appear rather than retaining
                        // an entire GOP of decoded full-resolution images in memory.
                        let count = next.checked_add(1).ok_or("video sample count overflow")?;
                        if count > 512 {
                            return Err("cross-fragment decode sample limit exceeded".into());
                        }
                        let annex = movie.annex_b(0, count)?;
                        let mut decoder =
                            fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                        let mut dimensions = None;
                        let mut decoded = 0usize;
                        let mut observe = |frame: fss_codec_h264::Picture| -> Result<(), Box<dyn std::error::Error>> {
                            let current = (frame.width(), frame.height());
                            if dimensions.is_some_and(|old| old != current) {
                                return Err("fragment dimensions changed".into());
                            }
                            dimensions = Some(current);
                            decoded = decoded.checked_add(1).ok_or("decoded frame count overflow")?;
                            Ok(())
                        };
                        for nal in fss_codec_h264::annex_b_nal_units(annex.bytes()) {
                            task.checkpoint_for(
                                RuntimeGrant::MediaDecode,
                                resource,
                                clock.now()?,
                                &BudgetVector::ZERO,
                            )?;
                            if let Some(frame) = decoder.decode_nal(nal)? {
                                observe(frame)?;
                            }
                            while let Some(frame) = decoder.next_output() {
                                observe(frame)?;
                            }
                        }
                        for frame in decoder.finish()? {
                            observe(frame)?;
                        }
                        if decoded != count {
                            return Err("cross-fragment decoded frame count mismatch".into());
                        }
                        let (width, height) = dimensions.ok_or("fragment dimensions missing")?;
                        println!(
                            "trial_owned_decoded width={width} height={height} frames={decoded} samples={count} decode_mode=streamed_prefix capture_bounds=unknown"
                        );
                    } else {
                        let annex = movie.annex_b(0, movie.samples().len().min(3))?;
                        let mut decoder =
                            fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                        let mut frames = decoder.decode_annex_b(annex.bytes())?;
                        frames.extend(decoder.finish()?);
                        let frame = frames.first().ok_or("archive video did not decode")?;
                        println!(
                            "trial_owned_decoded width={} height={} frames={} capture_bounds=unknown",
                            frame.width(),
                            frame.height(),
                            frames.len()
                        );
                    }
                }
            }
        }
        Phase::StoppedRollover(parts) => {
            let parts = *parts;
            let media = parts.supervisor.retire().media;
            let resource = root.to_str().ok_or("archive path is not UTF-8")?;
            let tail = Box::pin(archive_tail(
                parts.source,
                media,
                key,
                camera_claim,
                task,
                cx,
                clock,
                access.as_ref(),
                resource,
                wait,
            ))
            .await;
            drop((parts.state, parts.supplies));
            if tail.is_err() {
                return Err("stopped rollover source custody requires reconciliation".into());
            }
        }
        Phase::Managed { .. } | Phase::Retained { .. } => {
            return Err("video managed phase did not drain".into());
        }
    }
    drop((
        supply_custody,
        reservation_custody,
        bootstrap_custody,
        retained_unresolved,
    ));
    result.map(|()| pins.len()).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::controller_retirement_unresolved;
    use fss_reference::unifi_direct::{
        Controller, Identity, MessageKind, Phase, RejectedMessage, VideoChannel,
    };

    #[test]
    fn controller_retirement_keeps_unresolved_facts_visible()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity = Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?;
        let mut baseline = Controller::new(identity, 1)?.close();
        baseline.previous_phase = Phase::AgreementReplyObserved;
        assert!(!controller_retirement_unresolved(&baseline, false));
        assert!(controller_retirement_unresolved(&baseline, true));
        let mut cases = [baseline; 17];
        cases[0].previous_phase = Phase::Indeterminate;
        cases[1].prepared = Some((7, MessageKind::HelloReply));
        cases[2].agreement_id = Some(7);
        cases[3].hello_request_id = Some(7);
        cases[4].time_sync_request_id = Some(7);
        cases[5].stream_request = Some((7, VideoChannel::Video1));
        cases[6].stream_request_kind = Some(MessageKind::StartStream(VideoChannel::Video1));
        cases[7].motion_request = Some((7, true));
        cases[8].event_reply = Some((7, fss_core::ContentDigest::sha256(b"fixture")));
        cases[9].event_reply_is_startup_request = true;
        cases[10].rejected_message = Some(RejectedMessage::Hello);
        cases[11].unhandled_requests.pre_hello = 1;
        cases[12].previous_phase = Phase::AwaitHello;
        cases[13].previous_phase = Phase::HelloObserved;
        cases[14].previous_phase = Phase::AwaitAgreementPreparation;
        cases[15].previous_phase = Phase::AwaitAgreementReply;
        cases[16].previous_phase = Phase::Closed;
        for (index, case) in cases.iter().enumerate() {
            assert!(
                controller_retirement_unresolved(case, false),
                "case {index}"
            );
        }
        Ok(())
    }
}
