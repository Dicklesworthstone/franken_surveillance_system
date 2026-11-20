#![forbid(unsafe_code)]
//! Bounded laboratory driver for a checkpointed, reconnecting A/V recorder.

use std::{error::Error, time::Duration};
use asupersync::Cx;
use fss_core::BudgetVector;
use fss_runtime::execution::TaskCx;
use fss_reference::unifi_direct::{
    archive, av_recovered_startup, av_worker, listener, metered::MeteredClock, pipeline,
    retirement_source, source_coordinator::ArchiveAdmission, source_worker,
    http_stream::{media_av_archive as av_archive, media_av_managed as managed,
        media_av_reconnect as reconnect, media_av_recovery as recovery,
        media_av_startup as startup, media_av_supervisor as supervisor},
};
use super::stopped;

/// Original management, events and old source boundaries remain caller-owned.
pub(super) struct Custody {
    pub manager: managed::Parts,
    pub recovery: Box<recovery::Recovery>,
    pub receipts: recovery::DrainReceipts,
    pub report: recovery::DrainReport,
    pub events: Vec<supervisor::Step>,
    pub boundaries: Vec<Box<supervisor::Boundary>>,
}

enum Decision { Continue, Boundary, Retry, Complete, Stop(&'static str) }

/// Only a stop whose event still leaves all unconsumed bytes in the pipeline
/// is eligible for source-tail retirement. Other events may own separate
/// unaccepted records and must remain untouched for reconciliation.
fn has_retirable_tail(event: &supervisor::Step) -> bool {
    matches!(event,
        supervisor::Step::Recording(step)
            if matches!(&**step,
                managed::Step::Recording(av_archive::AllowanceStep::Recording(event))
                    if event.has_retirable_tail()))
}

fn report_source_failure(done: &source_worker::Completion) {
    use source_worker::{Outcome, Publication, Refusal};
    let reason = if done.runtime.is_err() { "runtime" } else { match &done.outcome {
        Outcome::NotStarted => "not_started",
        Outcome::Panicked => "panicked",
        Outcome::Indeterminate => "indeterminate",
        Outcome::Publication(Publication::Published { .. }) => "published",
        Outcome::Publication(Publication::Refused { reason, .. }) => match reason {
            Refusal::Preparation(_) => "preparation",
            Refusal::BatchPreparation(_) => "batch_preparation",
            Refusal::Work => "work",
            Refusal::Candidate => "candidate",
            Refusal::RootCapacity { .. } => "root_capacity_before_intent",
            Refusal::BeforePublication(av_worker::FailureReason::JournalCapacity) => "journal_capacity_before",
            Refusal::Archive(av_worker::FailureReason::JournalCapacity) => "journal_capacity_archive",
            Refusal::BeforePublication(_) => "before_publication",
            Refusal::Archive(_) => "archive",
            Refusal::AfterPublication { .. } => "after_publication",
        },
    }};
    eprintln!("trial_http_av_supervised_source_stop={reason}");
}

fn decision(event: &supervisor::Step, pins: &mut Vec<archive::UnknownTimePin>, target: usize) -> Decision {
    use av_archive::{AllowanceStep, Offer, Step as A};
    use managed::Step as M;
    use supervisor::Step as S;
    match event {
        S::Recording(event) => match &**event {
            M::Planned(_) | M::CreatorStarted | M::CreatorReady | M::PlanExhausted
            | M::AwaitingSupplies(_) | M::PreflightPrepared | M::RolloverStarted
            | M::RolloverWaiting | M::PreflightReady | M::Resumed(_)
            | M::Recording(AllowanceStep::Renewed { .. }) => Decision::Continue,
            M::InterventionRequired => Decision::Stop("supervised generation intervention required"),
            M::CreatorFailed => Decision::Stop("supervised creator failed"),
            M::CreatorBindingRefused => Decision::Stop("supervised creator binding refused"),
            M::CreatorStartRefused(_) => Decision::Stop("supervised creator admission refused"),
            M::RolloverStartRefused(_) => Decision::Stop("supervised rollover admission refused"),
            M::RolloverStopped => Decision::Stop("supervised rollover stopped"),
            M::Recording(AllowanceStep::Recording(event)) => match event {
                A::Offer(Offer::Source { .. } | Offer::Buffered(_) | Offer::Segment(_))
                | A::SourceStarted | A::SourceRunning | A::AvStarted | A::AvRunning | A::Idle
                | A::Media(pipeline::Step::Progress { .. } | pipeline::Step::Eof) => Decision::Continue,
                A::SourceCompleted(done) if done.runtime.is_ok() && matches!(&done.outcome,
                    source_worker::Outcome::Publication(source_worker::Publication::Published { .. })) => Decision::Continue,
                A::SourceCompleted(done) => {
                    report_source_failure(done);
                    Decision::Stop("supervised source publication requires reconciliation")
                }
                A::MediaError(error) => {
                    match error {
                        pipeline::Error::Ingress(error) => eprintln!("trial_http_av_supervised_media_stop=ingress:{error:?}"),
                        pipeline::Error::Recording(refusal) => eprintln!("trial_http_av_supervised_media_stop=recording:{:?}", refusal.reason),
                        pipeline::Error::Stopped => eprintln!("trial_http_av_supervised_media_stop=stopped"),
                        pipeline::Error::AudioPending => eprintln!("trial_http_av_supervised_media_stop=audio_pending"),
                        pipeline::Error::Cancelled => eprintln!("trial_http_av_supervised_media_stop=cancelled"),
                    }
                    Decision::Stop("supervised media stopped")
                }
                A::AvCompleted(done) if done.runtime.is_ok() => match &done.outcome {
                    av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(value)) => {
                        pins.push(value.pin);
                        if pins.len() == target { Decision::Complete } else { Decision::Continue }
                    }
                    av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Refused {
                        reason: av_worker::FailureReason::JournalCapacity, rollover: Some(_), ..
                    }) => Decision::Continue,
                    _ => Decision::Stop("supervised A/V publication requires reconciliation"),
                },
                _ => Decision::Stop("supervised media stopped"),
            },
            _ => Decision::Stop("supervised management stopped"),
        },
        S::ReconnectStarted | S::VerificationPrepared | S::Resumed => Decision::Continue,
        S::ArchivesReused | S::BoundaryPending => Decision::Boundary,
        S::ReconnectBlocked => Decision::Retry,
        S::Reconnecting(event) => match &**event {
            reconnect::AutoStep::Tail(retirement_source::DriverStep::Offered { .. }
                | retirement_source::DriverStep::BatchOffered { .. }
                | retirement_source::DriverStep::Started | retirement_source::DriverStep::Finished)
            | reconnect::AutoStep::Accepted(_) | reconnect::AutoStep::Ready(_)
            | reconnect::AutoStep::Refused(reconnect::AutoError::Admission(
                fss_reference::unifi_direct::media_reconnect::Error::Listener(listener::Error::Deadline))) => Decision::Continue,
            reconnect::AutoStep::Tail(retirement_source::DriverStep::Completed(done))
                if done.runtime.is_ok() && matches!(&done.outcome,
                    source_worker::Outcome::Publication(source_worker::Publication::Published { .. })) => Decision::Continue,
            reconnect::AutoStep::Tail(retirement_source::DriverStep::Completed(done)) => {
                report_source_failure(done);
                Decision::Stop("supervised reconnect source requires reconciliation")
            }
            _ => Decision::Stop("supervised reconnect requires reconciliation"),
        },
        S::Verifying(event) => match &**event {
            reconnect::VerifyStep::Started | reconnect::VerifyStep::Running | reconnect::VerifyStep::Ready => Decision::Continue,
            reconnect::VerifyStep::Completed(done) if done.runtime.is_ok()
                && matches!(&done.outcome, av_recovered_startup::Outcome::Verified) => Decision::Continue,
            _ => Decision::Stop("supervised verification requires reconciliation"),
        },
        S::Starting(event) => match &**event {
            startup::Step::Retained | startup::Step::Progress | startup::Step::Idle
            | startup::Step::SourceStarted | startup::Step::SourceRunning | startup::Step::Ready
            | startup::Step::Buffered(_) | startup::Step::SourceOffered { .. } => Decision::Continue,
            startup::Step::SourceCompleted(done) if done.runtime.is_ok() && matches!(&done.outcome,
                source_worker::Outcome::Publication(source_worker::Publication::Published { .. })) => Decision::Continue,
            _ => Decision::Stop("supervised successor startup requires reconciliation"),
        },
        _ => Decision::Stop("supervised recorder requires reconciliation"),
    }
}

pub(super) async fn run<'scope, 'task, 'policy>(
    owner: Box<managed::Managed>, bound: listener::Listener<'scope, 'task, 'policy>,
    task: &'scope TaskCx<'task>, cx: &'scope Cx, clock: MeteredClock<'scope, 'task>,
    config: supervisor::Config, admission: ArchiveAdmission<'_>, target: usize,
    pins: &mut Vec<archive::UnknownTimePin>,
) -> Result<(av_archive::Driver, Custody), Box<dyn Error>> {
    let mut events = Vec::new();
    let mut boundaries = Vec::new();
    if events.try_reserve_exact(4096).is_err() || boundaries.try_reserve_exact(16).is_err()
        || pins.try_reserve(target).is_err() {
        let (owner, source, av) = super::stop_automatic(*owner).await;
        return Err(stopped("supervised event allocation refused", (owner, source, av)));
    }
    let mut supervisor = match supervisor::Supervisor::new(owner, bound, task, cx, clock, config) {
        Ok(owner) => owner,
        Err((owner, _listener)) => {
            let (owner, source, av) = super::stop_automatic(*owner).await;
            return Err(stopped("supervised owner refused", (owner, source, av)));
        }
    };
    let mut reason = "supervised decision limit reached";
    let mut completed = false;
    for _ in 0..4096 {
        if boundaries.len() == 16 { reason = "supervised boundary limit reached"; break; }
        let event = Box::pin(supervisor.step(task, cx, clock, Duration::from_secs(1),
            admission, admission, &BudgetVector::ZERO, admission)).await;
        let action = decision(&event, pins, target);
        events.push(event);
        match action {
            Decision::Continue => (),
            Decision::Boundary => match supervisor.take_boundary() {
                Some(boundary) => boundaries.push(boundary),
                None => { reason = "supervised boundary was unavailable"; break; }
            },
            Decision::Retry => if !supervisor.authorize_reconnect_retry() {
                reason = "supervised reconnect retry refused"; break;
            },
            Decision::Complete => { completed = true; break; },
            Decision::Stop(why) => { reason = why; break; },
        }
    }
    let (scope, recovery) = recovery::detach(supervisor);
    let mut drain = match recovery::Drain::begin(recovery) {
        Ok(drain) => drain,
        Err(recovery) => return Err(stopped("supervised drain requires manual recovery", (recovery, events, boundaries))),
    };
    let report = Box::pin(drain.join_available()).await;
    let (mut recovery, receipts) = match drain.finish_if_drained() {
        Ok(parts) => parts,
        Err(drain) => return Err(stopped("supervised workers remain undrained", (drain, report, events, boundaries))),
    };
    drop(scope);
    if !completed {
        let rollovers = events.iter().filter(|event| matches!(event,
            supervisor::Step::Recording(step) if matches!(&**step, managed::Step::Resumed(_)))).count();
        let verifications = events.iter().filter(|event| matches!(event,
            supervisor::Step::Verifying(step) if matches!(&**step, reconnect::VerifyStep::Completed(done)
                if done.runtime.is_ok() && matches!(&done.outcome, av_recovered_startup::Outcome::Verified)))).count();
        let timeouts = events.iter().filter(|event| matches!(event,
            supervisor::Step::Reconnecting(step) if matches!(&**step,
                reconnect::AutoStep::Refused(reconnect::AutoError::Admission(
                    fss_reference::unifi_direct::media_reconnect::Error::Listener(listener::Error::Deadline)))))).count();
        let denied = events.iter().filter(|event| matches!(event,
            supervisor::Step::Reconnecting(step) if matches!(&**step,
                reconnect::AutoStep::Refused(reconnect::AutoError::Admission(
                    fss_reference::unifi_direct::media_reconnect::Error::Listener(listener::Error::Denied)))))).count();
        eprintln!("trial_http_av_supervised_stop=drained boundaries={} effect=reconciliation_required reason={reason}", boundaries.len());
        eprintln!("trial_http_av_supervised_stopped_rollovers={rollovers} verified_reuse={verifications} published={}", pins.len());
        eprintln!("trial_http_av_supervised_listener_timeouts={timeouts} denied_peers={denied}");
        if events.last().is_some_and(has_retirable_tail) {
            match recovery.phase.take() {
                Some(recovery::Phase::Recording(owner)) => {
                    let mut manager = (*owner).into_parts();
                    match manager.owner.take() {
                        Some(managed::Owner::Recording(driver)) => match (*driver).into_parts() {
                            Ok(parts) => {
                                let tail = Box::pin(super::preserve_stopped_tail(parts, task, cx, clock, admission)).await;
                                eprintln!("trial_http_av_supervised_failure_tail=attempted effect=reconciliation_required");
                                return Err(stopped(reason, (recovery, manager, receipts, report, events, boundaries, tail)));
                            }
                            Err(driver) => manager.owner = Some(managed::Owner::Recording(Box::new(driver))),
                        },
                        other => manager.owner = other,
                    }
                    return Err(stopped(reason, (recovery, manager, receipts, report, events, boundaries)));
                }
                other => recovery.phase = other,
            }
        }
        return Err(stopped(reason, (recovery, receipts, report, events, boundaries)));
    }
    let manager = match recovery.phase.take() {
        Some(recovery::Phase::Recording(manager)) => manager,
        other => { recovery.phase = other; return Err(stopped("supervised final phase is not recording", (recovery, receipts, report, events, boundaries))); }
    };
    let mut manager = (*manager).into_parts();
    let driver = match manager.owner.take() {
        Some(managed::Owner::Recording(driver)) => driver,
        other => { manager.owner = other; return Err(stopped("supervised archive owner unavailable", (manager, recovery, receipts, report, events, boundaries))); }
    };
    let rollovers = events.iter().filter(|event| matches!(event,
        supervisor::Step::Recording(step) if matches!(&**step, managed::Step::Resumed(_)))).count();
    let verifications = events.iter().filter(|event| matches!(event,
        supervisor::Step::Verifying(step) if matches!(&**step, reconnect::VerifyStep::Completed(done)
            if done.runtime.is_ok() && matches!(&done.outcome, av_recovered_startup::Outcome::Verified)))).count();
    let (tail_batches, tail_records) = events.iter().fold((0usize, 0usize), |(batches, records), event| {
        match event {
            supervisor::Step::Reconnecting(step) => match &**step {
                reconnect::AutoStep::Tail(retirement_source::DriverStep::BatchOffered { records: count, .. }) =>
                    (batches.saturating_add(1), records.saturating_add(*count)),
                _ => (batches, records),
            },
            _ => (batches, records),
        }
    });
    println!("trial_http_av_supervised=drained boundaries={} effect=reconciliation_required", boundaries.len());
    println!("trial_http_av_supervised_rollovers={rollovers} verified_reuse={verifications}");
    println!("trial_http_av_supervised_tail_batches={tail_batches} records={tail_records}");
    Ok((*driver, Custody { manager, recovery, receipts, report, events, boundaries }))
}
