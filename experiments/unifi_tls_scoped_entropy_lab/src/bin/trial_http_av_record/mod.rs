#![forbid(unsafe_code)]
//! One bounded checkpointed HTTP A/V recording attempt; not a service.

mod supervised;

use std::{any::Any, cell::{Cell, RefCell}, error::Error, net::Ipv4Addr, path::Path, sync::Arc, time::Duration};
use asupersync::{Cx, io::{AsyncRead, AsyncWrite}, time::timeout_at};
use fss_container::{Mp4Limits, demux::{AvcMp4, DemuxLimits}, flv_avc::SourceKey};
use fss_core::{BudgetVector, ContentDigest, IdempotencyKey, OperationId, RootAuthoritySpec, RuntimeGrant};
use fss_object::{HostSpoolIo, effect_journal::EffectJournalLimits};
use fss_packet::extended_flv::{Limits as FlvLimits, stream::{Framer, SearchMode}};
use fss_reference::{DeploymentLimits, ReplayCx, unifi_direct::{
    archive, av_owned_sink, av_rollover_generation, av_worker, camera_api::SerializerAuthority, camera_http, evidence,
    handoff, http_stream::{Preconditions, media_av_archive, media_av_managed, media_av_startup}, listener,
    metered::MeteredClock, pipeline, recording, recording_storage, retirement_source, source_coordinator::ArchiveAdmission,
    source_worker,
}};
use fss_runtime::{effect::{CommitApproval, EffectCoordinator, PrepareSpec}, execution::TaskCx, lease::LeaseRegistry};
use super::{trial_http_checkpoint::{self, AvCapture, AvStartState, Prepared}, trial_http_restore,
            trial_http_record::{ObservationCheckpoint, stopped}, trial_run_id::TrialRunId};

struct Access(ContentDigest);
impl archive::RetainAuthority for Access {
    fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool { retention == self.0 }
}
impl archive::ReadAuthority for Access {
    fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool { retention == self.0 }
}

async fn stop_automatic(mut owner: media_av_managed::Managed) -> (
    media_av_managed::Managed,
    Option<source_worker::Completion>,
    Option<av_worker::UnknownTimeCompletion>,
) {
    owner.abort();
    owner.join_creator().await;
    owner.join_rollover().await;
    let (source, av) = owner.join_recording_workers().await;
    (owner, source, av)
}

struct AutomaticFailure {
    error: Box<dyn Error>,
    restore_eligible: bool,
    tail_parts: Option<media_av_archive::Parts>,
}

/// Exact owners and observations after a bounded attempt to publish the
/// stopped stream's source tail. A refusal retains every unconsumed owner.
#[must_use]
enum TailRetention {
    Refused(media_av_archive::RetirementRefusal),
    Driven {
        retired: media_av_archive::Retired,
        events: Vec<retirement_source::DriverStep>,
        joined: Option<source_worker::Completion>,
        finished: bool,
    },
}

async fn preserve_stopped_tail<'scope, 'task>(
    parts: media_av_archive::Parts, task: &'scope TaskCx<'task>, cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>, admission: ArchiveAdmission<'_>,
) -> TailRetention {
    let mut retired = match parts.prepare_retirement() {
        Ok(retired) => retired,
        Err(refusal) => {
            eprintln!("trial_http_av_tail=refused custody=retained");
            return TailRetention::Refused(refusal);
        }
    };
    let (events, joined, finished) = drive_stopped_tail(&mut retired.tail, task, cx, clock, admission).await;
    TailRetention::Driven { retired, events, joined, finished }
}

/// The collector retains its originals; successful source publications can
/// make exact copies durable without settling the camera effect.
#[must_use]
enum BootstrapTailRetention {
    Refused(media_av_startup::RetirementRefusal),
    Driven {
        retired: media_av_startup::Retired,
        events: Vec<retirement_source::DriverStep>,
        joined: Option<source_worker::Completion>,
        finished: bool,
    },
}

async fn preserve_bootstrap_tail<'scope, 'task>(
    parts: media_av_startup::Parts, task: &'scope TaskCx<'task>, cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>, admission: ArchiveAdmission<'_>,
) -> BootstrapTailRetention {
    let mut retired = match parts.prepare_tail_retirement() {
        Ok(retired) => retired,
        Err(refusal) => {
            eprintln!("trial_http_av_bootstrap_tail=refused collector=volatile custody=retained");
            return BootstrapTailRetention::Refused(refusal);
        }
    };
    let (events, joined, finished) = drive_stopped_tail(&mut retired.tail, task, cx, clock, admission).await;
    if finished {
        println!("trial_http_av_bootstrap_collector=copies_published records={} effect=reconciliation_required", retired.collector_copies);
    } else {
        eprintln!("trial_http_av_bootstrap_collector=volatile effect=reconciliation_required");
    }
    BootstrapTailRetention::Driven { retired, events, joined, finished }
}

async fn drive_stopped_tail<'scope, 'task>(
    tail: &mut retirement_source::Driver, task: &'scope TaskCx<'task>, cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>, admission: ArchiveAdmission<'_>,
) -> (Vec<retirement_source::DriverStep>, Option<source_worker::Completion>, bool) {
    let deadline = cx.now() + Duration::from_secs(90);
    if !tail.enable_batching(256, 1024 * 1024) {
        eprintln!("trial_http_av_tail=batch_admission_refused custody=retained");
        return (Vec::new(), None, false);
    }
    let mut events = Vec::new();
    let mut finished = false;
    let mut published = 0usize;
    let mut published_roots = 0usize;
    let mut offered = 0usize;
    // Each retained source takes offer, start, and completion decisions;
    // one additional decision reports that the tail is empty. The tail plan
    // is already bounded by the recorder's input limits.
    let decisions = tail.plan().len().checked_mul(3)
        .and_then(|count| count.checked_add(1)).unwrap_or(0);
    for _ in 0..decisions {
        // Reserve before polling: allocation failure must not discard the
        // returned completion or consume an unrecorded observation.
        if events.try_reserve(1).is_err() { break; }
        let event = match timeout_at(deadline, tail.step(task, cx, clock, admission)).await {
            Ok(event) => event,
            Err(_) => break,
        };
        let advance = match &event {
            retirement_source::DriverStep::Offered { .. } if offered == 0 => { offered = 1; true }
            retirement_source::DriverStep::BatchOffered { records, .. } if offered == 0 && *records > 0 => {
                offered = *records;
                true
            }
            retirement_source::DriverStep::Started => true,
            retirement_source::DriverStep::Completed(done) if done.runtime.is_ok()
                && offered > 0 && matches!(&done.outcome, source_worker::Outcome::Publication(source_worker::Publication::Published { .. })) => {
                    published += offered;
                    offered = 0;
                    published_roots += 1;
                    true
                }
            retirement_source::DriverStep::Finished => { finished = true; false }
            _ => false,
        };
        events.push(event);
        if !advance { break; }
    }
    let joined = if finished {
        if published == 0 {
            println!("trial_http_av_tail=empty capture_time=unknown");
        } else {
            println!("trial_http_av_tail=published items={published} capture_time=unknown");
        }
        println!("trial_http_av_tail_roots={published_roots}");
        None
    } else {
        tail.abort();
        let joined = tail.join().await;
        eprintln!("trial_http_av_tail=incomplete published={published} custody=retained");
        joined
    };
    (events, joined, finished)
}

/// Read back the final source ranges before declaring a supervised stop.
/// This covers only bytes already received, not unread socket data or a GOP.
#[must_use]
pub(super) struct FinalTail {
    plan: retirement_source::Plan,
    source: source_worker::Retirement,
    events: Vec<retirement_source::DriverStep>,
    pub(super) records: usize,
}

pub(super) async fn archive_final_tail<'scope, 'task>(
    retirement: pipeline::Retirement, source: source_worker::Worker,
    key: SourceKey, camera_claim: ContentDigest, retention: ContentDigest,
    task: &'scope TaskCx<'task>, cx: &'scope Cx, clock: MeteredClock<'scope, 'task>,
    admission: ArchiveAdmission<'_>,
) -> Result<FinalTail, Box<dyn Error>> {
    let plan = match retirement_source::Plan::new(retirement) {
        Ok(plan) => plan,
        Err(refusal) => return Err(stopped("final source planning refused", (source, refusal))),
    };
    let mut expected = Vec::new();
    if expected.try_reserve_exact(plan.len()).is_err() {
        return Err(stopped("final source verification allocation refused", (source, plan)));
    }
    for item in plan.items_in_order() {
        expected.push((item.record.offset(), item.record.bytes().len(), item.disposition,
            item.record.kind(), ContentDigest::sha256(item.record.bytes())));
    }
    let mut tail = match retirement_source::Driver::begin(source, plan, key, camera_claim) {
        Ok(tail) => tail,
        Err(parts) => return Err(stopped("final source driver refused", (parts, expected))),
    };
    let (events, joined, finished) = drive_stopped_tail(&mut tail, task, cx, clock, admission).await;
    if !finished {
        return Err(stopped("final source publication incomplete", (tail, events, joined, expected)));
    }
    let parts = match tail.into_parts() {
        Ok(parts) => parts,
        Err(tail) => return Err(stopped("final source worker did not drain", (tail, events, joined, expected))),
    };
    let retirement_source::DriverParts { worker, plan, .. } = parts;
    let mut source = match worker.retire() {
        Ok(source) => source,
        Err(worker) => return Err(stopped("final source worker did not retire", (worker, plan, events, joined, expected))),
    };
    if !plan.is_empty() || source.pending.is_some() || source.fenced {
        return Err(stopped("final source retirement unresolved", (source, plan, events, joined, expected)));
    }
    let verified = (|| {
        let mut index = 0usize;
        let mut batch = None;
        for event in &events {
            match event {
                retirement_source::DriverStep::Offered { .. } => batch = Some(false),
                retirement_source::DriverStep::BatchOffered { .. } => batch = Some(true),
                retirement_source::DriverStep::Completed(done) => {
                    let source_worker::Outcome::Publication(source_worker::Publication::Published { pin, .. }) = &done.outcome else { return false };
                    if !done.runtime.is_ok() { return false; }
                    let mut work = fss_geometry::WorkBudget::new(4_000_000_000);
                    let Some(is_batch) = batch.take() else { return false };
                    if is_batch {
                        let Ok(recovered) = archive::read_unknown_time_source_batch(&mut source.parts.deployment, *pin,
                            &Access(retention), archive::Limits::default(), &mut work, &source.parts.replay) else { return false };
                        if recovered.key != key || recovered.camera_claim != camera_claim { return false; }
                        for record in recovered.records {
                            let Some(bytes) = recovered.payload.get(record.range) else { return false };
                            let actual = (record.offset, bytes.len(), record.disposition, record.kind, ContentDigest::sha256(bytes));
                            if expected.get(index) != Some(&actual) { return false; }
                            index += 1;
                        }
                    } else {
                        let Ok(recovered) = archive::read_unknown_time_source(&mut source.parts.deployment, *pin,
                            &Access(retention), archive::Limits::default(), &mut work, &source.parts.replay) else { return false };
                        let actual = (recovered.offset(), recovered.bytes().len(), recovered.disposition(), recovered.kind(), ContentDigest::sha256(recovered.bytes()));
                        if recovered.key() != key || recovered.camera_claim() != camera_claim || expected.get(index) != Some(&actual) { return false; }
                        index += 1;
                    }
                }
                _ => (),
            }
        }
        index == expected.len() && batch.is_none()
    })();
    if !verified {
        return Err(stopped("final source readback mismatch", (source, plan, events, joined, expected)));
    }
    Ok(FinalTail { plan, source, events, records: expected.len() })
}

fn automatic_failure(reason: &'static str, custody: impl Any) -> AutomaticFailure {
    AutomaticFailure { error: stopped(reason, custody), restore_eligible: false, tail_parts: None }
}

async fn stopped_automatic(
    owner: media_av_managed::Managed, reason: &'static str, event: impl Any,
    restore_candidate: bool, save_tail: bool,
) -> AutomaticFailure {
    let (owner, source, av) = stop_automatic(owner).await;
    let mut retained = owner.into_parts();
    let mut recording = None;
    if (restore_candidate || save_tail) && (!retained.creator_started || retained.creator_completion.is_some()) {
        match retained.owner.take() {
            Some(media_av_managed::Owner::Recording(driver)) => match (*driver).into_parts() {
                Ok(parts) => recording = Some(parts),
                Err(driver) => retained.owner = Some(media_av_managed::Owner::Recording(Box::new(driver))),
            },
            other => retained.owner = other,
        }
    }
    let restore_eligible = restore_candidate && recording.is_some();
    let tail_parts = if save_tail { recording.take() } else { None };
    AutomaticFailure { error: stopped(reason, (retained, recording, source, av, event)), restore_eligible, tail_parts }
}

fn build_manager(
    driver: media_av_archive::Driver, parent: &Path, auth: &fss_core::region::ContextAuthority,
    retention: ContentDigest, run_id: &TrialRunId, count: u64, history: EffectJournalLimits,
) -> Result<Box<media_av_managed::Managed>, AutomaticFailure> {
    let replay = match ReplayCx::from_context_authority(auth, parent.to_path_buf()) {
        Ok(replay) => Arc::new(replay),
        Err(error) => return Err(automatic_failure("HTTP A/V generation replay authority refused", (driver, error))),
    };
    let plan = match av_rollover_generation::Plan::new(av_rollover_generation::Configuration {
        namespace: run_id.as_str().to_owned(), scope_seed: retention, first: 1, count,
        journal_replay: replay.clone(), pin_replay: replay,
        journal_io: Arc::new(HostSpoolIo), pin_io: Arc::new(HostSpoolIo),
        journal_limits: history, pin_limits: EffectJournalLimits::default(),
        read: Arc::new(Access(retention)),
        object_limits: archive::StagedAvLimits { max_objects: 8192, max_object_bytes: 1024 * 1024, max_total_bytes: 8 * 1024 * 1024 },
        work_limit: 4_000_000_000,
    }) {
        Ok(plan) => plan,
        Err(config) => return Err(automatic_failure("HTTP A/V generation plan refused", (driver, config))),
    };
    let audio = match fss_reference::unifi_direct::recording_session::AudioAllowancePolicy::new(1_000_000, 1024, 65_536) {
        Some(audio) => audio,
        None => return Err(automatic_failure("invalid HTTP A/V allowance", (driver, plan))),
    };
    match media_av_managed::Managed::new(driver, plan, audio, 8) {
        Ok(owner) => Ok(Box::new(owner)),
        Err(owners) => return Err(automatic_failure("HTTP A/V manager refused", owners)),
    }
}

/// Drive a finite synthetic-or-owner-authorized trial through automatic
/// successor provisioning. Generation choices are not restart durable here.
async fn drive_automatic<'scope, 'task>(
    driver: media_av_archive::Driver, task: &'scope TaskCx<'task>, cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>, parent: &Path, auth: &fss_core::region::ContextAuthority,
    retention: ContentDigest, run_id: &TrialRunId, count: u64, history: EffectJournalLimits,
    segments: usize, admission: ArchiveAdmission<'_>,
    observations: &mut Vec<Option<fss_reference::unifi_direct::pipeline::AudioEvent>>,
    source_completions: &mut Vec<source_worker::Completion>,
    av_completions: &mut Vec<av_worker::UnknownTimeCompletion>,
    published: &mut Vec<archive::UnknownTimePin>,
) -> Result<(media_av_archive::Driver, media_av_managed::Parts), AutomaticFailure> {
    let mut owner = *build_manager(driver, parent, auth, retention, run_id, count, history)?;
    let mut rollovers = 0usize;
    for _ in 0..4096 {
        let event = Box::pin(owner.step(task, cx, clock, Duration::from_secs(1), admission, admission,
            &BudgetVector::ZERO, admission)).await;
        match event {
            media_av_managed::Step::Planned(_) | media_av_managed::Step::CreatorStarted
            | media_av_managed::Step::CreatorReady | media_av_managed::Step::PlanExhausted
            | media_av_managed::Step::AwaitingSupplies(_) | media_av_managed::Step::PreflightPrepared
            | media_av_managed::Step::RolloverStarted | media_av_managed::Step::RolloverWaiting
            | media_av_managed::Step::PreflightReady => (),
            media_av_managed::Step::Resumed(_) => rollovers += 1,
            media_av_managed::Step::Recording(media_av_archive::AllowanceStep::Renewed { before, after, budget }) =>
                println!("trial_http_av_allowance=renewed before={before} after={after} remaining_budget={budget}"),
            media_av_managed::Step::Recording(media_av_archive::AllowanceStep::Recording(event)) => match event {
                media_av_archive::Step::Offer(media_av_archive::Offer::Source { audio, .. })
                | media_av_archive::Step::Offer(media_av_archive::Offer::Buffered(audio))
                | media_av_archive::Step::Offer(media_av_archive::Offer::Segment(audio)) => observations.push(audio),
                media_av_archive::Step::SourceStarted | media_av_archive::Step::SourceRunning
                | media_av_archive::Step::AvStarted | media_av_archive::Step::AvRunning | media_av_archive::Step::Idle
                | media_av_archive::Step::Media(fss_reference::unifi_direct::pipeline::Step::Progress { .. }) => (),
                media_av_archive::Step::SourceCompleted(done) if done.runtime.is_ok() && matches!(&done.outcome,
                    source_worker::Outcome::Publication(source_worker::Publication::Published { .. })) => source_completions.push(done),
                media_av_archive::Step::AvCompleted(done) if done.runtime.is_ok() => match &done.outcome {
                    av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(value)) => {
                        published.push(value.pin); av_completions.push(done);
                        if published.len() == segments { break; }
                    }
                    av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Refused {
                        reason: av_worker::FailureReason::JournalCapacity, rollover: Some(_), ..
                    }) => av_completions.push(done),
                    _ => {
                        return Err(stopped_automatic(owner, "HTTP A/V automatic archive refused", done, false, false).await);
                    }
                },
                other => {
                    if matches!(&other, media_av_archive::Step::MediaError(fss_reference::unifi_direct::pipeline::Error::Ingress(
                        fss_reference::unifi_direct::ingress::Error::Source(fss_runtime::tcp_ingress::IngressError::BudgetExhausted)
                    ))) { eprintln!("trial_http_av_stop=network_budget_exhausted"); }
                    let eligible = match &other {
                        media_av_archive::Step::Media(fss_reference::unifi_direct::pipeline::Step::Eof | fss_reference::unifi_direct::pipeline::Step::LimitReached) => true,
                        media_av_archive::Step::MediaError(error) => trial_http_restore::eligible_media_error(error),
                        _ => false,
                    };
                    let save_tail = other.has_retirable_tail();
                    return Err(stopped_automatic(owner, "HTTP A/V automatic media stopped", other, eligible, save_tail).await);
                }
            },
            other => {
                return Err(stopped_automatic(owner, "HTTP A/V automatic provisioning stopped", other, false, false).await);
            }
        }
    }
    if published.len() != segments {
        return Err(stopped_automatic(owner, "HTTP A/V automatic step limit reached", (), false, false).await);
    }
    owner.abort();
    owner.join_creator().await;
    owner.join_rollover().await;
    let mut custody = owner.into_parts();
    let driver = match custody.owner.take() {
        Some(media_av_managed::Owner::Recording(driver)) => driver,
        other => { custody.owner = other; return Err(automatic_failure("HTTP A/V automatic owner not recording", custody)); }
    };
    println!("trial_http_av_auto=drained rollovers={rollovers} retained_custody={} restart_durable=false independent_storage=unverified", custody.custody.len());
    Ok((*driver, custody))
}

/// Start once using the retained checkpoint, archive bounded A/V, and keep the
/// effect unresolved. Out-of-band AAC is a caller claim, never an epoch proof.
pub async fn run<'scope, 'task, 'policy, IO: AsyncRead + AsyncWrite + Unpin>(
    task: &'scope TaskCx<'task>, cx: &'scope Cx, clock: MeteredClock<'scope, 'task>,
    http: &mut camera_http::Owner<'_, '_, '_, IO>, mut listener: listener::Listener<'scope, 'task, 'policy>,
    checkpoint: Prepared, conditions: Preconditions, authority: &dyn SerializerAuthority,
    leases: &RefCell<LeaseRegistry>, effects: &mut EffectCoordinator, run_id: &TrialRunId,
    root: &Path, resource: &str, effect_attempted: &Cell<bool>, framing: SearchMode,
    inband: bool, dimensions: [u32; 2], segments: usize, supplied_audio: Option<[u8; 2]>, restore_after: bool, name_probe: bool,
    auto_generations: Option<u64>, supervised_mode: bool, history_records: Option<usize>, exhaust_network_after_bootstrap: bool,
    exhaust_network_in_bootstrap: bool,
    observation: ObservationCheckpoint<'_>, authorize: impl Fn(Ipv4Addr, u64) -> bool,
) -> Result<(), Box<dyn Error>> {
    if !(1..=8).contains(&segments) { return Err("HTTP A/V segment limit must be 1 to 8".into()); }
    if name_probe && !restore_after { return Err("HTTP A/V name probe requires restoration".into()); }
    if supervised_mode && auto_generations.is_none() { return Err("supervised A/V requires automatic generations".into()); }
    let parent = root.parent().ok_or("archive parent missing")?;
    let replay_authority = fss_core::region::ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:http-owned-av-storage".into(),
        operation_id: OperationId::parse("operation:http-owned-av-storage")?,
        principal: "principal:owner".into(), capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None, priority: 1, budgets: BudgetVector::builder().bytes(256 * 1024 * 1024).build()?,
        privacy_scope: "privacy:owner".into(), retention_scope: "retention:trial".into(),
        anchor_universe: conditions.camera, generation: 1,
    })?;
    let retention = ContentDigest::sha256(b"unifi-http-av-record-trial-retention");
    let source = SourceKey { connection: 1, generation: 1 };
    let av_history = EffectJournalLimits { max_records: history_records.unwrap_or(EffectJournalLimits::default().max_records), ..EffectJournalLimits::default() };
    let cfg = recording_storage::Configuration {
        root, site_lineage: "site:http-av-record-trial", source, camera_claim: conditions.camera,
        source_retention: retention, source_scope: ContentDigest::sha256(b"http-av-trial-source"),
        av_scope: ContentDigest::sha256(b"http-av-trial-media"),
        source_deployment_limits: DeploymentLimits::standard(), av_deployment_limits: DeploymentLimits::standard(),
        source_history_limits: EffectJournalLimits::default(), av_history_limits: av_history,
        limits: archive::Limits::default(), max_source_bytes: 16 * 1024 * 1024, work_limit: 4_000_000_000,
    };
    let storage = recording_storage::create(task, cx, clock, cfg,
        ReplayCx::from_context_authority(&replay_authority, parent.to_path_buf())?,
        ReplayCx::from_context_authority(&replay_authority, parent.to_path_buf())?, Arc::new(Access(retention)))?;
    let mut recorder = if inband { recording::Recorder::new_inband(source, recording::Limits::default())? }
        else { recording::Recorder::new(source, recording::Limits::default())? };
    recorder.require_dimensions(dimensions)?;
    let capture = AvCapture {
        framer: Framer::with_mode(FlvLimits::default(), 8 * 1024 * 1024, framing)?, recorder, storage, retention,
        policy: av_owned_sink::BootstrapPolicy {
            allow_initial_video_only: false, max_separation_ms: 5_000, jitter_ms: 5,
            max_epoch_frames: 1_000_000, max_audio_frames: Mp4Limits::default().max_samples,
            media_limits: Mp4Limits::default(), evidence_limits: evidence::Limits::default(),
        }, supplied_unverified_audio: supplied_audio, wait: Duration::from_secs(10),
        chunk_bytes: 4096, max_bytes: 64 * 1024 * 1024,
    };
    let bootstrap_policy = capture.policy;
    let probe = if name_probe {
        Some(fss_packet::extended_flv::stream::NameProbeOwner::new(
            "onMetaData", &run_id.as_str()[..16], 256 * 1024, 4, 4_000_000,
        )?)
    } else { None };
    let operation = run_id.operation("http-start")?;
    effect_attempted.set(true);
    let prepared = task.prepare_effect(cx, effects, &mut leases.borrow_mut(), PrepareSpec {
        operation: &operation, idempotency_key: IdempotencyKey::parse(operation.as_str())?,
        request_digest: checkpoint.plan.request_digest(), precondition_digest: checkpoint.plan.precondition_digest(),
        resource, fence: conditions.lease_fence, prepare_grant: RuntimeGrant::CameraSettingPrepare,
        commit_grant: RuntimeGrant::CameraSettingCommit,
        terminal_predicate: "independent serializer observation or reconciliation",
    }, clock.now()?)?;
    let approval = CommitApproval { prepared_digest: prepared.digest(), current_precondition_digest: checkpoint.plan.precondition_digest() };
    let permit = task.commit_effect(cx, effects, &mut leases.borrow_mut(), prepared, clock.now()?, approval)
        .map_err(|_| "HTTP A/V effect commit refused; inspect journal")?;
    let started = Box::pin(trial_http_checkpoint::start_av(task, cx, clock, http, &mut listener,
        checkpoint, conditions, authority, capture, permit, effects, resource, &authorize)).await;
    let checkpoint = started.checkpoint;
    let mut bootstrap = match started.state {
        AvStartState::Started(driver) => driver,
        state => {
            let eligible = match &state {
                AvStartState::Media { refusal, .. } => trial_http_restore::eligible_start_failure(&refusal.failure, refusal.may_have_written, refusal.readback.is_some()),
                _ => false,
            };
            if restore_after && eligible {
                let recovery = trial_http_restore::after_observed_failure(cx, task, clock, http, &checkpoint, conditions, authority, leases, effects, run_id, resource, &observation, &authorize).await;
                if recovery.is_ok() {
                    println!("trial_http_failure_restore=readback_matches restored_checkpoint=anchored recording=failed effects=reconciliation_required");
                } else {
                    eprintln!("trial_http_failure_restore=requires_reconciliation recording=failed");
                }
                return Err(stopped("HTTP A/V stream start refused; reconcile effect", (checkpoint, state, recovery)));
            }
            return Err(stopped("HTTP A/V stream start refused; reconcile effect", (checkpoint, state)));
        }
    };
    let _name_probe = if let Some(probe) = probe {
        use fss_reference::unifi_direct::ingress::NameProbeStep;
        let mut matched = None;
        let mut initial_refusal = None;
        let mut refusal_reason = "step_limit";
        if let Err(probe) = bootstrap.begin_name_probe(probe) { initial_refusal = Some(probe); }
        if initial_refusal.is_some() { refusal_reason = "owner_state"; }
        if initial_refusal.is_none() {
            let deadline = cx.now() + Duration::from_secs(10);
            for _ in 0..128 {
                let now = match clock.now() { Ok(now) => now, Err(_) => { refusal_reason = "clock"; break; } };
                match asupersync::time::timeout_at(deadline, bootstrap.probe_name_step(task, cx, now)).await {
                    Ok(Ok(NameProbeStep::Progress { .. })) => (),
                    Ok(Ok(NameProbeStep::Matched { tag_index })) => { matched = Some(tag_index); break; },
                    Ok(Ok(NameProbeStep::Mismatched { .. })) => { refusal_reason = "name_mismatch"; break; },
                    Ok(Ok(NameProbeStep::LimitReached { .. })) => { refusal_reason = "prefix_limit"; break; },
                    Ok(Ok(NameProbeStep::Empty)) => { refusal_reason = "empty"; break; },
                    Ok(Ok(NameProbeStep::Incomplete)) => { refusal_reason = "incomplete"; break; },
                    Ok(Err(error)) => { refusal_reason = trial_http_restore::name_probe_error_label(&error); break; },
                    Err(_) => { refusal_reason = "timeout"; break; },
                }
            }
        }
        let probe = initial_refusal.or_else(|| bootstrap.take_name_probe());
        if let Some(tag_index) = matched {
            println!("trial_http_av_name_probe=matched tag_index={tag_index} camera_identity=unverified source_boundary=claim");
            probe
        } else {
            eprintln!("trial_http_av_name_probe_reason={refusal_reason} camera_identity=unverified effect=reconciliation_required");
            bootstrap.abort();
            let source = bootstrap.join_source().await;
            let parts = match bootstrap.into_parts() {
                Ok(parts) => parts,
                Err(bootstrap) => return Err(stopped("HTTP A/V name probe worker did not drain", (checkpoint, bootstrap, probe, source))),
            };
            let recovery = trial_http_restore::after_observed_failure(cx, task, clock, http, &checkpoint, conditions, authority, leases, effects, run_id, resource, &observation, &authorize).await;
            if recovery.is_ok() {
                println!("trial_http_av_name_probe=refused restoration=readback_matches effect=reconciliation_required");
            } else {
                eprintln!("trial_http_av_name_probe=refused restoration=requires_reconciliation");
            }
            return Err(stopped("HTTP A/V name probe did not match; reconcile effect", (checkpoint, parts, probe, source, recovery)));
        }
    } else { None };
    let cost = BudgetVector::ZERO;
    let admission = ArchiveAdmission { resource, cost: &cost };
    let mut observations = Vec::new();
    let mut source_completions = Vec::new();
    let mut ready = false;
    let mut bootstrap_injected = false;
    for _ in 0..4096 {
        let event = bootstrap.step(task, cx, clock, Duration::from_secs(1), admission).await;
        if exhaust_network_in_bootstrap && !bootstrap_injected && matches!(&event, media_av_startup::Step::Retained) {
            let mut cost = BudgetVector::ZERO;
            cost.network_bytes = task.remaining_budget()?.network_bytes;
            if cost.network_bytes == 0 { return Err("network budget exhausted before bootstrap injection".into()); }
            task.checkpoint_for(RuntimeGrant::AdapterNet, resource, clock.now()?, &cost)?;
            bootstrap_injected = true;
            println!("trial_lab_network_exhaustion=injected stage=bootstrap");
        }
        match event {
            media_av_startup::Step::Retained | media_av_startup::Step::Progress | media_av_startup::Step::Idle
            | media_av_startup::Step::SourceStarted | media_av_startup::Step::SourceRunning => (),
            media_av_startup::Step::Buffered(audio) | media_av_startup::Step::SourceOffered { audio, .. } => observations.push(audio),
            media_av_startup::Step::SourceCompleted(done) if done.runtime.is_ok() && matches!(&done.outcome,
                source_worker::Outcome::Publication(source_worker::Publication::Published { .. })) => source_completions.push(done),
            media_av_startup::Step::Ready => { ready = true; break; },
            other => {
                if matches!(&other, media_av_startup::Step::MediaError(fss_reference::unifi_direct::pipeline::Error::Ingress(
                    fss_reference::unifi_direct::ingress::Error::Source(fss_runtime::tcp_ingress::IngressError::BudgetExhausted)
                ))) { eprintln!("trial_http_av_bootstrap_stop=network_budget_exhausted"); }
                if let media_av_startup::Step::MediaError(fss_reference::unifi_direct::pipeline::Error::Recording(refusal)) = &other {
                    eprintln!("trial_http_av_media_refusal=recording:{:?}", refusal.reason);
                }
                bootstrap.abort(); let joined = bootstrap.join_source().await;
                let eligible = match &other {
                    media_av_startup::Step::Eof | media_av_startup::Step::LimitReached => true,
                    media_av_startup::Step::MediaError(error) => trial_http_restore::eligible_media_error(error),
                    _ => false,
                };
                if other.has_retirable_tail() {
                    let parts = match bootstrap.into_parts() {
                        Ok(parts) => parts,
                        Err(bootstrap) => return Err(stopped("HTTP A/V bootstrap failure worker did not drain", (checkpoint, bootstrap, observations, source_completions, other, joined))),
                    };
                    let recovery = if restore_after && eligible {
                        let recovery = trial_http_restore::after_observed_failure(cx, task, clock, http, &checkpoint, conditions, authority, leases, effects, run_id, resource, &observation, &authorize).await;
                        if recovery.is_ok() {
                            println!("trial_http_failure_restore=readback_matches restored_checkpoint=anchored recording=failed effects=reconciliation_required");
                        } else {
                            eprintln!("trial_http_failure_restore=requires_reconciliation recording=failed");
                        }
                        Some(recovery)
                    } else { None };
                    let tail = Box::pin(preserve_bootstrap_tail(parts, task, cx, clock, admission)).await;
                    return Err(stopped("HTTP A/V bootstrap stopped; reconcile custody", (checkpoint, tail, observations, source_completions, other, joined, recovery)));
                }
                if restore_after && eligible {
                    let parts = match bootstrap.into_parts() {
                        Ok(parts) => parts,
                        Err(bootstrap) => return Err(stopped("HTTP A/V failure worker did not drain", (checkpoint, bootstrap, observations, source_completions, other, joined))),
                    };
                    let recovery = trial_http_restore::after_observed_failure(cx, task, clock, http, &checkpoint, conditions, authority, leases, effects, run_id, resource, &observation, &authorize).await;
                    if recovery.is_ok() {
                        println!("trial_http_failure_restore=readback_matches restored_checkpoint=anchored recording=failed effects=reconciliation_required");
                    } else {
                        eprintln!("trial_http_failure_restore=requires_reconciliation recording=failed");
                    }
                    return Err(stopped("HTTP A/V bootstrap stopped; reconcile custody", (checkpoint, parts, observations, source_completions, other, joined, recovery)));
                }
                return Err(stopped("HTTP A/V bootstrap stopped; reconcile custody", (checkpoint, bootstrap, observations, source_completions, other, joined)));
            }
        }
    }
    if !ready {
        bootstrap.abort(); let joined = bootstrap.join_source().await;
        return Err(stopped("HTTP A/V bootstrap step limit reached", (checkpoint, bootstrap, observations, source_completions, joined)));
    }
    let mut driver = match bootstrap.finish() {
        Ok(driver) => driver,
        Err(refusal) => {
            match &*refusal {
                media_av_startup::TransitionRefusal::Bootstrap { refusal: fss_reference::unifi_direct::http_stream::media_av_bootstrap::HandoffRefusal::Bootstrap { refusal, .. }, .. } =>
                    eprintln!("trial_http_av_bootstrap_refusal={:?}", refusal.reason),
                media_av_startup::TransitionRefusal::NotReady(_) => eprintln!("trial_http_av_bootstrap_refusal=not_ready"),
                media_av_startup::TransitionRefusal::Bootstrap { .. } => eprintln!("trial_http_av_bootstrap_refusal=bootstrap_not_ready"),
                media_av_startup::TransitionRefusal::Archive { .. } => eprintln!("trial_http_av_bootstrap_refusal=archive_attach"),
                media_av_startup::TransitionRefusal::Attach(_) => eprintln!("trial_http_av_bootstrap_refusal=source_attach"),
                media_av_startup::TransitionRefusal::Seal(_) => eprintln!("trial_http_av_bootstrap_refusal=prefix_seal"),
            }
            return Err(stopped("HTTP A/V bootstrap transition refused", (checkpoint, observations, source_completions, refusal)));
        }
    };
    if exhaust_network_after_bootstrap {
        let mut cost = BudgetVector::ZERO;
        cost.network_bytes = task.remaining_budget()?.network_bytes;
        if cost.network_bytes == 0 { return Err("network budget exhausted before injection".into()); }
        task.checkpoint_for(fss_core::RuntimeGrant::AdapterNet, resource, clock.now()?, &cost)?;
        println!("trial_lab_network_exhaustion=injected stage=after_bootstrap");
    }
    let mut published = Vec::with_capacity(segments);
    let mut av_completions = Vec::with_capacity(segments);
    let mut automatic_custody = None;
    if supervised_mode {
        let count = auto_generations.ok_or("supervised generation count missing")?;
        let manager = match build_manager(driver, parent, &replay_authority, retention, run_id, count, av_history) {
            Ok(manager) => manager,
            Err(failure) => return Err(stopped("supervised manager construction refused", (checkpoint, observations,
                source_completions, av_completions, published, failure.error, failure.tail_parts))),
        };
        let config = fss_reference::unifi_direct::http_stream::media_av_supervisor::Config {
            successor: fss_reference::unifi_direct::http_stream::media_av_reconnect::SuccessorConfig {
                flv: FlvLimits::default(), max_buffer: 8 * 1024 * 1024, search: framing,
                recorder: recording::Limits::default(), inband, expected_dimensions: Some(dimensions),
                chunk_bytes: 4096, max_bytes: 64 * 1024 * 1024, wait: Duration::from_secs(10),
            },
            attempts_per_eof: 2, retention, bootstrap: bootstrap_policy,
            supplied_unverified_audio: supplied_audio,
        };
        match Box::pin(supervised::run(manager, listener, task, cx, clock, config, admission, segments, &mut published)).await {
            Ok((returned, custody)) => { driver = returned; automatic_custody = Some((None, Some(custody))); }
            Err(error) => return Err(stopped("supervised A/V trial requires reconciliation", (checkpoint, observations,
                source_completions, av_completions, published, error))),
        }
    } else if let Some(count) = auto_generations {
        match Box::pin(drive_automatic(driver, task, cx, clock, parent, &replay_authority,
            retention, run_id, count, av_history, segments, admission, &mut observations,
            &mut source_completions, &mut av_completions, &mut published)).await {
            Ok((returned, custody)) => { driver = returned; automatic_custody = Some((Some(custody), None)); }
            Err(failure) => {
                let AutomaticFailure { error, restore_eligible, tail_parts } = failure;
                let recovery = if restore_after && restore_eligible {
                    let recovery = trial_http_restore::after_observed_failure(cx, task, clock, http, &checkpoint, conditions, authority, leases, effects, run_id, resource, &observation, &authorize).await;
                    if recovery.is_ok() {
                        println!("trial_http_failure_restore=readback_matches restored_checkpoint=anchored recording=failed effects=reconciliation_required");
                    } else {
                        eprintln!("trial_http_failure_restore=requires_reconciliation recording=failed");
                    }
                    Some(recovery)
                } else { None };
                let tail = match tail_parts {
                    Some(parts) => Some(Box::pin(preserve_stopped_tail(parts, task, cx, clock, admission)).await),
                    None => None,
                };
                return Err(stopped("HTTP A/V automatic trial requires reconciliation", (checkpoint, observations, source_completions, av_completions, published, error, recovery, tail)));
            }
        }
    } else {
    let mut audio_allowance = fss_reference::unifi_direct::recording_session::AudioAllowancePolicy::new(
        1_000_000, 1024, 65_536,
    ).ok_or("invalid HTTP A/V allowance")?;
    for _ in 0..4096 {
        let event = match Box::pin(driver.step_with_audio_allowance(
            &mut audio_allowance, task, cx, clock, Duration::from_secs(1), admission, admission,
        )).await {
            media_av_archive::AllowanceStep::Recording(event) => event,
            media_av_archive::AllowanceStep::Renewed { before, after, budget } => {
                println!("trial_http_av_allowance=renewed before={before} after={after} remaining_budget={budget}");
                continue;
            }
            other => {
                driver.abort(); let source_join = driver.join_source().await; let av_join = driver.join_av().await;
                return Err(stopped("HTTP A/V allowance refused; reconcile custody", (checkpoint, driver, observations, source_completions, av_completions, published, other, source_join, av_join)));
            }
        };
        match event {
            media_av_archive::Step::Offer(media_av_archive::Offer::Source { audio, .. })
            | media_av_archive::Step::Offer(media_av_archive::Offer::Buffered(audio))
            | media_av_archive::Step::Offer(media_av_archive::Offer::Segment(audio)) => observations.push(audio),
            media_av_archive::Step::SourceStarted | media_av_archive::Step::SourceRunning
            | media_av_archive::Step::AvStarted | media_av_archive::Step::AvRunning | media_av_archive::Step::Idle
            | media_av_archive::Step::Media(fss_reference::unifi_direct::pipeline::Step::Progress { .. }) => (),
            media_av_archive::Step::SourceCompleted(done) if done.runtime.is_ok() && matches!(&done.outcome,
                source_worker::Outcome::Publication(source_worker::Publication::Published { .. })) => source_completions.push(done),
            media_av_archive::Step::AvCompleted(done) if done.runtime.is_ok() && matches!(&done.outcome,
                av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(_))) => {
                if let av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(value)) = &done.outcome {
                    published.push(value.pin);
                }
                av_completions.push(done);
                if published.len() == segments { break; }
            }
            other => {
                if matches!(&other, media_av_archive::Step::MediaError(fss_reference::unifi_direct::pipeline::Error::Ingress(
                    fss_reference::unifi_direct::ingress::Error::Source(fss_runtime::tcp_ingress::IngressError::BudgetExhausted)
                ))) { eprintln!("trial_http_av_stop=network_budget_exhausted"); }
                if let media_av_archive::Step::MediaError(fss_reference::unifi_direct::pipeline::Error::Recording(refusal)) = &other {
                    eprintln!("trial_http_av_media_refusal=recording:{:?}", refusal.reason);
                }
                driver.abort(); let source_join = driver.join_source().await; let av_join = driver.join_av().await;
                let eligible = match &other {
                    media_av_archive::Step::Media(fss_reference::unifi_direct::pipeline::Step::Eof | fss_reference::unifi_direct::pipeline::Step::LimitReached) => true,
                    media_av_archive::Step::MediaError(error) => trial_http_restore::eligible_media_error(error),
                    _ => false,
                };
                if other.has_retirable_tail() {
                    let parts = match driver.into_parts() {
                        Ok(parts) => parts,
                        Err(driver) => return Err(stopped("HTTP A/V failure workers did not drain", (checkpoint, driver, observations, source_completions, av_completions, published, other, source_join, av_join))),
                    };
                    let recovery = if restore_after && eligible {
                        let recovery = trial_http_restore::after_observed_failure(cx, task, clock, http, &checkpoint, conditions, authority, leases, effects, run_id, resource, &observation, &authorize).await;
                        if recovery.is_ok() {
                            println!("trial_http_failure_restore=readback_matches restored_checkpoint=anchored recording=failed effects=reconciliation_required");
                        } else {
                            eprintln!("trial_http_failure_restore=requires_reconciliation recording=failed");
                        }
                        Some(recovery)
                    } else { None };
                    let tail = Box::pin(preserve_stopped_tail(parts, task, cx, clock, admission)).await;
                    return Err(stopped("HTTP A/V recording stopped; reconcile custody", (checkpoint, tail, observations, source_completions, av_completions, published, other, source_join, av_join, recovery)));
                }
                if restore_after && eligible {
                    let parts = match driver.into_parts() {
                        Ok(parts) => parts,
                        Err(driver) => return Err(stopped("HTTP A/V failure workers did not drain", (checkpoint, driver, observations, source_completions, av_completions, published, other, source_join, av_join))),
                    };
                    let recovery = trial_http_restore::after_observed_failure(cx, task, clock, http, &checkpoint, conditions, authority, leases, effects, run_id, resource, &observation, &authorize).await;
                    if recovery.is_ok() {
                        println!("trial_http_failure_restore=readback_matches restored_checkpoint=anchored recording=failed effects=reconciliation_required");
                    } else {
                        eprintln!("trial_http_failure_restore=requires_reconciliation recording=failed");
                    }
                    return Err(stopped("HTTP A/V recording stopped; reconcile custody", (checkpoint, parts, observations, source_completions, av_completions, published, other, source_join, av_join, recovery)));
                }
                return Err(stopped("HTTP A/V recording stopped; reconcile custody", (checkpoint, driver, observations, source_completions, av_completions, published, other, source_join, av_join)));
            }
        }
    }
    }
    if published.len() != segments {
        driver.abort(); let source_join = driver.join_source().await; let av_join = driver.join_av().await;
        return Err(stopped("HTTP A/V recording step limit reached", (checkpoint, driver, observations, source_completions, av_completions, published, source_join, av_join, automatic_custody)));
    }
    driver.abort();
    let source_join = driver.join_source().await;
    let av_join = driver.join_av().await;
    let parts = match driver.into_parts() {
        Ok(parts) => parts,
        Err(driver) => return Err(stopped("HTTP A/V workers did not drain", (checkpoint, driver, observations, source_completions, av_completions, published, source_join, av_join, automatic_custody))),
    };
    let media_av_archive::Parts { connected, source: source_owner, av: av_owner, key, camera_claim: source_claim, .. } = parts;
    let mut av_owner = match av_owner.retire() {
        Ok(owner) => owner,
        Err(owner) => return Err(stopped("HTTP A/V worker did not retire", (checkpoint, connected, source_owner, owner, observations, source_completions, av_completions, published, source_join, av_join, automatic_custody))),
    };
    let checked: Result<(usize, usize), Box<dyn Error>> = (|| {
        let mut video_total = 0usize; let mut audio_total = 0usize;
        for pin in &published {
            let clip = archive::read_unknown_time_av_clip(&mut av_owner.parts.deployment, *pin, &Access(retention),
                archive::Limits::default(), &mut fss_geometry::WorkBudget::new(4_000_000_000), &av_owner.parts.replay)?;
            if clip.video_samples() == 0 || clip.audio().frames == 0 { return Err("A/V segment missing a track".into()); }
            video_total = video_total.checked_add(clip.video_samples()).ok_or("video count overflow")?;
            audio_total = audio_total.checked_add(clip.audio().frames).ok_or("audio count overflow")?;
            let movie = if inband { AvcMp4::parse_inband(clip.bytes(), None, DemuxLimits::default())? }
                else { AvcMp4::parse(clip.bytes(), None, DemuxLimits::default())? };
            let annex = movie.annex_b(0, 1)?;
            let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits { max_pictures: 8, ..Default::default() })?;
            let mut pictures = decoder.decode_annex_b(annex.bytes())?;
            pictures.extend(decoder.finish()?);
            let picture = pictures.first().ok_or("A/V clip has no decodable picture")?;
            if [picture.width(), picture.height()] != dimensions { return Err("A/V frame dimensions differ from selected profile".into()); }
        }
        Ok((video_total, audio_total))
    })();
    let (video_total, audio_total) = match checked {
        Ok(value) => value,
        Err(error) => return Err(stopped("HTTP A/V archive readback failed", (checkpoint, connected, source_owner, av_owner, observations, source_completions, av_completions, published, source_join, av_join, error, automatic_custody))),
    };
    let detached = connected.into_parts();
    if clock.now().ok().is_none_or(|now| task.checkpoint_for(RuntimeGrant::ObserveStatus, resource, now, &BudgetVector::ZERO).is_err()) {
        return Err(stopped("serializer observation authority refused", (checkpoint, detached, source_owner, av_owner, observations, source_completions, av_completions, published, source_join, av_join, automatic_custody)));
    }
    let reread = match http.settings_serializers(Duration::from_secs(10)).await {
        Ok((_, value)) => value,
        Err(error) => return Err(stopped("serializer observation unavailable", (checkpoint, detached, source_owner, av_owner, observations, source_completions, av_completions, published, source_join, av_join, error, automatic_custody))),
    };
    let consistent = (|| {
        let original = detached.readback.binding(&authorize).ok()?;
        let current = reread.binding(&authorize).ok()?;
        let comparison = checkpoint.plan.observe_readback(&checkpoint.baseline, &reread, &authorize).ok()?;
        Some(original == current && comparison.change == fss_reference::unifi_direct::http_stream::ReadbackChange::TargetTrackOnly && comparison.requested_fields_match)
    })();
    if consistent != Some(true) {
        return Err(stopped("serializer observation changed after recording", (checkpoint, detached, reread, source_owner, av_owner, observations, source_completions, av_completions, published, source_join, av_join, automatic_custody)));
    }
    let observation_plan = (|| {
        let binding = reread.binding(&authorize).ok()?;
        let observed_conditions = Preconditions { serializers: binding, ..conditions };
        let plan = fss_reference::unifi_direct::http_stream::Plan::new(observation.peer, observation.start, observed_conditions, &reread, handoff::Framing::ContentLength).ok()?;
        (plan.request_digest() == checkpoint.plan.request_digest()).then_some(plan)
    })();
    let observation_plan = match observation_plan {
        Some(plan) => plan,
        None => return Err(stopped("serializer observation checkpoint scope refused", (checkpoint, detached, reread, source_owner, av_owner, observations, source_completions, av_completions, published, source_join, av_join, automatic_custody))),
    };
    let observed_checkpoint = match trial_http_checkpoint::prepare(task, cx, clock, observation.root.join("observation"), observation_plan, reread, observation.certificate).await {
        Ok(checkpoint) => checkpoint,
        Err(reason) => return Err(stopped("serializer observation checkpoint requires inspection", (checkpoint, detached, source_owner, av_owner, observations, source_completions, av_completions, published, source_join, av_join, reason, automatic_custody))),
    };
    let restoration = if restore_after {
        match trial_http_restore::run(cx, task, clock, http, &checkpoint, conditions, authority, leases, effects, run_id, resource, &authorize).await {
            Ok(outcome) => match trial_http_restore::anchor(cx, task, clock, &checkpoint, conditions, &observation, outcome, &authorize).await {
                Ok(anchored) => Some(anchored),
                Err(error) => return Err(stopped("HTTP restoration checkpoint requires inspection", (checkpoint, observed_checkpoint, detached, source_owner, av_owner, observations, source_completions, av_completions, published, source_join, av_join, error, automatic_custody))),
            },
            Err(error) => return Err(stopped("HTTP restoration requires reconciliation", (checkpoint, observed_checkpoint, detached, source_owner, av_owner, observations, source_completions, av_completions, published, source_join, av_join, error, automatic_custody))),
        }
    } else { None };
    if restoration.is_some() {
        println!("trial_http_restore=readback_matches restored_checkpoint=anchored camera_identity=unverified effects=reconciliation_required");
    }
    let fss_reference::unifi_direct::http_stream::media::Detached { camera_claim, permit, readback, comparison, pipeline } = detached;
    let retirement = pipeline.retire();
    let unclosed = retirement.recorder.pending.iter().map(|record| record.bytes().len()).sum::<usize>();
    let unframed = retirement.ingress.framing.bytes().len()
        .saturating_add(retirement.ingress.buffered.as_ref().map_or(0, |v| v.source.bytes().len().saturating_sub(v.appended)))
        .saturating_add(retirement.ingress.source.pending.as_ref().map_or(0, |v| v.bytes().len()));
    if source_claim != camera_claim {
        return Err(stopped("final source camera claim changed", (checkpoint, observed_checkpoint, source_owner, av_owner,
            observations, source_completions, av_completions, published, source_join, av_join, retirement,
            camera_claim, permit, readback, comparison, restoration, automatic_custody)));
    }
    let final_tail = if supervised_mode {
        match Box::pin(archive_final_tail(retirement, source_owner, key, camera_claim, retention,
            task, cx, clock, admission)).await {
            Ok(tail) => {
                println!("trial_http_av_final_tail=verified records={} capture_time=unknown coverage=unproven", tail.records);
                Ok(tail)
            },
            Err(error) => return Err(stopped("supervised final source requires reconciliation", (checkpoint,
                observed_checkpoint, av_owner, observations, source_completions, av_completions, published,
                source_join, av_join, camera_claim, permit, readback, comparison, restoration, automatic_custody, error))),
        }
    } else {
        Err((source_owner, retirement))
    };
    println!("trial_http_av_record=published decoded_width={} decoded_height={} fragments={} video_samples={} audio_frames={} source_unclosed_bytes={} source_unframed_bytes={} audio_configuration={} continuous=false readbacks=consistent observation_checkpoint=anchored effect=reconciliation_required",
        dimensions[0], dimensions[1], published.len(), video_total, audio_total, unclosed, unframed,
        if supplied_audio.is_some() { "supplied_unverified" } else { "in_band" });
    let _custody = (checkpoint, observed_checkpoint, final_tail, av_owner, observations, source_completions,
        av_completions, published, source_join, av_join, camera_claim, permit, readback, comparison, restoration, automatic_custody);
    Ok(())
}
