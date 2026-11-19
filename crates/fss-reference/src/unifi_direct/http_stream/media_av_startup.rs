#![forbid(unsafe_code)]
//! Bounded source archival while bootstrapping an HTTP-started A/V stream.
//!
//! This composes the existing bootstrap, standalone-source worker and A/V
//! archive driver. Its optional guarded start dispatches one already authorized
//! camera request; it does not authenticate the camera, infer capture time,
//! reconnect, or establish a retention duration.

use std::time::Duration;

use asupersync::{Cx, io::{AsyncRead, AsyncWrite}, time::timeout_at};
use fss_container::flv_avc::SourceKey;
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_runtime::{effect::CommittedEffect, execution::TaskCx};

use super::{media, media_av_archive, media_av_bootstrap};
use crate::unifi_direct::{
    AudioCodec, VideoCodec, av_owned_sink, av_unknown_worker_guard::BootstrapResources, av_worker,
    camera_http, listener,
    metered::MeteredClock, pipeline, recording, recording_storage, retirement_source,
    source_coordinator::{ArchiveAdmission, Coordinator}, source_worker,
};

/// A rejected attachment retains all original owners and inputs.
#[must_use]
pub struct AttachRefusal {
    /// HTTP-started source, readback and effect.
    pub connected: media::Connected,
    /// Exclusive source and A/V archive resources.
    pub storage: recording_storage::Created,
    /// Caller-supplied retention decision.
    pub retention: ContentDigest,
    /// Original bootstrap policy.
    pub policy: av_owned_sink::BootstrapPolicy,
    /// Caller-supplied camera claim.
    pub camera_claim: ContentDigest,
    /// Explicitly supplied AAC configuration, if any, returned unchanged.
    pub supplied_unverified_audio: Option<[u8; 2]>,
}

/// Camera request, archive owners and policy retained before guarded startup.
pub struct Start<'a> {
    /// Already authorized camera-start request.
    pub request: media::Request<'a>,
    /// Exclusive source and A/V archive owners.
    pub storage: recording_storage::Created,
    /// Caller-supplied source-retention decision identity.
    pub retention: ContentDigest,
    /// Bootstrap timing and resource bounds.
    pub policy: av_owned_sink::BootstrapPolicy,
    /// Optional caller-supplied AAC configuration; its source and epoch remain
    /// unverified and are recorded as such in the resulting archive.
    pub supplied_unverified_audio: Option<[u8; 2]>,
}

/// Payload-free reason guarded startup refused before the camera request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartPreflight {
    /// Source, listener, task, codec, or archive bindings disagree.
    Binding,
    /// A statically invalid retention decision or bound was supplied.
    Policy,
    /// The current runtime lacks the required blocking worker pool.
    MissingBlockingPool,
    /// Cancellation was observed before dispatch.
    Cancelled,
}

/// Stopped startup retains its remaining effect and archive owners.
#[must_use = "retain or reconcile the returned effect and archive owners"]
pub enum StartRefusal<'a> {
    /// No camera request was sent.
    Preflight {
        /// Static refusal classification.
        reason: StartPreflight,
        /// All original request and storage owners.
        inputs: Box<Start<'a>>,
        /// Original unclaimed effect permit.
        permit: CommittedEffect,
    },
    /// Media startup stopped; its permit may require reconciliation.
    Media {
        /// Media refusal and exact retained effect permit.
        refusal: media::Refusal,
        /// Unconsumed archive owners.
        storage: recording_storage::Created,
        /// Original retention identity.
        retention: ContentDigest,
        /// Original bootstrap policy.
        policy: av_owned_sink::BootstrapPolicy,
        /// Original explicitly unverified AAC configuration.
        supplied_unverified_audio: Option<[u8; 2]>,
    },
    /// A connected source could not attach to its archive owners.
    Attach(Box<AttachRefusal>),
}

fn valid_policy(retention: ContentDigest, policy: av_owned_sink::BootstrapPolicy) -> bool {
    retention.algorithm() == DigestAlgorithm::Sha256
        && !retention.is_laboratory()
        && retention.bytes() != [0; 32]
        && policy.media_limits.validate().is_ok()
        && policy.evidence_limits.validate().is_ok()
        && policy.max_separation_ms < (1 << 31)
        && policy.jitter_ms <= 100
        && (1..=fss_packet::extended_flv::aac_clock::MAX_EPOCH_FRAMES).contains(&policy.max_epoch_frames)
        && (1..=policy.media_limits.max_samples).contains(&policy.max_audio_frames)
}

/// Validate known prerequisites, then dispatch one already committed request.
/// The AAC-dependent jitter bound and camera behavior remain unverified until
/// media is observed. Recovered rollover custody requires a successful drained
/// `av_recovered_startup` verification before any camera request. Preflight is
/// not a space reservation, retention grant, sender authentication, effect
/// settlement, or guarantee against later failure.
pub async fn start<'a, 'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>(
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    http: &mut camera_http::Owner<'_, '_, '_, IO>,
    listener: &mut listener::Listener<'_, '_, '_>,
    inputs: Box<Start<'a>>,
    permit: CommittedEffect,
    authorize_observation: impl Fn(std::net::Ipv4Addr, u64) -> bool,
) -> Result<Driver, Box<StartRefusal<'a>>> {
    Box::pin(start_with_response(task, cx, clock, http, listener, inputs, permit, authorize_observation, &mut |_, _| Ok(()))).await
}

/// Start A/V capture with caller-owned custody of the untrusted response.
/// A custody failure retains the permit and never authorizes a retry.
pub async fn start_with_response<'a, 'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>(
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    http: &mut camera_http::Owner<'_, '_, '_, IO>,
    listener: &mut listener::Listener<'_, '_, '_>,
    inputs: Box<Start<'a>>,
    permit: CommittedEffect,
    authorize_observation: impl Fn(std::net::Ipv4Addr, u64) -> bool,
    record_response: &mut media::ResponseRecorder<'_>,
) -> Result<Driver, Box<StartRefusal<'a>>> {
    let key = inputs.request.recorder.source_key();
    let camera = inputs.request.current.camera;
    let av = &inputs.storage.av;
    let reason = if cx.checkpoint().is_err() {
        Some(StartPreflight::Cancelled)
    } else if !cx.has_timer()
        || !clock.matches(task, cx)
        || !http.matches_media_listener(listener)
        || !listener.matches_camera_binding(&clock, &inputs.request.plan.resource())
        || inputs.request.plan.operation() != super::Operation::Start
        || inputs.request.plan.start.video != VideoCodec::H264
        || inputs.request.plan.start.audio != AudioCodec::Aac
        || inputs.request.current.listener != listener.local_addr()
        || !listener::valid_accept_config(inputs.request.chunk_bytes, inputs.request.max_bytes, inputs.request.wait)
        || key.connection == 0 || key.generation == 0
        || !inputs.storage.coordinator.matches_binding(key, camera)
        || inputs.storage.coordinator.source_status() != source_worker::Status::Idle
        || !inputs.storage.coordinator.ready_for_start()
        || !(1..=100_000_000_000).contains(&av.work_limit)
        || av.journal.pending().is_some() || av.journal.replay_pin().is_some()
        || av.keeper.target() != av.journal.anchor()
        || av.journal.confirmed().is_some_and(|pin| pin.retention != inputs.retention)
        || av.rollover_custody.as_ref().is_some_and(|custody| !custody.startup_verified(&av.journal, &av.keeper))
        || av.deployment.publisher().is_poisoned()
    {
        Some(StartPreflight::Binding)
    } else if !valid_policy(inputs.retention, inputs.policy)
        || !media_av_bootstrap::valid_supplied_audio(inputs.supplied_unverified_audio, inputs.policy)
        || !inputs.storage.coordinator.matches_retention(inputs.retention)
        || !(1024..=64 * 1024 * 1024).contains(&av.limits.maximum_spool_object_bytes)
        || !(1..=262_144).contains(&av.limits.maximum_ledger_deltas)
        || av.deployment.publisher().limits().spool.max_object_bytes > av.limits.maximum_spool_object_bytes
    {
        Some(StartPreflight::Policy)
    } else if cx.blocking_pool_handle().is_none() {
        Some(StartPreflight::MissingBlockingPool)
    } else {
        None
    };
    if let Some(reason) = reason {
        return Err(Box::new(StartRefusal::Preflight { reason, inputs, permit }));
    }
    let Start { request, storage, retention, policy, supplied_unverified_audio } = *inputs;
    let connected = match Box::pin(media::start_with_response(http, listener, request, permit, authorize_observation, record_response)).await {
        Ok(connected) => connected,
        Err(refusal) => return Err(Box::new(StartRefusal::Media { refusal, storage, retention, policy, supplied_unverified_audio })),
    };
    Driver::attach_with_unverified_audio(connected, storage, retention, policy, camera, supplied_unverified_audio).map_err(|refusal| Box::new(StartRefusal::Attach(refusal)))
}

/// A bootstrap decision or source archival result.
#[must_use]
pub enum Step {
    /// The bootstrap retained a configuration or first segment.
    Retained,
    /// An original source entered the standalone-source worker.
    SourceOffered {
        /// Why the recorder returned this source separately.
        disposition: recording::SourceDisposition,
        /// Same-step audio interpretation, still caller-owned.
        audio: Option<pipeline::AudioEvent>,
    },
    /// An audio interpretation paired with a source retained by the recorder.
    Buffered(Option<pipeline::AudioEvent>),
    /// The source worker returned its unchanged input and paired observation.
    SourceRefused {
        /// Original worker refusal.
        refusal: source_worker::OfferRefusal,
        /// Same-step audio interpretation.
        audio: Option<pipeline::AudioEvent>,
    },
    /// A source publication attempt started.
    SourceStarted,
    /// A source attempt is still running.
    SourceRunning,
    /// A fully drained attempt, retained by the caller for inspection.
    SourceCompleted(source_worker::Completion),
    /// Start was refused; the source remains held and retry is disarmed.
    StartRefused(av_worker::StartError),
    /// A retained source needs explicit retry authorization.
    SourceRetryRequired,
    /// Source custody is fenced or unavailable.
    SourceUnavailable,
    /// A bounded media result that cannot be transferred, returned intact.
    Forward {
        /// Original recorder result.
        push: recording::Push,
        /// Same-step audio interpretation.
        audio: Option<pipeline::AudioEvent>,
    },
    /// Bootstrap made bounded progress without emitting a record.
    Progress,
    /// No media arrived during the bounded wait.
    Idle,
    /// Bootstrap has the inputs and source archival has drained.
    Ready,
    /// Media ended before bootstrap completed.
    Eof,
    /// The source reached its configured byte limit.
    LimitReached,
    /// The connected pipeline refused; any pending source remains owned.
    MediaError(pipeline::Error),
    /// A new audio configuration or other fence requires reconciliation.
    Fenced,
    /// Invalid wait or task/clock binding.
    Configuration,
    /// Cancellation or a previous refusal stopped admission.
    Halted,
}

impl Step {
    /// Whether this event carries no additional unaccepted source record and
    /// permits attempting retirement after the source worker has drained.
    /// Collector inputs remain separately owned and are not thereby archived.
    pub fn has_retirable_tail(&self) -> bool {
        matches!(self, Self::Eof | Self::LimitReached
            | Self::MediaError(pipeline::Error::Ingress(crate::unifi_direct::ingress::Error::Source(
                fss_runtime::tcp_ingress::IngressError::BudgetExhausted
            )))
            | Self::MediaError(pipeline::Error::Ingress(crate::unifi_direct::ingress::Error::Framing(
                fss_packet::extended_flv::stream::Error::TrailerPolicyMismatch
            ))))
    }
}

/// All owners retained while bootstrap and source archival are in progress.
#[must_use = "drain the source worker and reconcile the camera effect"]
pub struct Parts {
    /// Source and bounded A/V collector.
    pub bootstrap: media_av_bootstrap::Driver,
    /// Standalone-source archive worker.
    pub source: source_worker::Worker,
    /// Exclusive A/V archive resources.
    pub av: Box<BootstrapResources>,
    /// Caller-supplied connection and generation claim.
    pub key: SourceKey,
    /// Caller-supplied camera claim.
    pub camera_claim: ContentDigest,
    /// One first or explicitly retried source attempt is armed.
    pub source_armed: bool,
    /// Further media admission has stopped.
    pub halted: bool,
}

/// Bootstrap inputs and effect retained outside the source archival driver.
/// Collector originals remain here even if copies are separately published.
#[must_use = "retain bootstrap inputs and reconcile the camera effect"]
pub struct RetirementAssets {
    /// Caller-bound camera claim, not independent authentication.
    pub camera_claim: ContentDigest,
    /// Committed camera-start effect requiring reconciliation.
    pub permit: CommittedEffect,
    /// Private camera serializer readback.
    pub readback: crate::unifi_direct::camera_api::VideoSerializers,
    /// Redacted comparison of the readback.
    pub comparison: super::ReadbackObservation,
    /// Original first-segment and configuration owners, possibly incomplete.
    pub collector: crate::unifi_direct::av_bootstrap::Collector,
    /// A/V archive resources not transferred to a worker.
    pub av: Box<BootstrapResources>,
    /// Collector's fence observation before retirement.
    pub fenced: bool,
}

/// Bootstrap effect and collector plus a separately archivable pipeline tail.
#[must_use = "retain collector and effect owners and drain or retain the tail"]
pub struct Retired {
    /// Bootstrap and camera-effect custody.
    pub assets: RetirementAssets,
    /// Number of collector-source copies included in the checked plan.
    pub collector_copies: usize,
    /// Checked source ranges and their exclusive archive worker.
    pub tail: retirement_source::Driver,
}

/// Refusal retains every owner at the stage where retirement stopped.
#[must_use = "retain or reconcile all returned owners"]
pub enum RetirementRefusal {
    /// Admission is still active, a worker is not idle, or bindings disagree.
    NotDrained(Parts),
    /// Pipeline range validation refused without consuming its retirement.
    TailPlan {
        /// Collector, A/V resources and camera effect.
        assets: RetirementAssets,
        /// Original source archive worker.
        source: source_worker::Worker,
        /// Complete pipeline retirement and its validation reason.
        refusal: retirement_source::Refusal,
    },
    /// Collector-copy preparation refused before mutating the checked plan.
    CollectorPlan {
        /// Collector, A/V resources and camera effect.
        assets: RetirementAssets,
        /// Original source archive worker.
        source: source_worker::Worker,
        /// Unchanged checked pipeline-tail plan.
        plan: retirement_source::Plan,
        /// Copy or range validation refusal.
        reason: retirement_source::Error,
    },
    /// Tail was valid but the archive worker refused attachment.
    TailDriver {
        /// Collector, A/V resources and camera effect.
        assets: RetirementAssets,
        /// Worker, checked plan, and source claims.
        parts: retirement_source::DriverParts,
    },
}

impl Parts {
    /// Prepare the stopped pipeline tail and exact collector-source copies.
    /// No I/O occurs. The collector retains its originals; a prepared plan
    /// is not a publication receipt and does not assert gap-free capture.
    pub fn prepare_tail_retirement(self) -> Result<Retired, RetirementRefusal> {
        if !self.halted || self.source_armed || self.source.status() != source_worker::Status::Idle
            || self.bootstrap.source_key() != self.key
            || self.bootstrap.camera_claim() != self.camera_claim
        {
            return Err(RetirementRefusal::NotDrained(self));
        }
        let Parts { bootstrap, source, av, key, camera_claim, .. } = self;
        let bootstrap = bootstrap.into_parts();
        let detached = bootstrap.connected.into_parts();
        let assets = RetirementAssets {
            camera_claim, permit: detached.permit, readback: detached.readback,
            comparison: detached.comparison, collector: bootstrap.collector,
            av, fenced: bootstrap.fenced,
        };
        let mut plan = match retirement_source::Plan::new(detached.pipeline.retire()) {
            Ok(plan) => plan,
            Err(refusal) => return Err(RetirementRefusal::TailPlan { assets, source, refusal }),
        };
        let collector_copies = match plan.include_collector_copies(&assets.collector) {
            Ok(count) => count,
            Err(reason) => return Err(RetirementRefusal::CollectorPlan { assets, source, plan, reason }),
        };
        let tail = match retirement_source::Driver::begin(source, plan, key, camera_claim) {
            Ok(tail) => tail,
            Err(parts) => return Err(RetirementRefusal::TailDriver { assets, parts }),
        };
        Ok(Retired { assets, collector_copies, tail })
    }
}

/// Owns one bootstrap and its separate-source archive worker.
#[must_use = "drain the source worker or recover all retained owners"]
pub struct Driver {
    parts: Parts,
}

struct BoxedBootstrapHandoff {
    handoff: media_av_bootstrap::Handoff,
    source: source_worker::Worker,
    av: Box<BootstrapResources>,
    key: SourceKey,
    camera_claim: ContentDigest,
}

struct BoxedArchiveHandoff {
    handoff: media_av_bootstrap::ArchiveHandoff,
    source: source_worker::Worker,
    key: SourceKey,
    camera_claim: ContentDigest,
}

/// Every failed transition retains all resources not transferred to an event.
#[must_use]
pub enum TransitionRefusal {
    /// Bootstrap or a source publication has not reached a transferable state.
    NotReady(Driver),
    /// A/V bootstrap validation refused its exact inputs.
    Bootstrap {
        /// Original bootstrap refusal and connected owner.
        refusal: media_av_bootstrap::HandoffRefusal,
        /// Original source worker.
        source: source_worker::Worker,
        /// Unconsumed A/V archive resources.
        av: Box<BootstrapResources>,
        /// Caller-supplied source claim.
        key: SourceKey,
        /// Caller-supplied camera claim.
        camera_claim: ContentDigest,
    },
    /// Converting bootstrap to an A/V worker refused all affected owners.
    Archive {
        /// Refusal retaining the connected source and A/V resources.
        refusal: Box<media_av_bootstrap::ArchiveHandoffRefusal>,
        /// Original source worker.
        source: source_worker::Worker,
        /// Caller-supplied source claim.
        key: SourceKey,
        /// Caller-supplied camera claim.
        camera_claim: ContentDigest,
    },
    /// The completed bootstrap could not attach to its source worker.
    Attach(Box<media_av_archive::AttachRefusal>),
    /// The final driver retained every owner but could not seal its prefix.
    Seal(media_av_archive::Driver),
}

impl Driver {
    /// Whether a bootstrap source archive attempt still requires joining.
    pub fn is_source_running(&self) -> bool { self.parts.source.is_running() }

    /// Install a bounded stream-name probe before bootstrap or source work.
    /// A match is an untrusted source claim, not camera authentication.
    pub fn begin_name_probe(
        &mut self, probe: fss_packet::extended_flv::stream::NameProbeOwner,
    ) -> Result<(), fss_packet::extended_flv::stream::NameProbeOwner> {
        if self.parts.halted || self.parts.source_armed
            || self.parts.source.status() != source_worker::Status::Idle {
            return Err(probe);
        }
        self.parts.bootstrap.begin_name_probe(probe)
    }

    /// Advance the installed probe without consuming bootstrap source records.
    pub async fn probe_name_step(
        &mut self, task: &TaskCx<'_>, cx: &Cx, now: fss_core::TimestampNs,
    ) -> Result<crate::unifi_direct::ingress::NameProbeStep, pipeline::NameProbeError> {
        if self.parts.halted { return Err(pipeline::NameProbeError::NotFresh); }
        self.parts.bootstrap.probe_name_step(task, cx, now).await
    }

    /// Return the name-probe owner while retaining the buffered source.
    pub fn take_name_probe(&mut self) -> Option<fss_packet::extended_flv::stream::NameProbeOwner> {
        self.parts.bootstrap.take_name_probe()
    }

    /// Attach compatible idle storage before consuming ordinary media.
    pub fn attach(
        connected: media::Connected,
        storage: recording_storage::Created,
        retention: ContentDigest,
        policy: av_owned_sink::BootstrapPolicy,
        camera_claim: ContentDigest,
    ) -> Result<Self, Box<AttachRefusal>> {
        Self::attach_with_unverified_audio(connected, storage, retention, policy, camera_claim, None)
    }

    /// Attach an explicit, unverified AAC configuration to this connection.
    /// A later in-band configuration fences processing for reconciliation.
    pub fn attach_with_unverified_audio(
        connected: media::Connected,
        storage: recording_storage::Created,
        retention: ContentDigest,
        policy: av_owned_sink::BootstrapPolicy,
        camera_claim: ContentDigest,
        supplied_unverified_audio: Option<[u8; 2]>,
    ) -> Result<Self, Box<AttachRefusal>> {
        let key = connected.pipeline.source_key();
        if key.connection == 0 || key.generation == 0
            || connected.camera_claim() != camera_claim
            || !storage.coordinator.matches_binding(key, camera_claim)
            || storage.coordinator.source_status() != source_worker::Status::Idle
            || !storage.coordinator.ready_for_start()
            || !storage.coordinator.matches_retention(retention)
            || !valid_policy(retention, policy)
            || !media_av_bootstrap::valid_supplied_audio(supplied_unverified_audio, policy)
            || !(1..=100_000_000_000).contains(&storage.av.work_limit)
        {
            return Err(Box::new(AttachRefusal { connected, storage, retention, policy, camera_claim, supplied_unverified_audio }));
        }
        let bootstrap = match media_av_bootstrap::Driver::attach_with_unverified_audio(connected, retention, policy, supplied_unverified_audio) {
            Ok(bootstrap) => bootstrap,
            Err(refusal) => return Err(Box::new(AttachRefusal {
                connected: refusal.connected, storage, retention, policy, camera_claim, supplied_unverified_audio: refusal.supplied_unverified_audio,
            })),
        };
        Ok(Self { parts: Parts {
            bootstrap, source: storage.coordinator.into_worker(), av: storage.av,
            key, camera_claim, source_armed: false, halted: false,
        } })
    }

    /// Authorize one more attempt for an already retained source.
    pub fn authorize_source_retry(&mut self) -> bool {
        if !self.parts.halted && !self.parts.source_armed && self.parts.source.status() == source_worker::Status::Pending {
            self.parts.source_armed = true;
            true
        } else { false }
    }

    /// Stop media admission and request cancellation of the source attempt.
    pub fn abort(&mut self) {
        self.parts.halted = true;
        self.parts.source_armed = false;
        self.parts.source.abort();
    }

    /// Join the exact source attempt, returning its completion once.
    pub async fn join_source(&mut self) -> Option<source_worker::Completion> {
        self.parts.source.join().await
    }

    /// Recover every owner after source work has drained.
    pub fn into_parts(self) -> Result<Parts, Self> {
        if self.parts.source.is_running() { Err(self) } else { Ok(self.parts) }
    }

    /// Construct the post-bootstrap driver after all accepted prefix records drain.
    pub fn finish(self) -> Result<media_av_archive::Driver, Box<TransitionRefusal>> {
        if self.parts.halted || self.parts.source.status() != source_worker::Status::Idle
            || !self.parts.bootstrap.is_ready()
        {
            return Err(Box::new(TransitionRefusal::NotReady(self)));
        }
        let Parts { bootstrap, source, av, key, camera_claim, .. } = self.parts;
        let handoff = match bootstrap.bootstrap() {
            Ok(handoff) => handoff,
            Err(refusal) => return Err(Box::new(TransitionRefusal::Bootstrap { refusal, source, av, key, camera_claim })),
        };
        let handoff = match handoff.into_archive(*av) {
            Ok(handoff) => handoff,
            Err(refusal) => return Err(Box::new(TransitionRefusal::Archive { refusal, source, key, camera_claim })),
        };
        let mut driver = media_av_archive::Driver::attach(handoff, Coordinator::new(source, key, camera_claim))
            .map_err(|refusal| Box::new(TransitionRefusal::Attach(refusal)))?;
        if !driver.seal_prefix() { return Err(Box::new(TransitionRefusal::Seal(driver))); }
        Ok(driver)
    }

    /// Finish the same transition in bounded, separately stacked phases.
    /// Every refusal has the same owner-custody semantics as `finish`.
    pub fn finish_boxed(self: Box<Self>) -> Result<Box<media_av_archive::Driver>, Box<TransitionRefusal>> {
        if self.parts.halted || self.parts.source.status() != source_worker::Status::Idle
            || !self.parts.bootstrap.is_ready()
        {
            return Err(Box::new(TransitionRefusal::NotReady(*self)));
        }
        let handoff = Self::boxed_bootstrap(self)?;
        let handoff = Self::boxed_archive(handoff)?;
        Self::boxed_attach(handoff)
    }

    #[inline(never)]
    fn boxed_bootstrap(driver: Box<Self>) -> Result<Box<BoxedBootstrapHandoff>, Box<TransitionRefusal>> {
        let Parts { bootstrap, source, av, key, camera_claim, .. } = driver.parts;
        match bootstrap.bootstrap() {
            Ok(handoff) => Ok(Box::new(BoxedBootstrapHandoff { handoff, source, av, key, camera_claim })),
            Err(refusal) => Err(Box::new(TransitionRefusal::Bootstrap { refusal, source, av, key, camera_claim })),
        }
    }

    #[inline(never)]
    fn boxed_archive(stage: Box<BoxedBootstrapHandoff>) -> Result<Box<BoxedArchiveHandoff>, Box<TransitionRefusal>> {
        let BoxedBootstrapHandoff { handoff, source, av, key, camera_claim } = *stage;
        match handoff.into_archive(*av) {
            Ok(handoff) => Ok(Box::new(BoxedArchiveHandoff { handoff, source, key, camera_claim })),
            Err(refusal) => Err(Box::new(TransitionRefusal::Archive { refusal, source, key, camera_claim })),
        }
    }

    #[inline(never)]
    fn boxed_attach(stage: Box<BoxedArchiveHandoff>) -> Result<Box<media_av_archive::Driver>, Box<TransitionRefusal>> {
        let BoxedArchiveHandoff { handoff, source, key, camera_claim } = *stage;
        let mut driver = media_av_archive::Driver::attach(handoff, Coordinator::new(source, key, camera_claim))
            .map_err(|refusal| Box::new(TransitionRefusal::Attach(refusal)))?;
        if !driver.seal_prefix() { return Err(Box::new(TransitionRefusal::Seal(driver))); }
        Ok(Box::new(driver))
    }

    /// Drive at most one source, media, or archive decision.
    pub async fn step<'scope, 'task>(
        &mut self,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        wait: Duration,
        source_archive: ArchiveAdmission<'_>,
    ) -> Step {
        if self.parts.halted { return Step::Halted; }
        if wait.is_zero() || wait > Duration::from_secs(30) || !clock.matches(task, cx)
            || !self.parts.bootstrap.is_bound_to_task(task) {
            return Step::Configuration;
        }
        if cx.checkpoint().is_err() { self.abort(); return Step::Halted; }
        match self.parts.source.status() {
            source_worker::Status::Running => return match timeout_at(cx.now() + wait, self.parts.source.join()).await {
                Ok(Some(done)) => Step::SourceCompleted(done), Ok(None) => Step::SourceUnavailable, Err(_) => Step::SourceRunning,
            },
            source_worker::Status::Pending if self.parts.source_armed => {
                self.parts.source_armed = false;
                return match self.parts.source.start(task, cx, clock, source_archive.resource, source_archive.cost) {
                    Ok(()) => Step::SourceStarted, Err(error) => Step::StartRefused(error),
                };
            }
            source_worker::Status::Pending => return Step::SourceRetryRequired,
            source_worker::Status::Fenced | source_worker::Status::Unavailable => return Step::SourceUnavailable,
            source_worker::Status::Idle => (),
        }
        match self.parts.bootstrap.step(task, cx, clock, wait).await {
            media_av_bootstrap::Step::Retained => Step::Retained,
            media_av_bootstrap::Step::Forward { push, audio } => {
                if matches!(&push, recording::Push::Source { disposition: recording::SourceDisposition::Configuration, .. })
                    || matches!(audio.as_ref(), Some(pipeline::AudioEvent::Fenced(_)) | Some(pipeline::AudioEvent::Observed(fss_packet::extended_flv::aac_track::Observation::Configuration { .. }))) {
                    self.parts.halted = true;
                    return Step::Forward { push, audio };
                }
                match push {
                    recording::Push::Source { record, disposition } => match self.parts.source.offer(source_worker::Input::Original {
                        record, key: self.parts.key, disposition, camera_claim: self.parts.camera_claim,
                    }) {
                        Ok(()) => { self.parts.source_armed = true; Step::SourceOffered { disposition, audio } },
                        Err(refusal) => { self.parts.halted = true; Step::SourceRefused { refusal, audio } },
                    },
                    recording::Push::Buffered => Step::Buffered(audio),
                    push => { self.parts.halted = true; Step::Forward { push, audio } },
                }
            }
            media_av_bootstrap::Step::Progress => Step::Progress,
            media_av_bootstrap::Step::Idle => Step::Idle,
            media_av_bootstrap::Step::Ready => Step::Ready,
            media_av_bootstrap::Step::Eof => { self.parts.halted = true; Step::Eof },
            media_av_bootstrap::Step::LimitReached => { self.parts.halted = true; Step::LimitReached },
            media_av_bootstrap::Step::MediaError(error) => { self.parts.halted = true; Step::MediaError(error) },
            media_av_bootstrap::Step::Fenced => { self.parts.halted = true; Step::Fenced },
            media_av_bootstrap::Step::Configuration => Step::Configuration,
        }
    }
}
