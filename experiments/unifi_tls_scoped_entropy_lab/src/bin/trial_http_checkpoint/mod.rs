#![forbid(unsafe_code)]
//! Pre-effect, private checkpoint for the camera-local HTTP experiment.
//! No camera request or stream listener is created by this module.

use std::{
    fs::{self, DirBuilder, File},
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite},
};
use fss_core::{BudgetVector, CanonicalDecoder, CanonicalEncoder, ContentDigest, RuntimeGrant, json_input::Value};
use fss_object::{
    HostSpoolIo, SpoolLimits, StagingSpool,
    effect_journal::{EffectJournalLimits, FileEffectJournal, FileTrustedRootPinRetainer},
};
use fss_packet::extended_flv::stream::Framer;
use fss_reference::unifi_direct::{
    camera_api::{HandoffResponseObservation, SerializerAuthority, VideoSerializers},
    camera_http,
    http_stream::{
        Plan, Preconditions,
        checkpoint::{self, Action, Anchored, Authority, Scope, Sealed, Stored, keyfile::KeyLease},
        media, media_archive, media_av_startup,
    },
    listener,
    metered::MeteredClock,
    recording::Recorder,
    av_owned_sink, recording_storage, video_bootstrap,
};
use fss_runtime::{
    drained_blocking::{self, WorkOutcome},
    effect::{CommittedEffect, EffectCoordinator},
    effect_journal::{EffectPinRetainer, PinRetainedEffectJournal},
    execution::TaskCx,
};

pub(super) fn response_receipt(domain: &str, prepared: ContentDigest, observation: HandoffResponseObservation) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(domain);
    encoder.digest(prepared);
    match observation {
        HandoffResponseObservation::Empty => encoder.u8(0),
        HandoffResponseObservation::Other => encoder.u8(1),
        HandoffResponseObservation::Object { success, status_code } => {
            encoder.u8(2);
            match success { None => encoder.u8(0), Some(false) => encoder.u8(1), Some(true) => encoder.u8(2) }
            match status_code { None => encoder.u8(0), Some(value) => { encoder.u8(1); encoder.i128(i128::from(value)); } }
        }
    }
    ContentDigest::sha256(&encoder.finish())
}

fn retain_start_response<'scope, 'task>(
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    effects: &mut EffectCoordinator,
    resource: &str,
    permit: &mut CommittedEffect,
    response: HandoffResponseObservation,
) -> Result<(), media::ResponseCustodyError> {
    cx.checkpoint().map_err(|_| media::ResponseCustodyError::Cancelled)?;
    let now = clock.now().map_err(|_| media::ResponseCustodyError::Cancelled)?;
    let mut cost = BudgetVector::ZERO;
    cost.storage_operations = 1;
    task.checkpoint_for(RuntimeGrant::ObjectStage, resource, now, &cost)
        .map_err(|_| media::ResponseCustodyError::Authority)?;
    let receipt = response_receipt("fss.unifi-direct.http-start-response.v1", permit.prepared().digest(), response);
    effects.adapter_accepted(permit, Some(receipt), now)
        .map_err(|_| media::ResponseCustodyError::Storage)?;
    println!("trial_http_start_response=journaled response=peer_claim effect=unsettled");
    Ok(())
}

/// Capture inputs are returned on a preflight refusal before any camera write.
pub struct Capture {
    pub framer: Framer,
    pub recorder: Recorder,
    pub storage: recording_storage::Created,
    pub policy: video_bootstrap::Policy,
    pub wait: Duration,
    pub chunk_bytes: usize,
    pub max_bytes: u64,
}

/// A/V inputs for one checkpointed start; supplied AAC stays explicitly unverified.
pub struct AvCapture {
    pub framer: Framer,
    pub recorder: Recorder,
    pub storage: recording_storage::Created,
    pub retention: ContentDigest,
    pub policy: av_owned_sink::BootstrapPolicy,
    pub supplied_unverified_audio: Option<[u8; 2]>,
    pub wait: Duration,
    pub chunk_bytes: usize,
    pub max_bytes: u64,
}

/// The checkpoint and exact A/V start result remain owned together.
#[must_use = "retain checkpoint custody and reconcile any camera effect"]
pub struct AvStartOutcome {
    pub checkpoint: Prepared,
    pub state: AvStartState,
}

/// Every refusal retains the applicable input, storage and effect owners.
#[must_use]
pub enum AvStartState {
    Started(media_av_startup::Driver),
    Preflight {
        reason: media_av_startup::StartPreflight,
        capture: AvCapture,
        permit: CommittedEffect,
    },
    Media {
        refusal: media::Refusal,
        storage: recording_storage::Created,
        retention: ContentDigest,
        policy: av_owned_sink::BootstrapPolicy,
        supplied_unverified_audio: Option<[u8; 2]>,
    },
    Attach(Box<media_av_startup::AttachRefusal>),
}

/// Dispatch a checkpoint-bound A/V start once, preserving all refusal owners.
/// This does not authenticate a camera, reconcile effects or prove continuity.
pub async fn start_av<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>(
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    http: &mut camera_http::Owner<'_, '_, '_, IO>,
    listener: &mut listener::Listener<'_, '_, '_>,
    checkpoint: Prepared,
    current: Preconditions,
    authority: &dyn SerializerAuthority,
    capture: AvCapture,
    permit: CommittedEffect,
    effects: &mut EffectCoordinator,
    resource: &str,
    authorize_observation: impl Fn(std::net::Ipv4Addr, u64) -> bool,
) -> AvStartOutcome {
    let AvCapture { framer, recorder, storage, retention, policy, supplied_unverified_audio, wait, chunk_bytes, max_bytes } = capture;
    let request = media::Request {
        plan: &checkpoint.plan, current, baseline: &checkpoint.baseline,
        checkpoint: &checkpoint.anchored, authority, wait, framer, recorder, chunk_bytes, max_bytes,
    };
    let inputs = Box::new(media_av_startup::Start { request, storage, retention, policy, supplied_unverified_audio });
    let mut retain_response = |permit: &mut CommittedEffect, response: HandoffResponseObservation| {
        retain_start_response(task, cx, clock, effects, resource, permit, response)
    };
    let state = match media_av_startup::start_with_response(task, cx, clock, http, listener, inputs, permit, authorize_observation, &mut retain_response).await {
        Ok(driver) => AvStartState::Started(driver),
        Err(refusal) => match *refusal {
            media_av_startup::StartRefusal::Preflight { reason, inputs, permit } => {
                let media_av_startup::Start { request, storage, retention, policy, supplied_unverified_audio } = *inputs;
                AvStartState::Preflight {
                    reason,
                    capture: AvCapture { framer: request.framer, recorder: request.recorder, storage, retention, policy, supplied_unverified_audio, wait: request.wait, chunk_bytes: request.chunk_bytes, max_bytes: request.max_bytes },
                    permit,
                }
            }
            media_av_startup::StartRefusal::Media { refusal, storage, retention, policy, supplied_unverified_audio } =>
                AvStartState::Media { refusal, storage, retention, policy, supplied_unverified_audio },
            media_av_startup::StartRefusal::Attach(refusal) => AvStartState::Attach(refusal),
        },
    };
    AvStartOutcome { checkpoint, state }
}

/// Outcome after attempting a start with the same live listener and checkpoint.
#[must_use = "retain checkpoint custody and reconcile any camera effect"]
pub struct StartOutcome {
    pub checkpoint: Prepared,
    pub state: StartState,
}

/// All outcomes preserve the remaining capture and effect owners.
#[must_use]
pub enum StartState {
    Started(media_archive::Driver),
    Preflight {
        reason: media_archive::StartPreflight,
        capture: Capture,
        permit: CommittedEffect,
    },
    Media {
        refusal: media::Refusal,
        storage: recording_storage::Created,
        policy: video_bootstrap::Policy,
    },
    Attach(media_archive::AttachRefusal),
}

/// Start with the checkpoint, effect permit, and the listener that remained
/// bound during checkpointing. No retry or effect settlement is performed.
pub async fn start<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>(
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    http: &mut camera_http::Owner<'_, '_, '_, IO>,
    listener: &mut listener::Listener<'_, '_, '_>,
    checkpoint: Prepared,
    current: Preconditions,
    authority: &dyn SerializerAuthority,
    capture: Capture,
    permit: CommittedEffect,
    effects: &mut EffectCoordinator,
    resource: &str,
    authorize_observation: impl Fn(std::net::Ipv4Addr, u64) -> bool,
) -> StartOutcome {
    let Capture {
        framer,
        recorder,
        storage,
        policy,
        wait,
        chunk_bytes,
        max_bytes,
    } = capture;
    let request = media::Request {
        plan: &checkpoint.plan,
        current,
        baseline: &checkpoint.baseline,
        checkpoint: &checkpoint.anchored,
        authority,
        wait,
        framer,
        recorder,
        chunk_bytes,
        max_bytes,
    };
    let mut retain_response = |permit: &mut CommittedEffect, response: HandoffResponseObservation| {
        retain_start_response(task, cx, clock, effects, resource, permit, response)
    };
    let state = match media_archive::start_with_response(
        task,
        cx,
        clock,
        http,
        listener,
        media_archive::Start {
            request,
            storage,
            policy,
        },
        permit,
        authorize_observation,
        &mut retain_response,
    )
    .await
    {
        Ok(driver) => StartState::Started(driver),
        Err(media_archive::StartRefusal::Preflight {
            reason,
            inputs,
            permit,
        }) => {
            let media_archive::Start {
                request,
                storage,
                policy,
            } = *inputs;
            StartState::Preflight {
                reason,
                capture: Capture {
                    framer: request.framer,
                    recorder: request.recorder,
                    storage,
                    policy,
                    wait: request.wait,
                    chunk_bytes: request.chunk_bytes,
                    max_bytes: request.max_bytes,
                },
                permit,
            }
        }
        Err(media_archive::StartRefusal::Media {
            refusal,
            storage,
            policy,
        }) => StartState::Media {
            refusal,
            storage,
            policy,
        },
        Err(media_archive::StartRefusal::Attach(refusal)) => StartState::Attach(refusal),
    };
    StartOutcome { checkpoint, state }
}

/// Owners needed by a later start, kept together with the anchored checkpoint.
#[must_use]
pub struct Prepared {
    pub plan: Plan,
    pub baseline: VideoSerializers,
    pub anchored: Anchored,
    pub key: KeyLease,
    pub spool: StagingSpool,
    pub journal: PinRetainedEffectJournal,
}

struct Policy(Scope);
impl Authority for Policy {
    fn permits(&self, cx: &Cx, scope: &Scope, action: Action) -> bool {
        *scope == self.0
            && cx.checkpoint().is_ok()
            && (action != Action::Entropy || cx.entropy().source_id() == "os")
    }
}

fn create(
    cx: Cx,
    root: &Path,
    plan: Plan,
    baseline: VideoSerializers,
    certificate: ContentDigest,
) -> Result<Prepared, &'static str> {
    let parent = root.parent().ok_or("checkpoint parent missing")?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| "checkpoint parent unavailable")?;
    if !root.is_absolute() || !metadata.file_type().is_dir() || metadata.mode() & 0o077 != 0 {
        return Err("checkpoint parent must be an existing private directory");
    }
    cx.checkpoint().map_err(|_| "checkpoint cancelled")?;
    DirBuilder::new()
        .mode(0o700)
        .create(root)
        .map_err(|_| "checkpoint directory creation refused")?;
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_| "checkpoint parent sync failed")?;
    let scope = Scope::from_plan(&plan, certificate).map_err(|_| "checkpoint scope refused")?;
    let policy = Policy(scope);
    let key = KeyLease::create(&cx, &policy, scope, &root.join("key"))
        .map_err(|_| "checkpoint key creation refused")?;
    let mut spool = StagingSpool::open(
        root.join("spool"),
        SpoolLimits::new(4, 1_000_000, 100_000, 8),
    )
    .map_err(|_| "checkpoint spool creation refused")?;
    let stored =
        Stored::capture_with_keyfile(&cx, &policy, scope, &key, &plan, &baseline, &mut spool)
            .map_err(|_| "checkpoint capture refused")?;
    let limits = EffectJournalLimits::default();
    let journal = FileEffectJournal::create(root.join("journal"), limits, Arc::new(HostSpoolIo))
        .map_err(|_| "checkpoint journal creation refused")?;
    let retainer = FileTrustedRootPinRetainer::create(
        root.join("pin"),
        limits,
        Arc::new(HostSpoolIo),
        ContentDigest::sha256(b"unifi-http-trial-checkpoint"),
    )
    .map_err(|_| "checkpoint pin creation refused")?;
    let mut journal = PinRetainedEffectJournal::new(Box::new(journal), Box::new(retainer))
        .map_err(|_| "checkpoint journal binding refused")?;
    let anchored = stored
        .anchor_with_keyfile(&cx, &policy, &key, &mut spool, &mut journal)
        .map_err(|_| "checkpoint anchor refused")?;
    Ok(Prepared {
        plan,
        baseline,
        anchored,
        key,
        spool,
        journal,
    })
}

/// Create and verify private checkpoint custody on a drained blocking worker.
/// A failure can leave partial create-only artifacts; inspect before retrying.
/// The parent and its ancestors are explicitly trusted by the caller.
pub async fn prepare<'scope, 'task>(
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    root: PathBuf,
    plan: Plan,
    baseline: VideoSerializers,
    certificate: ContentDigest,
) -> Result<Prepared, &'static str> {
    let resource = root.to_str().ok_or("checkpoint path must be UTF-8")?;
    let mut cost = BudgetVector::ZERO;
    cost.storage_operations = 32;
    task.checkpoint_for(
        RuntimeGrant::ObjectStage,
        resource,
        clock.now().map_err(|_| "checkpoint clock unavailable")?,
        &cost,
    )
    .map_err(|_| "checkpoint authority refused")?;
    let work = move |child: Cx| create(child, &root, plan, baseline, certificate);
    let mut worker = drained_blocking::start(cx, work).map_err(|_| "checkpoint worker refused")?;
    let receipt =
        match asupersync::time::timeout(cx.now(), Duration::from_secs(15), worker.join()).await {
            Ok(receipt) => receipt.ok_or("checkpoint worker already joined")?,
            Err(_) => {
                worker.abort();
                let _drained = worker.join().await;
                return Err("checkpoint worker timed out; inspect artifacts");
            }
        };
    if receipt.runtime.is_err() {
        return Err("checkpoint worker runtime failed; inspect artifacts");
    }
    match receipt.work {
        WorkOutcome::Finished(result) => result,
        WorkOutcome::NotStarted(_) => Err("checkpoint worker did not start"),
        WorkOutcome::Panicked | WorkOutcome::Indeterminate => {
            Err("checkpoint worker outcome indeterminate; inspect artifacts")
        }
    }
}

struct InspectionPolicy;
impl Authority for InspectionPolicy {
    fn permits(&self, cx: &Cx, _: &Scope, action: Action) -> bool {
        cx.checkpoint().is_ok()
            && matches!(
                action,
                Action::Anchor | Action::KeyRead | Action::KeyUse | Action::Open | Action::Inspect
            )
    }
}

fn open_disk(cx: &Cx, root: &Path) -> Result<(Scope, checkpoint::Retained, ContentDigest), &'static str> {
    if !root.is_absolute() {
        return Err("checkpoint path must be absolute");
    }
    let meta = fs::symlink_metadata(root).map_err(|_| "checkpoint directory unavailable")?;
    if !meta.file_type().is_dir() || meta.mode() & 0o077 != 0 {
        return Err("checkpoint directory must be private");
    }
    // Require the complete layout before opening; this inspection must not
    // create a missing spool directory or silently initialize missing state.
    for name in ["spool", "journal", "pin"] {
        let base = root.join(name);
        for path in [
            base.clone(),
            base.join("objects"),
            base.join("staging"),
            base.join("verified"),
        ] {
            if !fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_dir()) {
                return Err("checkpoint layout incomplete");
            }
        }
    }
    let limits = EffectJournalLimits::default();
    let mut retainer = FileTrustedRootPinRetainer::open_trusting_storage(
        root.join("pin"),
        limits,
        Arc::new(HostSpoolIo),
        ContentDigest::sha256(b"unifi-http-trial-checkpoint"),
    )
    .map_err(|_| "checkpoint pin recovery refused")?;
    let pin = retainer
        .retained_pin()
        .map_err(|_| "checkpoint pin unavailable")?
        .ok_or("checkpoint pin missing")?;
    let journal = FileEffectJournal::open(root.join("journal"), limits, Arc::new(HostSpoolIo), pin)
        .map_err(|_| "checkpoint journal recovery refused")?;
    let mut journal =
        PinRetainedEffectJournal::for_reconciliation(Box::new(journal), Box::new(retainer))
            .map_err(|_| "checkpoint journal binding refused")?;
    let policy = InspectionPolicy;
    let record = checkpoint::recover_record(cx, &policy, &mut journal, pin)
        .map_err(|_| "checkpoint record recovery refused")?;
    let key = KeyLease::load(cx, &policy, record.scope(), &root.join("key"))
        .map_err(|_| "checkpoint key recovery refused")?;
    let mut spool = StagingSpool::open(
        root.join("spool"),
        SpoolLimits::new(4, 1_000_000, 100_000, 8),
    )
    .map_err(|_| "checkpoint spool recovery refused")?;
    let bytes = spool
        .read_bounded(record.digest(), 100_000)
        .map_err(|_| "checkpoint ciphertext unavailable")?;
    let retained = key
        .with_key(cx, &policy, |key| {
            Sealed::from_bytes(&bytes)?.open(cx, &policy, record.scope(), key)
        })
        .map_err(|_| "checkpoint key use refused")?
        .map_err(|_| "checkpoint authentication refused")?;
    Ok((record.scope(), retained, record.digest()))
}

/// Compare a caller-selected, digest-verified source object with the stream
/// name inside an authenticated checkpoint. No source-to-journal association,
/// camera identity, effect settlement, or authorization follows from a match.
pub async fn compare_source_name<'scope, 'task>(
    task: &'scope TaskCx<'task>, cx: &'scope Cx, clock: MeteredClock<'scope, 'task>,
    checkpoint_root: PathBuf, source_spool: PathBuf, source_digest: ContentDigest,
) -> Result<(), &'static str> {
    if !checkpoint_root.is_absolute() || !source_spool.is_absolute()
        || source_digest.algorithm() != fss_core::DigestAlgorithm::Sha256 {
        return Err("invalid source comparison inputs");
    }
    let mut cost = BudgetVector::ZERO;
    cost.storage_operations = 32;
    cost.bytes = 128 * 1024;
    for path in [&checkpoint_root, &source_spool] {
        let resource = path.to_str().ok_or("comparison path must be UTF-8")?;
        task.checkpoint_for(RuntimeGrant::ObjectStage, resource, clock.now().map_err(|_| "comparison clock unavailable")?, &cost)
            .map_err(|_| "comparison authority refused")?;
    }
    task.checkpoint_for(RuntimeGrant::ReadMedia, source_spool.to_str().ok_or("comparison path must be UTF-8")?,
        clock.now().map_err(|_| "comparison clock unavailable")?, &BudgetVector::ZERO)
        .map_err(|_| "source media authority refused")?;
    let mut worker = drained_blocking::start(cx, move |child: Cx| {
        use fss_packet::extended_flv::{self, Parse, Tag};
        let (_, retained, _) = open_disk(&child, &checkpoint_root)?;
        let bytes = fss_object::read_verified_payload(&source_spool, source_digest, 64 * 1024, &HostSpoolIo)
            .map_err(|_| "source object unavailable or corrupt")?;
        let tag = match Tag::parse(&bytes, extended_flv::Limits::default()).map_err(|_| "source tag invalid")? {
            Parse::Complete(tag) if tag.wire_bytes().len() == bytes.len() => tag,
            _ => return Err("source tag incomplete or has trailing bytes"),
        };
        let claim = extended_flv::metadata::parse(tag).map_err(|_| "source metadata invalid")?;
        if claim.event() != "onMetaData" { return Err("source metadata event mismatch"); }
        let observed = claim.stream_name().ok_or("source stream name missing")?;
        let matches = retained.visit(&child, &InspectionPolicy, |_, forward| {
            let videos = forward.object()?.get("av")?.object()?.get("video")?.object()?;
            if videos.len() != 1 { return None; }
            let video = videos.values().next()?.object()?;
            let expected = video.get("avSerializer")?.object()?.get("parameters")?.object()?.get("streamName")?.text()?;
            Some(expected == observed)
        }).map_err(|_| "checkpoint inspection refused")?;
        match matches {
            Some(true) => Ok(()),
            Some(false) => Err("source stream name differs from checkpoint"),
            None => Err("checkpoint stream name missing or ambiguous"),
        }
    }).map_err(|_| "source comparison worker refused")?;
    let receipt = match asupersync::time::timeout(cx.now(), Duration::from_secs(15), worker.join()).await {
        Ok(receipt) => receipt.ok_or("source comparison worker already joined")?,
        Err(_) => { worker.abort(); let _ = worker.join().await; return Err("source comparison timed out"); }
    };
    if receipt.runtime.is_err() { return Err("source comparison runtime failed"); }
    match receipt.work {
        WorkOutcome::Finished(result) => result,
        WorkOutcome::NotStarted(_) => Err("source comparison did not start"),
        WorkOutcome::Panicked | WorkOutcome::Indeterminate => Err("source comparison outcome indeterminate"),
    }
}

/// Reconstruct the lab's H.264/AAC forward request from encrypted private
/// data, then compare the restore request against the retained journal digest.
/// Peer selection is a caller claim; no effect, identity, or causality follows.
pub async fn compare_restore_request<'scope, 'task>(
    task: &'scope TaskCx<'task>, cx: &'scope Cx, clock: MeteredClock<'scope, 'task>,
    checkpoint_root: PathBuf, peer: std::net::Ipv4Addr, expected: ContentDigest,
) -> Result<(), &'static str> {
    if !checkpoint_root.is_absolute() { return Err("checkpoint path must be absolute"); }
    let resource = checkpoint_root.to_str().ok_or("checkpoint path must be UTF-8")?;
    let mut cost = BudgetVector::ZERO; cost.storage_operations = 32;
    task.checkpoint_for(RuntimeGrant::ObjectStage, resource, clock.now().map_err(|_| "comparison clock unavailable")?, &cost)
        .map_err(|_| "checkpoint comparison authority refused")?;
    let mut worker = drained_blocking::start(cx, move |child: Cx| {
        use fss_reference::unifi_direct::{AudioCodec, StreamStart, VideoChannel, VideoCodec, handoff::Framing};
        let (scope, retained, _) = open_disk(&child, &checkpoint_root)?;
        let channel = match scope_claim(scope)?.3 {
            1 => VideoChannel::Video1, 2 => VideoChannel::Video2, 3 => VideoChannel::Video3,
            _ => return Err("checkpoint channel invalid"),
        };
        let channel_name = match channel { VideoChannel::Video1 => "video1", VideoChannel::Video2 => "video2", VideoChannel::Video3 => "video3" };
        let (name, destination) = retained.visit(&child, &InspectionPolicy, |_, forward| {
            let videos = forward.object()?.get("av")?.object()?.get("video")?.object()?;
            if videos.len() != 1 { return None; }
            let serializer = videos.get(channel_name)?.object()?.get("avSerializer")?.object()?;
            let parameters = serializer.get("parameters")?.object()?;
            if serializer.get("type")?.text()? != "extendedFlv" || parameters.get("withOpus")?.boolean()? { return None; }
            let name = parameters.get("streamName")?.text()?.to_owned();
            let destinations = serializer.get("destinations")?.array()?;
            if destinations.len() != 1 { return None; }
            let destination = destinations[0].text()?.strip_prefix("tcp://")?
                .strip_suffix("?retryInterval=1&connectTimeout=5")?.parse::<std::net::SocketAddrV4>().ok()?;
            Some((name, destination))
        }).map_err(|_| "checkpoint inspection refused")?.ok_or("forward request cannot be reconstructed")?;
        let start = StreamStart::new(channel, destination, VideoCodec::H264, AudioCodec::Aac, &name)
            .map_err(|_| "forward request invalid")?;
        let matches = retained.matches_restore_request(&child, &InspectionPolicy, checkpoint::RestoreRequestClaim {
            peer, forward: &start, generation: 1, forward_framing: Framing::ContentLength,
            restore_framing: Framing::ContentLength, expected,
        }).map_err(|_| "forward request or restore comparison invalid")?;
        if !matches { return Err("restore request does not match baseline"); }
        Ok(())
    }).map_err(|_| "restore comparison worker refused")?;
    let receipt = match asupersync::time::timeout(cx.now(), Duration::from_secs(15), worker.join()).await {
        Ok(receipt) => receipt.ok_or("restore comparison worker already joined")?,
        Err(_) => { worker.abort(); let _ = worker.join().await; return Err("restore comparison timed out"); }
    };
    if receipt.runtime.is_err() { return Err("restore comparison runtime failed"); }
    match receipt.work {
        WorkOutcome::Finished(result) => result,
        WorkOutcome::NotStarted(_) => Err("restore comparison did not start"),
        WorkOutcome::Panicked | WorkOutcome::Indeterminate => Err("restore comparison outcome indeterminate"),
    }
}

/// Verify a selected source graph against the local ledger and checkpoint, then
/// compare its source metadata name. This does not reopen the writer or prove
/// that the source-intent journal confirmed the graph. In particular, retained
/// temporary publication records remain an unresolved publication observation.
pub async fn compare_ledger_source_name<'scope, 'task>(
    task: &'scope TaskCx<'task>, cx: &'scope Cx, clock: MeteredClock<'scope, 'task>,
    checkpoint_root: PathBuf, deployment_root: PathBuf, root: ContentDigest, require_history: bool,
) -> Result<(), &'static str> {
    if !checkpoint_root.is_absolute() || !deployment_root.is_absolute()
        || root.algorithm() != fss_core::DigestAlgorithm::Sha256 {
        return Err("invalid ledger comparison inputs");
    }
    let mut cost = BudgetVector::ZERO;
    cost.storage_operations = 32;
    cost.bytes = 4 * 1024 * 1024;
    for path in [&checkpoint_root, &deployment_root] {
        let resource = path.to_str().ok_or("comparison path must be UTF-8")?;
        for grant in [RuntimeGrant::ObjectStage, RuntimeGrant::ReadMedia] {
            task.checkpoint_for(grant, resource, clock.now().map_err(|_| "comparison clock unavailable")?, &cost)
                .map_err(|_| "comparison authority refused")?;
        }
    }
    let checkpoint = checkpoint_root.clone();
    let deployment = deployment_root.clone();
    let mut worker = drained_blocking::start(cx, move |child: Cx| {
        let (scope, _, _) = open_disk(&child, &checkpoint)?;
        let camera = scope_claim(scope)?.0;
        let hex: String = root.bytes().iter().map(|byte| format!("{byte:02x}")).collect();
        let slot = fss_publication::SlotName::parse(&format!("uflv1-{hex}"))
            .map_err(|_| "source slot invalid")?;
        let object = fss_publication::root_reachability_object_id(&slot)
            .map_err(|_| "source ledger identity invalid")?;
        let ledger = fss_ledger::DurableReferenceLedger::inspect(
            deployment.join("ledger/journal.fssj"), "site:http-record-trial", 2 * 1024 * 1024,
        ).map_err(|_| "source ledger inspection refused")?;
        if !ledger.is_clean() || ledger.status != fss_ledger::DurableLedgerStatus::Present {
            return Err("source ledger is incomplete");
        }
        let revision = ledger.snapshot.objects.get(&object).ok_or("source root not ledgered")?;
        if revision.family != fss_publication::ROOT_REACHABILITY_FAMILY
            || revision.payload_digest != root
            || revision.validity.earliest != fss_core::TimestampNs::MIN
            || revision.validity.latest != fss_core::TimestampNs::MAX {
            return Err("source ledger root mismatch");
        }
        let spool = deployment.join("objects/spool");
        let read = |digest| fss_object::read_verified_payload(&spool, digest, 64 * 1024, &HostSpoolIo)
            .map_err(|_| "source graph object unavailable or corrupt");
        let root_bytes = read(root)?;
        let manifest = fss_object::ObjectManifest::from_canonical_bytes(&root_bytes)
            .map_err(|_| "source manifest invalid")?;
        if manifest.root() != root || manifest.kind() != "unifi-direct-flv-source-v1"
            || manifest.children().len() != 2 {
            return Err("source manifest mismatch");
        }
        let metadata_digest = manifest.metadata_digest().ok_or("source metadata missing")?;
        let metadata = read(metadata_digest)?;
        let mut decoder = CanonicalDecoder::new(&metadata);
        if decoder.text().map_err(|_| "source metadata invalid")? != "fss.unifi-direct.flv-source-evidence.v1"
            || decoder.digest().map_err(|_| "source metadata invalid")? != ContentDigest::sha256(b"unifi-http-record-trial-retention")
            || decoder.bool().map_err(|_| "source metadata invalid")?
            || decoder.u64().map_err(|_| "source metadata invalid")? != 1
            || decoder.u64().map_err(|_| "source metadata invalid")? != 1
            || decoder.digest().map_err(|_| "source metadata invalid")? != camera {
            return Err("source metadata scope mismatch");
        }
        let disposition = decoder.u8().map_err(|_| "source metadata invalid")?;
        let offset = decoder.u64().map_err(|_| "source metadata invalid")?;
        let length = decoder.u64().map_err(|_| "source metadata invalid")?;
        let digest = decoder.digest().map_err(|_| "source metadata invalid")?;
        let record_kind = decoder.u8().map_err(|_| "source metadata invalid")?;
        let tag_kind = decoder.u8().map_err(|_| "source metadata invalid")?;
        let _timestamp = decoder.u32().map_err(|_| "source metadata invalid")?;
        decoder.ensure_finished().map_err(|_| "source metadata invalid")?;
        if disposition == 0 || disposition > 3 || offset != 13 || length == 0 || length > 64 * 1024
            || record_kind != 1 || tag_kind != 18 || digest == metadata_digest
            || !manifest.children().contains(&digest) {
            return Err("source metadata record mismatch");
        }
        let bytes = read(digest)?;
        if bytes.len() as u64 != length { return Err("source length mismatch"); }
        if require_history {
            let archive = deployment.parent().ok_or("source archive parent unavailable")?;
            super::trial_local_history::source_confirmed(archive, root)?;
        }
        Ok(digest)
    }).map_err(|_| "ledger comparison worker refused")?;
    let receipt = match asupersync::time::timeout(cx.now(), Duration::from_secs(15), worker.join()).await {
        Ok(receipt) => receipt.ok_or("ledger comparison worker already joined")?,
        Err(_) => { worker.abort(); let _ = worker.join().await; return Err("ledger comparison timed out"); }
    };
    if receipt.runtime.is_err() { return Err("ledger comparison runtime failed"); }
    let digest = match receipt.work {
        WorkOutcome::Finished(result) => result?,
        WorkOutcome::NotStarted(_) => return Err("ledger comparison did not start"),
        WorkOutcome::Panicked | WorkOutcome::Indeterminate => return Err("ledger comparison outcome indeterminate"),
    };
    compare_source_name(task, cx, clock, checkpoint_root, deployment_root.join("objects/spool"), digest).await
}

// Decode only the public canonical v1 scope fields needed to bind two
// independently authenticated snapshots. Preconditions and baseline digests
// intentionally differ; comparing these claims does not authenticate a device.
fn scope_claim(
    scope: Scope,
) -> Result<(ContentDigest, ContentDigest, ContentDigest, u8), &'static str> {
    let bytes = scope.encode().map_err(|_| "checkpoint scope invalid")?;
    let mut d = CanonicalDecoder::new(&bytes);
    if d.text().map_err(|_| "checkpoint scope invalid")?
        != "fss.unifi-direct.serializer-checkpoint-scope.v1"
    {
        return Err("checkpoint scope invalid");
    }
    let camera = d.digest().map_err(|_| "checkpoint scope invalid")?;
    let certificate = d.digest().map_err(|_| "checkpoint scope invalid")?;
    let request = d.digest().map_err(|_| "checkpoint scope invalid")?;
    let _preconditions = d.digest().map_err(|_| "checkpoint scope invalid")?;
    let _baseline = d.digest().map_err(|_| "checkpoint scope invalid")?;
    let channel = d.u8().map_err(|_| "checkpoint scope invalid")?;
    d.ensure_finished()
        .map_err(|_| "checkpoint scope invalid")?;
    Ok((camera, certificate, request, channel))
}

fn contains_requested(expected: &Value, actual: &Value) -> bool {
    match (expected, actual) {
        (Value::Object(want), Value::Object(got)) => want.iter().all(|(key, value)| {
            got.get(key)
                .is_some_and(|actual| contains_requested(value, actual))
        }),
        (Value::Array(want), Value::Array(got)) => {
            want.len() == got.len()
                && want
                    .iter()
                    .zip(got)
                    .all(|(value, actual)| contains_requested(value, actual))
        }
        _ => expected == actual,
    }
}

fn compare_disk(cx: &Cx, root: &Path, observation: &Path, restored: bool) -> Result<Scope, &'static str> {
    if restored {
        let before = fs::symlink_metadata(root).map_err(|_| "checkpoint directory unavailable")?;
        let after = fs::symlink_metadata(observation).map_err(|_| "checkpoint directory unavailable")?;
        if (before.dev(), before.ino()) == (after.dev(), after.ino()) {
            return Err("restored checkpoint must be a separate observation");
        }
    }
    let (before_scope, before, before_digest) = open_disk(cx, root)?;
    let (after_scope, after, after_digest) = open_disk(cx, observation)?;
    if restored && before_digest == after_digest {
        return Err("restored checkpoint must be a distinct encrypted artifact");
    }
    let claim = scope_claim(before_scope)?;
    if claim != scope_claim(after_scope)? {
        return Err("checkpoint camera or request claims differ");
    }
    let channel = match claim.3 {
        1 => "video1",
        2 => "video2",
        3 => "video3",
        _ => return Err("checkpoint scope invalid"),
    };
    let index = usize::from(claim.3 - 1);
    let policy = InspectionPolicy;
    let comparison = before
        .visit(cx, &policy, |prior, forward| {
            after.visit(cx, &policy, |observed, observed_forward| {
                let expected = forward
                    .object()?
                    .get("av")?
                    .object()?
                    .get("video")?
                    .object()?
                    .get(channel)?
                    .object()?
                    .get("avSerializer")?;
                Some(if restored {
                    forward == observed_forward && prior == observed
                } else {
                    forward == observed_forward
                        && prior[index] != observed[index]
                        && (0..3).all(|i| i == index || prior[i] == observed[i])
                        && observed[index]
                            .is_some_and(|actual| contains_requested(expected, actual))
                })
            })
        })
        .map_err(|_| "checkpoint comparison refused")?
        .map_err(|_| "checkpoint comparison refused")?;
    if comparison != Some(true) {
        return Err(if restored { "restored checkpoint differs from baseline" } else { "checkpoint observations do not match the requested change" });
    }
    Ok(before_scope)
}

/// Reopen and authenticate the stored checkpoint on a drained worker.
/// The root remains a caller-trusted storage domain, not proof of camera identity
/// or authority to dispatch or restore a camera setting.
pub async fn inspect<'scope, 'task>(
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    root: PathBuf,
    observation: Option<PathBuf>,
    restored: bool,
) -> Result<Scope, &'static str> {
    if restored && observation.is_none() { return Err("restored comparison requires a second checkpoint"); }
    let resource = root.to_str().ok_or("checkpoint path must be UTF-8")?;
    let mut cost = BudgetVector::ZERO;
    cost.storage_operations = if observation.is_some() { 64 } else { 32 };
    task.checkpoint_for(
        RuntimeGrant::ObjectStage,
        resource,
        clock.now().map_err(|_| "checkpoint clock unavailable")?,
        &cost,
    )
    .map_err(|_| "checkpoint authority refused")?;
    if let Some(path) = &observation {
        let resource = path.to_str().ok_or("checkpoint path must be UTF-8")?;
        task.checkpoint_for(
            RuntimeGrant::ObjectStage,
            resource,
            clock.now().map_err(|_| "checkpoint clock unavailable")?,
            &BudgetVector::ZERO,
        )
        .map_err(|_| "checkpoint authority refused")?;
    }
    let mut worker = drained_blocking::start(cx, move |child: Cx| {
        if let Some(observation) = observation {
            compare_disk(&child, &root, &observation, restored)
        } else {
            open_disk(&child, &root).map(|(scope, _, _)| scope)
        }
    })
    .map_err(|_| "checkpoint inspection worker refused")?;
    let receipt =
        match asupersync::time::timeout(cx.now(), Duration::from_secs(15), worker.join()).await {
            Ok(receipt) => receipt.ok_or("checkpoint inspection already joined")?,
            Err(_) => {
                worker.abort();
                let _drained = worker.join().await;
                return Err("checkpoint inspection timed out");
            }
        };
    if receipt.runtime.is_err() {
        return Err("checkpoint inspection runtime failed");
    }
    match receipt.work {
        WorkOutcome::Finished(result) => result,
        WorkOutcome::NotStarted(_) => Err("checkpoint inspection did not start"),
        WorkOutcome::Panicked | WorkOutcome::Indeterminate => {
            Err("checkpoint inspection outcome indeterminate")
        }
    }
}

/// Reopen a retained baseline on a drained worker and compare it with a fresh
/// caller-admitted camera session. The peer's response remains a claim; this
/// neither settles an effect nor authenticates the physical device.
pub async fn compare_live<'scope, 'task>(
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    root: PathBuf,
    camera: ContentDigest,
    certificate: ContentDigest,
    observed: &VideoSerializers,
    authorize: impl FnOnce(std::net::Ipv4Addr, u64) -> bool,
) -> Result<fss_reference::unifi_direct::http_stream::ReadbackObservation, &'static str> {
    let resource = root.to_str().ok_or("checkpoint path must be UTF-8")?;
    let mut cost = BudgetVector::ZERO;
    cost.storage_operations = 32;
    task.checkpoint_for(
        RuntimeGrant::ObjectStage,
        resource,
        clock.now().map_err(|_| "checkpoint clock unavailable")?,
        &cost,
    )
    .map_err(|_| "checkpoint authority refused")?;
    let mut worker = drained_blocking::start(cx, move |child: Cx| open_disk(&child, &root))
        .map_err(|_| "checkpoint inspection worker refused")?;
    let receipt =
        match asupersync::time::timeout(cx.now(), Duration::from_secs(15), worker.join()).await {
            Ok(receipt) => receipt.ok_or("checkpoint worker already joined")?,
            Err(_) => {
                worker.abort();
                let _drained = worker.join().await;
                return Err("checkpoint inspection timed out");
            }
        };
    if receipt.runtime.is_err() {
        return Err("checkpoint inspection runtime failed");
    }
    let (scope, retained, _digest) = match receipt.work {
        WorkOutcome::Finished(result) => result?,
        WorkOutcome::NotStarted(_) => return Err("checkpoint inspection did not start"),
        WorkOutcome::Panicked | WorkOutcome::Indeterminate => {
            return Err("checkpoint inspection outcome indeterminate");
        }
    };
    if !scope.matches_camera(camera, certificate) {
        return Err("live checkpoint camera or certificate claim mismatch");
    }
    retained
        .compare_reopened(
            cx,
            &InspectionPolicy,
            camera,
            certificate,
            observed,
            authorize,
        )
        .map_err(|error| match error {
            checkpoint::Error::Denied => "live checkpoint comparison authority refused",
            checkpoint::Error::Invalid => "live checkpoint comparison content invalid",
            checkpoint::Error::Authentication => {
                "live checkpoint comparison authentication refused"
            }
            checkpoint::Error::Storage => "live checkpoint comparison storage refused",
        })
}
