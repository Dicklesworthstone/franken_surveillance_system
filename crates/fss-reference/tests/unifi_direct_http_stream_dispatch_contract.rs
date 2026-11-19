#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Synthetic journaled local serializer dispatch and reconciliation contracts.
#[path = "../../../experiments/unifi_tls_scoped_entropy_lab/src/bin/trial_http_checkpoint/mod.rs"]
mod trial_http_checkpoint;
#[path = "../../../experiments/unifi_tls_scoped_entropy_lab/src/bin/trial_local_history/mod.rs"]
mod trial_local_history;
use asupersync::{
    http::h1::Response,
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
    runtime::RuntimeBuilder,
    time::timeout,
};
use fss_container::{
    demux::{AvcMp4, DemuxLimits},
    flv_avc::SourceKey,
};
use fss_core::{
    BudgetVector, ContentDigest, IdempotencyKey, OperationId, RegionId, RegionKind,
    RootAuthoritySpec, RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_object::{
    HostSpoolIo, SpoolLimits, StagingSpool,
    effect_journal::{EffectJournalLimits, FileEffectJournal, FileTrustedRootPinRetainer},
};
use fss_packet::extended_flv::{Limits as FlvLimits, stream::Framer};
use fss_reference::unifi_direct::{
    AudioCodec, StreamStart, VideoChannel, VideoCodec,
    camera_api::{HandoffError, HandoffWrite, Phase, SerializerAuthority, Session, WriteOutcome},
    camera_http,
    handoff::Framing,
    http_stream::{
        Operation as SerializerOperation, Plan, Preconditions, ReadbackChange, ReadbackObservation,
        checkpoint, media,
    },
    listener,
    metered::{MeteredClock, MeteredIo},
    recording,
};
use fss_runtime::{
    authority::AuthorityCx,
    effect::{CommitApproval, CommittedEffect, EffectCoordinator, PrepareSpec, Reconciliation},
    effect_journal::{EffectJournalStore, EffectPinRetainer, PinRetainedEffectJournal},
    execution::{TaskCompletion, TaskSpec, run_owned_async},
    lease::LeaseRegistry,
};
use std::os::unix::fs::DirBuilderExt;
use std::{
    cell::{Cell, RefCell},
    error::Error,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4},
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

type Test = Result<(), Box<dyn Error>>;

struct ArchiveAccess;
struct DeniedArchiveAccess;
impl fss_reference::unifi_direct::archive::ReadAuthority for DeniedArchiveAccess {
    fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool { false }
}
impl fss_reference::unifi_direct::archive::RetainAuthority for ArchiveAccess {
    fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
        true
    }
}
impl fss_reference::unifi_direct::archive::ReadAuthority for ArchiveAccess {
    fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
        true
    }
}

fn preflight_archive_storage<'scope, 'task>(
    task: &'scope fss_runtime::execution::TaskCx<'task>,
    cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
    dir: &std::path::Path,
    label: &str,
    camera: ContentDigest,
) -> Result<
    (
        fss_reference::unifi_direct::recording_storage::Created,
        fss_reference::unifi_direct::video_bootstrap::Policy,
    ),
    Box<dyn Error>,
> {
    preflight_archive_storage_for(task, cx, clock, dir, label, camera, SourceKey { connection: 1, generation: 1 })
}

fn preflight_archive_storage_for<'scope, 'task>(
    task: &'scope fss_runtime::execution::TaskCx<'task>,
    cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
    dir: &std::path::Path,
    label: &str,
    camera: ContentDigest,
    source: SourceKey,
) -> Result<
    (
        fss_reference::unifi_direct::recording_storage::Created,
        fss_reference::unifi_direct::video_bootstrap::Policy,
    ),
    Box<dyn Error>,
> {
    use fss_core::region::ContextAuthority;
    use fss_reference::{
        DeploymentLimits, ReplayCx,
        unifi_direct::{archive, evidence, recording_storage, video_bootstrap},
    };
    let auth = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:preflight-archive".into(),
        operation_id: OperationId::parse("operation:preflight-archive")?,
        principal: "principal:fixture".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 1,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"preflight archive"),
        generation: 1,
    })?;
    let root = dir.join(label);
    let retention = ContentDigest::sha256(b"preflight retention");
    let cfg = recording_storage::Configuration {
        root: &root,
        site_lineage: "site:preflight-archive",
        source,
        camera_claim: camera,
        source_retention: retention,
        source_scope: ContentDigest::sha256(b"preflight source"),
        av_scope: ContentDigest::sha256(b"preflight video"),
        source_deployment_limits: DeploymentLimits::standard(),
        av_deployment_limits: DeploymentLimits::standard(),
        source_history_limits: EffectJournalLimits::default(),
        av_history_limits: if label == "http-av-rollover" {
            EffectJournalLimits { max_records: 5, ..EffectJournalLimits::default() }
        } else if label == "checkpointed-av-rollover" {
            EffectJournalLimits { max_records: 5, ..EffectJournalLimits::default() }
        } else { EffectJournalLimits::default() },
        limits: archive::Limits::default(),
        max_source_bytes: 1024 * 1024,
        work_limit: 4_000_000_000,
    };
    let storage = recording_storage::create(
        task,
        cx,
        clock,
        cfg,
        ReplayCx::from_context_authority(&auth, dir.to_path_buf())?,
        ReplayCx::from_context_authority(&auth, dir.to_path_buf())?,
        Arc::new(ArchiveAccess),
    )?;
    let policy = video_bootstrap::Policy {
        inband: false,
        retention,
        media_limits: fss_container::Mp4Limits::default(),
        evidence_limits: evidence::Limits::default(),
    };
    Ok((storage, policy))
}

fn metadata_journal(
    dir: &std::path::Path,
    label: &str,
) -> Result<PinRetainedEffectJournal, Box<dyn Error>> {
    let limits = EffectJournalLimits::default();
    let file = FileEffectJournal::create(
        dir.join(format!("{label}-journal")),
        limits,
        Arc::new(HostSpoolIo),
    )?;
    let root = FileTrustedRootPinRetainer::create(
        dir.join(format!("{label}-root")),
        limits,
        Arc::new(HostSpoolIo),
        ContentDigest::sha256(label.as_bytes()),
    )?;
    Ok(PinRetainedEffectJournal::new(
        Box::new(file),
        Box::new(root),
    )?)
}
fn serializer_snapshot(
    peer: Ipv4Addr,
    generation: u64,
    payload: &[u8],
) -> Result<fss_reference::unifi_direct::camera_api::VideoSerializers, Box<dyn Error>> {
    let mut session = Session::new(peer, generation)?;
    let r = session.prepare_login(br#"{"username":"fixture","password":"synthetic"}"#)?;
    session.finish_write(r, WriteOutcome::Written)?;
    session.accept_login(
        Response::new(200, "OK", Vec::new()).with_header("Set-Cookie", "authId=synthetic"),
    )?;
    let r = session.prepare_status()?;
    session.finish_write(r, WriteOutcome::Written)?;
    session.accept_status(Response::new(200, "OK", b"{}".to_vec()))?;
    let r = session.prepare_serializer_settings()?;
    session.finish_write(r, WriteOutcome::Written)?;
    Ok(session
        .accept_settings_with_serializers(Response::new(200, "OK", payload.to_vec()))?
        .1)
}
struct Guard(bool);
struct CheckpointPolicy(bool);
impl checkpoint::Authority for CheckpointPolicy {
    fn permits(&self, _: &asupersync::Cx, _: &checkpoint::Scope, _: checkpoint::Action) -> bool {
        self.0
    }
}
struct DenyCheckpoint(checkpoint::Action);
impl checkpoint::Authority for DenyCheckpoint {
    fn permits(
        &self,
        _: &asupersync::Cx,
        _: &checkpoint::Scope,
        action: checkpoint::Action,
    ) -> bool {
        action != self.0
    }
}
impl SerializerAuthority for Guard {
    fn permits(&self, _: &Plan, _: Preconditions, _: &CommittedEffect) -> bool {
        self.0
    }
}
struct OwnerPolicy(Cell<bool>);
impl camera_http::Authority for OwnerPolicy {
    fn permits(&self, _: Ipv4Addr, generation: u64, operation: camera_http::Operation) -> bool {
        generation == 1 && (operation != camera_http::Operation::SerializerSettings || self.0.get())
    }
}
struct MediaPolicy(SocketAddrV4);
impl listener::Admission for MediaPolicy {
    fn listener(&self, requested: SocketAddrV4, bound: Option<SocketAddrV4>) -> bool {
        requested == self.0 && bound.is_none_or(|value| value == self.0)
    }
    fn peer(&self, bound: SocketAddrV4, source: SocketAddrV4) -> bool {
        bound == self.0 && source.ip().is_loopback()
    }
}
fn flv_tag(kind: u8, timestamp: u32, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let size = payload.len();
    let size32 = u32::try_from(size).map_err(std::io::Error::other)?;
    let mut out = vec![
        kind,
        (size >> 16) as u8,
        (size >> 8) as u8,
        size as u8,
        (timestamp >> 16) as u8,
        (timestamp >> 8) as u8,
        timestamp as u8,
        (timestamp >> 24) as u8,
        0,
        0,
        0,
    ];
    out.extend_from_slice(payload);
    out.extend_from_slice(&(11_u32 + size32).to_be_bytes());
    Ok(out)
}
fn synthetic_high_flv(audio_mode: u8) -> std::io::Result<Vec<u8>> {
    let with_audio = audio_mode != 0;
    const SOURCE: &[u8] = include_bytes!(
        "../../../experiments/unifi_tls_05_server_lab/tests/fixtures/synthetic_g4_resolution.264"
    );
    const AUDIO_SOURCE: &[u8] = include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264");
    const HIGH_AV_SOURCE: &[u8] = include_bytes!("../../../experiments/unifi_tls_05_server_lab/tests/fixtures/synthetic_g4_av_gop3.264");
    let nals: Vec<_> =
        fss_codec_h264::annex_b_nal_units(if (5..=8).contains(&audio_mode) || audio_mode == 10 { HIGH_AV_SOURCE } else if with_audio { AUDIO_SOURCE } else { SOURCE }).collect();
    let sps = nals
        .iter()
        .copied()
        .find(|n| n[0] & 31 == 7)
        .ok_or_else(|| std::io::Error::other("fixture SPS"))?;
    let pps = nals
        .iter()
        .copied()
        .find(|n| n[0] & 31 == 8)
        .ok_or_else(|| std::io::Error::other("fixture PPS"))?;
    let mut pictures: Vec<_> = nals
        .iter()
        .copied()
        .filter(|n| {
            if with_audio {
                matches!(n[0] & 31, 1 | 5)
            } else {
                n[0] & 31 == 5
            }
        })
        .collect();
    if pictures.len() != if (5..=8).contains(&audio_mode) || audio_mode == 10 { 7 } else { 4 } {
        return Err(std::io::Error::other("fixture IDR count"));
    }
    if with_audio {
        if pictures[0][0] & 31 != 5 {
            return Err(std::io::Error::other("fixture first picture"));
        }
        if (5..=8).contains(&audio_mode) || audio_mode == 10 {
            // The high-resolution fixture already contains two complete GOPs.
        } else if matches!(audio_mode, 4 | 12) {
            pictures = vec![pictures[0], pictures[1], pictures[2], pictures[0], pictures[1], pictures[2], pictures[0]];
        } else {
            pictures.push(pictures[0]);
        }
    }
    if matches!(audio_mode, 10 | 12) {
        // A third GOP forces the tiny fixture journal to rotate while a
        // complete successor segment remains owned by the recorder.
        pictures.extend_from_within(1..4);
    }
    let mut avc = vec![0x17, 0, 0, 0, 0, 1, sps[1], sps[2], sps[3], 0xff, 0xe1];
    avc.extend_from_slice(
        &u16::try_from(sps.len())
            .map_err(std::io::Error::other)?
            .to_be_bytes(),
    );
    avc.extend_from_slice(sps);
    avc.push(1);
    avc.extend_from_slice(
        &u16::try_from(pps.len())
            .map_err(std::io::Error::other)?
            .to_be_bytes(),
    );
    avc.extend_from_slice(pps);
    let mut wire = if with_audio {
        b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00".to_vec()
    } else {
        b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec()
    };
    wire.extend(flv_tag(9, 0, &avc)?);
    if with_audio && audio_mode != 7 && audio_mode != 10 {
        wire.extend(flv_tag(8, 0, &[0xaf, 0, 0x14, 0x08])?);
        if audio_mode == 2 {
            wire.extend(flv_tag(8, 0, &[0xaf, 0, 0x14, 0x08])?);
        }
    }
    for (i, picture) in pictures.iter().enumerate() {
        let mut data = vec![if picture[0] & 31 == 5 { 0x17 } else { 0x27 }, 1, 0, 0, 0];
        data.extend_from_slice(
            &u32::try_from(picture.len())
                .map_err(std::io::Error::other)?
                .to_be_bytes(),
        );
        data.extend_from_slice(picture);
        wire.extend(flv_tag(
            9,
            u32::try_from(i).map_err(std::io::Error::other)? * 40,
            &data,
        )?);
        if with_audio && i == 0 {
            wire.extend(flv_tag(8, 0, &[0xaf, 1, 0x11, 0x22])?);
        }
        if (4..=8).contains(&audio_mode) || matches!(audio_mode, 10 | 12) {
            let audio_time = match i { 1 => Some(64), 3 => Some(128), 4 => Some(192), 6 if matches!(audio_mode, 10 | 12) => Some(256), 8 if matches!(audio_mode, 10 | 12) => Some(320), _ => None };
            if let Some(timestamp) = audio_time {
                wire.extend(flv_tag(8, timestamp, &[0xaf, 1, 0x33, 0x44])?);
            }
        }
    }
    Ok(wire)
}
fn fixture_server(
    address: std::net::SocketAddr,
    match_request: bool,
    media_target: Option<SocketAddrV4>,
    audio_mode: u8,
    private_media: Option<Vec<u8>>,
) -> std::io::Result<()> {
    let mut socket = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    socket.set_read_timeout(Some(Duration::from_secs(8)))?;
    let mut routes = vec![
        "POST /api/1.1/login ",
        "GET /api/1.1/status ",
        "GET /api/1.1/settings ",
        "PUT /api/1.1/settings ",
        "GET /api/1.1/settings ",
    ];
    if match_request && media_target.is_none() {
        routes.extend(["PUT /api/1.1/settings ", "GET /api/1.1/settings "]);
    }
    for (index, route) in routes.iter().enumerate() {
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            socket.read_exact(&mut byte)?;
            request.push(byte[0]);
            if request.len() > 8192 {
                return Err(std::io::Error::other("fixture header limit"));
            }
        }
        let header = std::str::from_utf8(&request).map_err(std::io::Error::other)?;
        if !header.starts_with(*route) {
            return Err(std::io::Error::other("fixture route"));
        }
        let length = header
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .map_or(Ok(0), str::parse::<usize>)
            .map_err(std::io::Error::other)?;
        if length > 4096 {
            return Err(std::io::Error::other("fixture body limit"));
        }
        let mut body = vec![0u8; length];
        socket.read_exact(&mut body)?;
        if index == 3 {
            let text = std::str::from_utf8(&body).map_err(std::io::Error::other)?;
            if !text.contains("\"video1\":{\"avSerializer\":")
                || text.contains("\"video2\"")
                || text.contains("\"controller\"")
            {
                return Err(std::io::Error::other("fixture serializer mismatch"));
            }
        }
        if index == 5 && body != br#"{"av":{"video":{"video1":{"avSerializer":null}}}}"# {
            return Err(std::io::Error::other("fixture restore mismatch"));
        }
        let reply: Vec<u8> = if index == 4 && match_request {
            let target =
                media_target.unwrap_or(SocketAddrV4::new(Ipv4Addr::new(192, 168, 42, 11), 17777));
            format!(r#"{{"av":{{"video":{{"video1":{{"avSerializer":{{"type":"extendedFlv","parameters":{{"streamName":"0123456789abcdef","withOpus":false}},"destinations":["tcp://{target}?retryInterval=1&connectTimeout=5"]}}}},"video2":{{"avSerializer":{{"destinations":["tcp://fixture:1"]}}}}}}}}}}"#).into_bytes()
        } else if index == 2 || index == 4 || index == 6 {
            br#"{"av":{"video":{"video1":{"avSerializer":null},"video2":{"avSerializer":{"destinations":["tcp://fixture:1"]}}}}}"#.to_vec()
        } else {
            b"{}".to_vec()
        };
        let cookie = if index == 0 {
            "Set-Cookie: authId=synthetic\r\n"
        } else {
            ""
        };
        let head = format!(
            "HTTP/1.1 200 OK\r\n{cookie}Content-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            reply.len()
        );
        socket.write_all(head.as_bytes())?;
        socket.write_all(&reply)?;
        if index == 3 && audio_mode == u8::MAX {
            let mut unexpected = [0u8; 1];
            return match socket.read(&mut unexpected) {
                Ok(0) => Ok(()),
                Ok(_) => Err(std::io::Error::other("readback after response custody refusal")),
                Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof) => Ok(()),
                Err(error) => Err(error),
            };
        }
        if index == 4
            && let Some(target) = media_target
        {
            let mut media =
                std::net::TcpStream::connect_timeout(&target.into(), Duration::from_secs(5))?;
            if match_request {
                match private_media.as_ref() {
                    Some(input) => media.write_all(input)?,
                    None => media.write_all(&synthetic_high_flv(audio_mode)?)?,
                }
            } else {
                media.write_all(b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00")?;
            }
        }
    }
    Ok(())
}
struct Sink {
    bytes: Rc<RefCell<Vec<u8>>>,
    polled: Rc<Cell<bool>>,
    partial: bool,
}
struct NoIo<'a>(&'a Cell<bool>);
impl AsyncRead for NoIo<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.0.set(true);
        Poll::Ready(Err(std::io::Error::other("unexpected preflight read")))
    }
}
impl AsyncWrite for NoIo<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.0.set(true);
        Poll::Ready(Err(std::io::Error::other("unexpected preflight write")))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.0.set(true);
        Poll::Ready(Err(std::io::Error::other("unexpected preflight flush")))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.0.set(true);
        Poll::Ready(Err(std::io::Error::other("unexpected preflight shutdown")))
    }
}
impl AsyncWrite for Sink {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.polled.set(true);
        if self.partial && !self.bytes.borrow().is_empty() {
            return Poll::Pending;
        }
        let n = if self.partial {
            bytes.len().min(1)
        } else {
            bytes.len()
        };
        self.bytes.borrow_mut().extend_from_slice(&bytes[..n]);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn one_track_dispatch_requires_full_readback() -> Test {
    exercise(false, false, false, false, false, false, false, 0)
}
#[test]
fn partial_write_fences_and_leaves_effect_open() -> Test {
    exercise(true, false, false, false, false, false, false, 0)
}
#[test]
fn unsuccessful_response_fences_and_leaves_effect_open() -> Test {
    exercise(false, true, false, false, false, false, false, 0)
}
#[test]
fn owned_http_checks_policy_and_requires_private_readback() -> Test {
    exercise(false, false, true, false, false, false, false, 0)
}
#[test]
fn owned_http_observes_requested_fields_without_settling() -> Test {
    exercise(false, false, true, true, false, false, false, 0)
}
#[test]
fn owned_http_starts_native_media_listener() -> Test {
    exercise(false, false, true, true, true, false, false, 0)
}
#[test]
fn response_custody_refusal_retains_permit_and_stops_before_readback() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 0, false, 55)
}
#[test]
fn owned_http_refuses_unmatched_readback_before_media_accept() -> Test {
    exercise(false, false, true, false, true, false, false, 0)
}

#[test]
fn owned_http_media_publishes_and_reads_native_video() -> Test {
    exercise(false, false, true, true, true, true, false, 0)
}

#[test]
fn owned_http_archive_starts_media_with_preflight() -> Test {
    exercise(false, false, true, true, true, false, true, 0)
}

#[test]
fn owned_http_preflight_starts_and_archives_high_resolution_video() -> Test {
    exercise(false, false, true, true, true, true, true, 0)
}

#[test]
fn owned_http_bootstraps_in_band_audio_with_video() -> Test {
    exercise(false, false, true, true, true, false, false, 1)
}

#[test]
fn owned_http_fences_duplicate_audio_configuration() -> Test {
    exercise(false, false, true, true, true, false, false, 2)
}

#[test]
fn owned_http_audio_archive_refusal_preserves_custody() -> Test {
    exercise(false, false, true, true, true, false, false, 3)
}

#[test]
fn owned_http_archives_multiple_audio_video_segments_and_prefix() -> Test {
    exercise(false, false, true, true, true, false, false, 4)
}

#[test]
fn http_reconnect_fences_refused_tail_and_preserves_originals() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 4, false, 42)
}

#[test]
fn http_reconnect_refuses_wrong_successor_storage_without_losing_owners() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 4, false, 43)
}

#[test]
fn http_reconnect_reuses_settled_storage_for_successor_av() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 4, false, 44)
}

#[test]
fn managed_supervisor_reconnects_and_records_successor_av() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 4, false, 46)
}

#[test]
fn managed_supervisor_fences_accept_failures_until_explicit_retry() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 4, false, 47)
}

#[test]
fn managed_supervisor_detached_recovery_cancels_and_joins_running_tail() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 4, false, 50)
}

#[test]
fn managed_supervisor_general_recovery_retains_running_tail() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 4, false, 51)
}

#[test]
fn managed_supervisor_general_recovery_retains_running_verification() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 4, false, 52)
}

#[test]
fn managed_supervisor_general_drain_retains_running_av_completion() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 4, false, 53)
}

#[test]
fn managed_supervisor_general_drain_retains_reuse_refusal() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 4, false, 54)
}

#[test]
fn managed_supervisor_reconnects_after_real_archive_rollover() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 4, false, 48)
}

#[test]
fn managed_supervisor_retries_refused_rollover_verification() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 4, false, 49)
}

#[test]
fn http_reconnect_reuse_refuses_wrong_retention_without_losing_owners() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 4, false, 45)
}

#[test]
fn owned_http_bootstraps_and_archives_high_resolution_audio_video() -> Test {
    exercise(false, false, true, true, true, false, false, 5)
}

#[test]
fn recovered_rollover_starts_and_archives_high_resolution_audio_video() -> Test {
    exercise(false, false, true, true, true, false, false, 6)
}

#[test]
fn supplied_unverified_audio_starts_and_archives_high_resolution_video() -> Test {
    exercise(false, false, true, true, true, false, false, 7)
}

#[test]
fn supplied_unverified_audio_fences_later_in_band_configuration() -> Test {
    exercise(false, false, true, true, true, false, false, 8)
}

#[test]
#[ignore = "requires owner-authorized bounded camera-derived FLV on stdin"]
fn private_camera_audio_video_http_start_replay() -> Test {
    exercise(false, false, true, true, true, false, false, 9)
}

#[test]
fn checkpointed_http_av_start_archives_supplied_audio() -> Test {
    exercise(false, false, true, true, true, false, false, 10)
}

#[test]
fn checkpointed_http_av_rollover_denial_retains_pending_media() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 10, true, 0)
}

#[test]
fn checkpointed_http_av_automatically_provisions_and_rolls() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 10, false, 1)
}

#[test]
fn checkpointed_http_av_creator_collision_retains_pending_media() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 10, false, 2)
}

#[test]
fn checkpointed_http_av_automatic_cancel_joins_av_worker() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 10, false, 3)
}

#[test]
fn checkpointed_http_av_eof_does_not_plan_another_generation() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 10, false, 4)
}

#[test]
fn checkpointed_http_av_eof_batches_original_tail() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 10, false, 5)
}

#[test]
fn checkpointed_http_av_network_exhaustion_preserves_original_tail() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 10, false, 9)
}

#[test]
fn checkpointed_http_av_bootstrap_network_exhaustion_retains_collector_and_tail() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 10, false, 10)
}

#[test]
fn checkpointed_http_av_batch_start_refusal_preserves_tail_for_retry() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 10, false, 6)
}

#[test]
fn checkpointed_http_av_batch_cancel_before_start_retains_originals() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 10, false, 7)
}

#[test]
fn checkpointed_http_av_batch_cancel_after_start_drains_and_accounts() -> Test {
    exercise_rollover(false, false, true, true, true, false, false, 10, false, 8)
}

#[test]
#[ignore = "requires owner-authorized bounded camera-derived FLV on stdin"]
fn private_camera_checkpointed_http_av_replay() -> Test {
    exercise(false, false, true, true, true, false, false, 11)
}

struct SeededRollover {
    storage: fss_reference::unifi_direct::recording_storage::Created,
    _forwarded: Vec<(recording::Push, Option<fss_reference::unifi_direct::pipeline::AudioEvent>)>,
    _old_sink: fss_reference::unifi_direct::av_owned_sink::UnknownTimeOwnedSink,
}

struct SeedMedia {
    sink: fss_reference::unifi_direct::av_owned_sink::UnknownTimeOwnedSink,
    first: recording::Segment,
    second: recording::Segment,
    forwarded: Vec<(recording::Push, Option<fss_reference::unifi_direct::pipeline::AudioEvent>)>,
}

#[inline(never)]
fn seed_media() -> Result<Box<SeedMedia>, Box<dyn Error>> {
    use fss_packet::extended_flv::{aac_track, stream::Next};
    use fss_reference::unifi_direct::{av_bootstrap, av_owned_sink, pipeline};
    let policy = av_owned_sink::BootstrapPolicy {
        allow_initial_video_only: false, max_separation_ms: 5_000, jitter_ms: 5,
        max_epoch_frames: 1_000_000, max_audio_frames: fss_container::Mp4Limits::default().max_samples,
        media_limits: fss_container::Mp4Limits::default(), evidence_limits: fss_reference::unifi_direct::evidence::Limits::default(),
    };
    let retention = ContentDigest::sha256(b"preflight retention");
    let mut collector = av_bootstrap::Collector::new(None, retention, policy);
    let mut recorder = recording::Recorder::new(SourceKey { connection: 99, generation: 1 }, recording::Limits::default())?;
    let mut track = aac_track::Track::new(FlvLimits::default(), fss_packet::extended_flv::aac::Limits::default());
    let mut framer = Framer::new(FlvLimits::default(), 1024 * 1024)?;
    framer.append(0, &synthetic_high_flv(4)?)?;
    let mut forwarded = Vec::new();
    while let Next::Record(record) = framer.take()? {
        let audio = match track.observe(&record)? {
            aac_track::Observation::Header | aac_track::Observation::Other => None,
            observation => Some(pipeline::AudioEvent::Observed(observation)),
        };
        let push = recorder.push(record).map_err(|refusal| refusal.reason)?;
        if let av_bootstrap::Collected::Forward { push, audio } = collector.collect(push, audio) {
            forwarded.push((push, audio));
        }
        if collector.ready() { break; }
    }
    let inputs = collector.into_inputs().map_err(|_| "seed A/V collector incomplete")?;
    let bootstrap = av_owned_sink::OwnedSink::bootstrap(inputs).map_err(|_| "seed A/V bootstrap refused")?;
    let mut second_segment = None;
    while let Next::Record(record) = framer.take()? {
        let audio = match track.observe(&record)? {
            aac_track::Observation::Header | aac_track::Observation::Other => None,
            observation => Some(pipeline::AudioEvent::Observed(observation)),
        };
        match recorder.push(record).map_err(|refusal| refusal.reason)? {
            recording::Push::Segment(segment) => {
                if audio.is_some() { return Err("unexpected paired segment audio".into()); }
                second_segment = Some(segment);
                break;
            }
            push => forwarded.push((push, audio)),
        }
    }
    let second_segment = second_segment.ok_or("seed second segment missing")?;
    let sink = bootstrap.sink.into_unknown_time().map_err(|_| "seed sink conversion refused")?;
    Ok(Box::new(SeedMedia { sink, first: bootstrap.first_segment, second: second_segment, forwarded }))
}

async fn seed_av_rollover<'scope, 'task>(
    task: &'scope fss_runtime::execution::TaskCx<'task>,
    cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
    dir: &std::path::Path,
    storage: fss_reference::unifi_direct::recording_storage::Created,
) -> Result<Box<SeededRollover>, Box<dyn Error>> {
    use fss_reference::unifi_direct::{av_unknown_worker_guard::BootstrapResources, av_worker};
    let SeedMedia { sink, first, second, forwarded } = *seed_media()?;
    let fss_reference::unifi_direct::recording_storage::Created { coordinator, av } = storage;
    let BootstrapResources { deployment, journal, keeper, replay, authority, limits, work_limit, rollover_custody } = *av;
    if rollover_custody.is_some() { return Err("seed storage already recovered".into()); }
    let mut worker = av_worker::UnknownTimeWorker::new(av_worker::UnknownTimeParts { sink, deployment, journal, keeper, replay, authority, limits, work_limit })
        .map_err(|_| "seed worker refused")?;
    for segment in [first, second] {
        worker.offer(segment).map_err(|_| "seed segment refused")?;
        worker.start(task, cx, clock, "fixture:archive", &BudgetVector::ZERO).map_err(|e| format!("seed start: {e:?}"))?;
        let completion = worker.join().await.ok_or("seed completion missing")?;
        if completion.runtime.is_err() || !matches!(completion.outcome, av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(_))) {
            return Err("seed publication failed".into());
        }
    }
    let retired = worker.retire().map_err(|_| "seed worker busy")?;
    let dir = dir.to_path_buf();
    let job = move |_child: asupersync::Cx| {
        finish_seed_rollover(Box::new(retired), coordinator, forwarded, &dir).map_err(|error| error.to_string())
    };
    let mut worker = fss_runtime::drained_blocking::start(cx, job).map_err(|_| "seed rollover worker refused")?;
    let receipt = worker.join().await.ok_or("seed rollover worker missing")?;
    if receipt.runtime.is_err() { return Err("seed rollover runtime failed".into()); }
    match receipt.work {
        fss_runtime::drained_blocking::WorkOutcome::Finished(Ok(seed)) => Ok(seed),
        fss_runtime::drained_blocking::WorkOutcome::Finished(Err(error)) => Err(error.into()),
        _ => Err("seed rollover worker did not complete".into()),
    }
}

#[inline(never)]
fn finish_seed_rollover(
    retired: Box<fss_reference::unifi_direct::av_worker::UnknownTimeRetirement>,
    coordinator: fss_reference::unifi_direct::source_coordinator::Coordinator,
    forwarded: Vec<(recording::Push, Option<fss_reference::unifi_direct::pipeline::AudioEvent>)>,
    dir: &std::path::Path,
) -> Result<Box<SeededRollover>, Box<dyn Error>> {
    use fss_reference::unifi_direct::{archive, av_unknown_worker_guard::BootstrapResources, av_worker};
    let (mut resources, previous) = (*retired).into_rollover().map_err(|_| "seed rollover refused")?;
    let limits = EffectJournalLimits::default();
    let store = |name: &str| -> Result<Box<dyn EffectJournalStore>, Box<dyn Error>> {
        Ok(Box::new(FileEffectJournal::create(dir.join(name), limits, Arc::new(HostSpoolIo))?))
    };
    let stage = archive::journal::rollover::Staged::begin(previous, store("av-recovered-journal")?, store("av-recovered-keeper")?, resources.replay())
        .map_err(|_| "seed rollover stage refused")?;
    let root = FileTrustedRootPinRetainer::create(dir.join("av-recovered-switch-root"), limits, Arc::new(HostSpoolIo), ContentDigest::sha256(b"seed switch custody"))?;
    let switch = PinRetainedEffectJournal::new(store("av-recovered-switch")?, Box::new(root))?;
    let mut active = stage.commit(switch, resources.replay()).map_err(|_| "seed switch refused")?;
    resources.replay_confirmed_av(&mut active, &ArchiveAccess, archive::StagedAvLimits { max_objects: 8192, max_object_bytes: 1024 * 1024, max_total_bytes: 8 * 1024 * 1024 }, &mut fss_geometry::WorkBudget::new(4_000_000_000))?;
    let worker = resources.attach(active).map_err(|_| "seed rollover attach refused")?;
    let retired = worker.retire().map_err(|_| "seed recovered worker busy")?;
    let custody = retired.rollover_custody.ok_or("seed rollover custody missing")?;
    let av_worker::UnknownTimeParts { sink, deployment, journal, keeper, replay, authority, limits, work_limit } = retired.parts;
    Ok(Box::new(SeededRollover {
        storage: fss_reference::unifi_direct::recording_storage::Created {
            coordinator,
            av: Box::new(BootstrapResources { deployment, journal, keeper, replay, authority, limits, work_limit, rollover_custody: Some(custody) }),
        },
        _forwarded: forwarded,
        _old_sink: sink,
    }))
}

async fn verify_start_resources<'a, 'scope, 'task>(
    task: &'scope fss_runtime::execution::TaskCx<'task>,
    cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
    inputs: Box<fss_reference::unifi_direct::http_stream::media_av_startup::Start<'a>>,
) -> Result<Box<fss_reference::unifi_direct::http_stream::media_av_startup::Start<'a>>, Box<dyn Error>> {
    use fss_reference::unifi_direct::{av_recovered_startup, http_stream::media_av_startup as startup, recording_storage};
    let startup::Start { request, storage, retention, policy, supplied_unverified_audio } = *inputs;
    let request = Box::new(request);
    let recording_storage::Created { coordinator, av } = storage;
    let mut worker = av_recovered_startup::Worker::new(av).map_err(|_| "recovered startup preflight refused")?;
    worker.start(task, cx, clock, "fixture:archive", &BudgetVector::ZERO)
        .map_err(|e| format!("recovered startup check: {e:?}"))?;
    let checked = worker.join().await.ok_or("recovered startup check missing")?;
    if checked.runtime.is_err() || !matches!(checked.outcome, av_recovered_startup::Outcome::Verified) {
        return Err("recovered startup check failed".into());
    }
    let retired = worker.retire().map_err(|_| "recovered startup check busy")?;
    if retired.fenced { return Err("recovered startup check fenced".into()); }
    Ok(Box::new(startup::Start { request: *request, storage: recording_storage::Created { coordinator, av: retired.resources }, retention, policy, supplied_unverified_audio }))
}

#[allow(clippy::too_many_arguments)]
async fn guarded_audio_start<'a, 'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>(
    task: &'scope fss_runtime::execution::TaskCx<'task>,
    cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
    owner: &mut camera_http::Owner<'_, '_, '_, IO>,
    media_listener: &mut listener::Listener<'_, '_, '_>,
    mut inputs: Box<fss_reference::unifi_direct::http_stream::media_av_startup::Start<'a>>,
    mut permit: CommittedEffect,
    peer: Ipv4Addr,
    resource: &str,
    owner_policy: &OwnerPolicy,
    wrong_plan: &'a Plan,
    expect_recovered: bool,
) -> Result<fss_reference::unifi_direct::http_stream::media_av_startup::Driver, Box<dyn Error>> {
    use fss_reference::unifi_direct::http_stream::media_av_startup as startup;
    let original_plan = inputs.request.plan;
    let valid_policy = inputs.policy;
    let valid_retention = inputs.retention;
    let valid_audio = inputs.supplied_unverified_audio;
    let io_polled = Cell::new(false);
    let fake_io = MeteredIo::with_clock(NoIo(&io_polled), clock, resource, 4096)?;
    let mut fake_owner = camera_http::Owner::new(fake_io, task, cx, clock, owner_policy, peer, 1, resource)?;
    if expect_recovered {
        let refusal = match Box::pin(startup::start(task, cx, clock, &mut fake_owner, media_listener, inputs, permit, |p, g| p == peer && g == 1)).await {
            Err(refusal) => refusal,
            Ok(_) => return Err("unverified recovered startup accepted".into()),
        };
        (inputs, permit) = match *refusal {
            startup::StartRefusal::Preflight { reason, inputs, permit } => {
                assert_eq!(reason, startup::StartPreflight::Binding);
                assert!(!io_polled.get());
                (inputs, permit)
            }
            _ => return Err("wrong unverified recovery refusal".into()),
        };
        inputs = Box::pin(verify_start_resources(task, cx, clock, inputs)).await?;
    }
    for mode in 0..7 {
        inputs.policy = valid_policy;
        inputs.retention = valid_retention;
        match mode {
            0 => inputs.policy.max_separation_ms = 1 << 31,
            1 => inputs.policy.max_epoch_frames = 0,
            2 => inputs.policy.max_epoch_frames = fss_packet::extended_flv::aac_clock::MAX_EPOCH_FRAMES + 1,
            3 => inputs.policy.jitter_ms = 101,
            4 => inputs.policy.max_audio_frames = 0,
            5 => inputs.policy.max_audio_frames = inputs.policy.media_limits.max_samples + 1,
            _ => inputs.retention = ContentDigest::sha256(b"different retention"),
        }
        let refusal = match Box::pin(startup::start(task, cx, clock, &mut fake_owner, media_listener, inputs, permit, |p, g| p == peer && g == 1)).await {
            Err(refusal) => refusal,
            Ok(_) => return Err("invalid A/V preflight was accepted".into()),
        };
        match *refusal {
            startup::StartRefusal::Preflight { reason, inputs: returned, permit: returned_permit } => {
                assert_eq!(reason, if expect_recovered && mode == 6 { startup::StartPreflight::Binding } else { startup::StartPreflight::Policy });
                assert!(!io_polled.get());
                inputs = returned;
                permit = returned_permit;
            }
            _ => return Err("wrong invalid-policy refusal".into()),
        }
    }
    inputs.policy = valid_policy;
    inputs.retention = valid_retention;
    for (configuration, jitter) in [([0, 0], 5), ([0x14, 0x08], 32)] {
        inputs.supplied_unverified_audio = Some(configuration);
        inputs.policy.jitter_ms = jitter;
        let refusal = match Box::pin(startup::start(task, cx, clock, &mut fake_owner, media_listener, inputs, permit, |p, g| p == peer && g == 1)).await {
            Err(refusal) => refusal,
            Ok(_) => return Err("invalid supplied audio passed preflight".into()),
        };
        (inputs, permit) = match *refusal {
            startup::StartRefusal::Preflight { reason, inputs, permit } => {
                assert_eq!(reason, startup::StartPreflight::Policy);
                assert_eq!(inputs.supplied_unverified_audio, Some(configuration));
                assert!(!io_polled.get());
                (inputs, permit)
            }
            _ => return Err("wrong supplied audio refusal".into()),
        };
    }
    inputs.policy = valid_policy;
    inputs.supplied_unverified_audio = valid_audio;
    inputs.request.plan = wrong_plan;
    let refusal = match Box::pin(startup::start(task, cx, clock, &mut fake_owner, media_listener, inputs, permit, |p, g| p == peer && g == 1)).await {
        Err(refusal) => refusal,
        Ok(_) => return Err("Opus request passed AAC preflight".into()),
    };
    let (mut inputs, permit) = match *refusal {
        startup::StartRefusal::Preflight { reason, inputs, permit } => {
            assert_eq!(reason, startup::StartPreflight::Binding);
            assert!(!io_polled.get());
            (inputs, permit)
        }
        _ => return Err("wrong invalid-codec refusal".into()),
    };
    inputs.request.plan = original_plan;
    Box::pin(startup::start(task, cx, clock, owner, media_listener, inputs, permit, |p, g| p == peer && g == 1))
        .await.map_err(|_| "guarded A/V startup refused".into())
}

async fn archive_http_media<'scope, 'task>(
    connected: Option<media::Connected>,
    started: Option<fss_reference::unifi_direct::http_stream::media_archive::Driver>,
    task: &'scope fss_runtime::execution::TaskCx<'task>,
    cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
    dir: &std::path::Path,
    camera: ContentDigest,
) -> Test {
    use fss_core::region::ContextAuthority;
    use fss_reference::{
        DeploymentLimits, ReplayCx,
        unifi_direct::{
            archive, evidence,
            http_stream::media_archive::{Driver, Observer, SliceConfig, SliceStop, Step},
            recording_storage,
            source_coordinator::ArchiveAdmission,
            source_worker, video_bootstrap, video_worker,
        },
    };
    struct Access;
    impl archive::RetainAuthority for Access {
        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
            true
        }
    }
    impl archive::ReadAuthority for Access {
        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
            true
        }
    }
    let mut driver = if let Some(driver) = started {
        if connected.is_some() {
            return Err("both archive inputs supplied".into());
        }
        driver
    } else {
        let connected = connected.ok_or("missing connected media")?;
        let replay_authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:http-media-archive".into(),
            operation_id: OperationId::parse("operation:http-media-archive")?,
            principal: "principal:fixture".into(),
            capabilities: vec!["ADP-REPLAY-001".into()],
            deadline: None,
            priority: 1,
            budgets: BudgetVector::builder().bytes(256 * 1024 * 1024).build()?,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"HTTP media archive fixture"),
            generation: 1,
        })?;
        let source_replay = ReplayCx::from_context_authority(&replay_authority, dir.to_path_buf())?;
        let video_replay = ReplayCx::from_context_authority(&replay_authority, dir.to_path_buf())?;
        let root = dir.join("media-archive");
        let retention = ContentDigest::sha256(b"HTTP media retention");
        let cfg = recording_storage::Configuration {
            root: &root,
            site_lineage: "site:http-media-fixture",
            source: SourceKey {
                connection: 1,
                generation: 1,
            },
            camera_claim: camera,
            source_retention: retention,
            source_scope: ContentDigest::sha256(b"HTTP source scope"),
            av_scope: ContentDigest::sha256(b"HTTP video scope"),
            source_deployment_limits: DeploymentLimits::standard(),
            av_deployment_limits: DeploymentLimits::standard(),
            source_history_limits: EffectJournalLimits::default(),
            av_history_limits: EffectJournalLimits::default(),
            limits: archive::Limits::default(),
            max_source_bytes: 1024 * 1024,
            work_limit: 4_000_000_000,
        };
        let storage = recording_storage::create(
            task,
            cx,
            clock,
            cfg,
            source_replay,
            video_replay,
            Arc::new(Access),
        )?;
        let policy = video_bootstrap::Policy {
            inband: false,
            retention,
            media_limits: fss_container::Mp4Limits::default(),
            evidence_limits: evidence::Limits::default(),
        };
        let other_camera = ContentDigest::sha256(b"different camera");
        let other_root = dir.join("other-media-archive");
        let other_cfg = recording_storage::Configuration {
            root: &other_root,
            camera_claim: other_camera,
            ..cfg
        };
        let other_source = ReplayCx::from_context_authority(&replay_authority, dir.to_path_buf())?;
        let other_video = ReplayCx::from_context_authority(&replay_authority, dir.to_path_buf())?;
        let other_storage = recording_storage::create(
            task,
            cx,
            clock,
            other_cfg,
            other_source,
            other_video,
            Arc::new(Access),
        )?;
        let mismatch = match Driver::attach(connected, other_storage, policy, other_camera) {
            Err(refusal) => refusal,
            Ok(_) => return Err("wrong camera archive binding accepted".into()),
        };
        let _other_storage = mismatch.storage;
        let mut incompatible_policy = policy;
        incompatible_policy.inband = true;
        let incompatible =
            match Driver::attach(mismatch.connected, storage, incompatible_policy, camera) {
                Err(refusal) => refusal,
                Ok(_) => return Err("incompatible video format accepted".into()),
            };
        let storage = incompatible.storage;
        let mut connected = incompatible.connected;
        connected
            .begin_name_probe(fss_packet::extended_flv::stream::NameProbeOwner::new(
                "event1",
                "0123456789abcdef",
                256 * 1024,
                4,
                1_000_000,
            )?)
            .map_err(|_| "name probe installation refused")?;
        let pending = match Driver::attach(connected, storage, policy, camera) {
            Err(refusal) => refusal,
            Ok(_) => return Err("unfinished name probe accepted".into()),
        };
        let mut connected = pending.connected;
        let _probe = connected.take_name_probe().ok_or("missing name probe")?;
        Driver::attach(connected, pending.storage, policy, camera)
            .map_err(|_| "HTTP media archive attachment refused")?
    };
    let cost = BudgetVector::ZERO;
    struct RecorderObserver {
        event: Option<Box<Step>>,
        refuse_once: bool,
    }
    impl Observer for RecorderObserver {
        fn observe(
            &mut self,
            event: Box<Step>,
        ) -> Result<fss_reference::unifi_direct::source_coordinator::Decision, Box<Step>> {
            if self.refuse_once {
                self.refuse_once = false;
                return Err(event);
            }
            self.event = Some(event);
            Ok(fss_reference::unifi_direct::source_coordinator::Decision::Yield)
        }
    }
    let mut observer = RecorderObserver {
        event: None,
        refuse_once: true,
    };
    let admission = ArchiveAdmission {
        resource: "fixture:archive",
        cost: &cost,
    };
    if !matches!(
        driver
            .run_slice(
                task,
                cx,
                clock,
                SliceConfig {
                    wait: Duration::from_secs(1),
                    max_steps: 0,
                    source_archive: admission,
                    video_archive: admission,
                },
                &mut observer
            )
            .await,
        SliceStop::Configuration
    ) || observer.event.is_some()
        || !observer.refuse_once
    {
        return Err("invalid slice began archive work".into());
    }
    if !matches!(
        driver
            .step(
                task,
                cx,
                clock,
                Duration::ZERO,
                ArchiveAdmission {
                    resource: "fixture:archive",
                    cost: &cost
                },
                ArchiveAdmission {
                    resource: "fixture:archive",
                    cost: &cost
                },
            )
            .await,
        Step::Configuration
    ) {
        return Err("zero wait did not refuse before media work".into());
    }
    let mut foreign_budget = BudgetVector::ZERO;
    foreign_budget.bytes = 64 * 1024 * 1024;
    foreign_budget.network_bytes = 1_000_000;
    let (mut foreign_authority, mut foreign_tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:foreign-archive".into(),
            operation_id: OperationId::parse("operation:foreign-archive")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::ReadMedia.as_str().into(),
                RuntimeGrant::ObjectStage.as_str().into(),
                RuntimeGrant::ObjectPublish.as_str().into(),
            ],
            deadline: None,
            priority: 1,
            budgets: foreign_budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"foreign archive"),
            generation: 1,
        },
        RegionId::new("region:foreign-archive")?,
        RegionKind::Process,
        foreign_budget,
        TimestampNs(1),
    )?;
    let foreign = run_owned_async(
        &mut foreign_authority,
        &mut foreign_tree,
        TaskSpec {
            task_id: TaskId::new("task:serializer-test")?,
            started_at: TimestampNs(7),
        },
        cx,
        async |foreign_task, foreign_cx| {
            let refused = match MeteredClock::new(foreign_task, foreign_cx, TimestampNs(8)) {
                Ok(foreign_clock) => matches!(
                    driver
                        .step(
                            foreign_task,
                            foreign_cx,
                            foreign_clock,
                            Duration::from_secs(5),
                            ArchiveAdmission {
                                resource: "fixture:archive",
                                cost: &cost
                            },
                            ArchiveAdmission {
                                resource: "fixture:archive",
                                cost: &cost
                            },
                        )
                        .await,
                    Step::Configuration
                ),
                Err(_) => false,
            };
            TaskCompletion {
                output: refused,
                outcome: TaskOutcome::Success,
                completed_at: TimestampNs(9),
            }
        },
    )
    .await?;
    if !foreign.output {
        return Err("foreign task was allowed to drive the archive".into());
    }
    foreign.receipt?;
    let pool = cx
        .blocking_pool_handle()
        .ok_or("missing archive blocking pool")?;
    let occupied = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker_occupied = Arc::clone(&occupied);
    let (release, wait_for_release) = std::sync::mpsc::channel();
    let blocker = pool.spawn(move || {
        worker_occupied.store(true, std::sync::atomic::Ordering::Release);
        let _ = wait_for_release.recv();
    });
    timeout(cx.now(), Duration::from_secs(5), async {
        while !occupied.load(std::sync::atomic::Ordering::Acquire) {
            asupersync::time::sleep(cx.now(), Duration::from_millis(2)).await;
        }
    })
    .await?;
    let mut release = Some(release);
    let mut observed_bounded_wait = false;
    let mut pin = None;
    let mut source_count = 0;
    for _ in 0..512 {
        let result = timeout(
            cx.now(),
            Duration::from_secs(30),
            driver.run_slice(
                task,
                cx,
                clock,
                SliceConfig {
                    wait: if release.is_some() {
                        Duration::from_millis(50)
                    } else {
                        Duration::from_secs(5)
                    },
                    max_steps: 8,
                    source_archive: admission,
                    video_archive: admission,
                },
                &mut observer,
            ),
        )
        .await?;
        let event = match result {
            SliceStop::ObserverYielded => *observer.event.take().ok_or("missing observed event")?,
            SliceStop::ObserverRefused(event) | SliceStop::Halted(event) => *event,
            _ => return Err("unexpected archive slice result".into()),
        };
        match event {
            Step::SourceRunning if release.is_some() => {
                observed_bounded_wait = true;
                release.take().ok_or("missing archive release")?.send(())?;
            }
            Step::SourceCompleted(completion) => {
                if completion.runtime.is_err() {
                    return Err("source archive runtime failed".into());
                }
                if !matches!(
                    completion.outcome,
                    source_worker::Outcome::Publication(
                        source_worker::Publication::Published { .. }
                    )
                ) {
                    return Err("source archive did not publish".into());
                }
                source_count += 1;
            }
            Step::VideoCompleted(completion) => {
                if completion.runtime.is_err() {
                    return Err("video archive runtime failed".into());
                }
                match completion.outcome {
                    video_worker::Outcome::Publication(video_worker::Publication::Published(
                        published,
                    )) => {
                        pin = Some(published.pin);
                        break;
                    }
                    _ => return Err("video archive did not publish".into()),
                }
            }
            Step::SourceOffered(_)
            | Step::Configured
            | Step::VideoOffered
            | Step::SourceStarted
            | Step::VideoStarted
            | Step::SourceRunning
            | Step::VideoRunning
            | Step::Media(_)
            | Step::Idle => (),
            Step::StartRefused(error) => {
                return Err(format!("archive start refused: {error:?}").into());
            }
            Step::SourceRefused(refusal) => {
                let reason = match refusal {
                    source_worker::OfferRefusal::Busy(_) => "busy",
                    source_worker::OfferRefusal::Invalid(_) => "invalid",
                    source_worker::OfferRefusal::Fenced(_) => "fenced",
                };
                return Err(format!("source offer refused: {reason}").into());
            }
            Step::VideoRefused(refusal) => {
                let reason = match refusal {
                    video_worker::OfferRefusal::Busy(_) => "busy".to_owned(),
                    video_worker::OfferRefusal::Fenced(_) => "fenced".to_owned(),
                    video_worker::OfferRefusal::Sink(refusal) => {
                        format!("sink {:?}", refusal.reason)
                    }
                };
                return Err(format!("video offer refused: {reason}").into());
            }
            Step::ConfigurationRefused(refusal) => {
                return Err(format!("video configuration refused: {:?}", refusal.reason).into());
            }
            Step::MediaError(error) => return Err(format!("media error: {error:?}").into()),
            Step::SourceRetryRequired => return Err("source retry required".into()),
            Step::VideoRetryRequired => return Err("video retry required".into()),
            Step::ArchiveUnavailable => return Err("archive unavailable".into()),
            Step::Configuration => return Err("archive context refused".into()),
            Step::Halted => return Err("archive halted".into()),
            Step::ConfigurationCopyRefused(_) => return Err("configuration copy refused".into()),
            Step::ConfigurationChanged(_) => return Err("configuration changed".into()),
            Step::SegmentBeforeConfiguration(_) => {
                return Err("segment before configuration".into());
            }
            Step::WorkerRefused(_) => return Err("video worker refused".into()),
            Step::RecoveredWorkerRefused { .. } => {
                return Err("recovered video worker refused".into());
            }
        }
    }
    let pin = pin.ok_or("no video archive publication")?;
    if observer.refuse_once {
        return Err("observer refusal was not exercised".into());
    }
    if !observed_bounded_wait || !blocker.is_done() {
        return Err("bounded archive wait did not retain the running worker".into());
    }
    if source_count < 2 {
        return Err("header and configuration were not archived".into());
    }
    driver.abort();
    let parts = driver
        .into_parts()
        .map_err(|_| "archive workers did not drain")?;
    let mut video = parts
        .video
        .ok_or("missing video archive worker")?
        .retire()
        .map_err(|_| "video archive did not retire")?;
    let clip = archive::read_unknown_time_video_clip(
        &mut video.parts.deployment,
        pin,
        &Access,
        archive::Limits::default(),
        &mut fss_geometry::WorkBudget::new(4_000_000_000),
        &video.parts.replay,
    )?;
    let movie = AvcMp4::parse(clip.bytes(), None, DemuxLimits::default())?;
    let annex = movie.annex_b(0, 1)?;
    let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits {
        max_pictures: 8,
        ..Default::default()
    })?;
    let mut pictures = decoder.decode_annex_b(annex.bytes())?;
    pictures.extend(decoder.finish()?);
    if pictures.len() != 1 || (pictures[0].width(), pictures[0].height()) != (2688, 1512) {
        return Err("archived high-resolution frame mismatch".into());
    }
    Ok(())
}

async fn exercise_http_av_network_exhaustion<'scope, 'task>(
    mut driver: fss_reference::unifi_direct::http_stream::media_av_archive::Driver,
    task: &'scope fss_runtime::execution::TaskCx<'task>,
    cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
    admission: fss_reference::unifi_direct::source_coordinator::ArchiveAdmission<'_>,
    resource: &str,
) -> Test {
    use fss_reference::unifi_direct::{http_stream::media_av_archive as av_archive, ingress, pipeline, source_worker};
    use fss_runtime::tcp_ingress::IngressError;

    // Exhaust the actual task ledger after bootstrap. The media source can
    // still consume any already-reserved bytes before its next read fails.
    let mut cost = BudgetVector::ZERO;
    cost.network_bytes = task.remaining_budget()?.network_bytes;
    if cost.network_bytes == 0 { return Err("fixture exhausted too early".into()); }
    task.checkpoint_for(RuntimeGrant::AdapterNet, resource, clock.now()?, &cost)?;
    let mut stopped = false;
    for _ in 0..4096 {
        let event = driver.step(task, cx, clock, Duration::from_secs(2), admission, admission).await;
        if matches!(event, av_archive::Step::MediaError(pipeline::Error::Ingress(
            ingress::Error::Source(IngressError::BudgetExhausted)
        ))) {
            if !event.has_retirable_tail() { return Err("budget stop not classified for retirement".into()); }
            stopped = true;
            break;
        }
        match event {
            av_archive::Step::Offer(_) | av_archive::Step::SourceStarted | av_archive::Step::SourceRunning
            | av_archive::Step::AvStarted | av_archive::Step::AvRunning | av_archive::Step::Idle
            | av_archive::Step::Media(pipeline::Step::Progress { .. }) => (),
            av_archive::Step::SourceCompleted(done) if done.runtime.is_ok()
                && matches!(done.outcome, source_worker::Outcome::Publication(source_worker::Publication::Published { .. })) => (),
            av_archive::Step::AvCompleted(done) if done.runtime.is_ok()
                && matches!(done.outcome, fss_reference::unifi_direct::av_worker::UnknownTimeOutcome::Publication(
                    fss_reference::unifi_direct::av_worker::UnknownTimePublication::Published(_))) => (),
            _ => return Err("unexpected stop before network exhaustion".into()),
        }
    }
    if !stopped { return Err("network budget stop was not observed".into()); }
    if av_archive::Step::MediaError(pipeline::Error::Cancelled).has_retirable_tail() {
        return Err("unqualified cancellation classified as retirable".into());
    }
    driver.abort();
    let _source = driver.join_source().await;
    let _av = driver.join_av().await;
    let parts = driver.into_parts().map_err(|_| "archive worker did not drain")?;
    let retired = parts.prepare_retirement().map_err(|_| "network stop tail retirement refused")?;
    let _assets = retired.assets;
    exercise_original_tail_readback(retired.tail, task, cx, clock, admission, 10, None).await
}

type PreviousTailCheck = (
    Vec<(fss_reference::unifi_direct::archive::UnknownTimePin, (u64, usize, usize))>,
    Vec<(u64, usize, fss_reference::unifi_direct::recording::SourceDisposition)>,
);

async fn exercise_original_tail_readback<'scope, 'task>(
    mut tail: fss_reference::unifi_direct::retirement_source::Driver,
    task: &'scope fss_runtime::execution::TaskCx<'task>,
    cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
    admission: fss_reference::unifi_direct::source_coordinator::ArchiveAdmission<'_>,
    wire_mode: u8,
    previous: Option<PreviousTailCheck>,
) -> Test {
    use fss_reference::unifi_direct::{archive, retirement_source, source_worker};
    let start = tail.plan().start.ok_or("network stop tail start missing")?;
    let end = tail.plan().end.ok_or("network stop tail end missing")?;
    let expected: Vec<_> = tail.plan().items_in_order().map(|item|
        (item.record.offset(), item.record.bytes().len(), item.disposition)).collect();
    if tail.plan().is_empty() || tail.plan().received != end || !tail.enable_batching(256, 1024 * 1024) {
        return Err("network stop tail is empty or not batchable".into());
    }
    let mut offers = Vec::new();
    let mut pending = None;
    let mut finished = false;
    for _ in 0..2048 {
        match tail.step(task, cx, clock, admission).await {
            retirement_source::DriverStep::BatchOffered { offset, len, records } => {
                if pending.replace((offset, len, records)).is_some() { return Err("overlapping tail batches".into()); }
            }
            retirement_source::DriverStep::Started => (),
            retirement_source::DriverStep::Completed(done) if done.runtime.is_ok() => {
                let pin = match done.outcome {
                    source_worker::Outcome::Publication(source_worker::Publication::Published { pin, .. }) => pin,
                    _ => return Err("network stop tail publication refused".into()),
                };
                offers.push((pin, pending.take().ok_or("tail receipt without offer")?));
            }
            retirement_source::DriverStep::Finished if pending.is_none() => { finished = true; break; }
            _ => return Err("network stop tail archival failed".into()),
        }
    }
    if !finished || offers.is_empty() { return Err("network stop tail did not publish".into()); }
    let parts = tail.into_parts().map_err(|_| "network stop tail still running")?;
    if !parts.plan.is_empty() { return Err("network stop tail retained unread data".into()); }
    let worker = parts.worker.retire().map_err(|_| "network stop source worker still active")?;
    if worker.pending.is_some() || worker.fenced { return Err("network stop source custody unresolved".into()); }
    let mut storage = worker.parts;
    let wire = synthetic_high_flv(wire_mode)?;
    let mut next_index = 0usize;
    for (pin, (offset, len, records)) in offers {
        let batch = archive::read_unknown_time_source_batch(&mut storage.deployment, pin, &ArchiveAccess,
            archive::Limits::default(), &mut fss_geometry::WorkBudget::new(4_000_000_000), &storage.replay)?;
        if batch.payload.len() != len || batch.records.len() != records || batch.records.first().map(|r| r.offset) != Some(offset) {
            return Err("network stop tail differs from original wire".into());
        }
        for record in &batch.records {
            let length = record.range.end.checked_sub(record.range.start).ok_or("bad record range")?;
            if expected.get(next_index) != Some(&(record.offset, length, record.disposition)) {
                return Err("network stop source metadata or order changed".into());
            }
            let begin = usize::try_from(record.offset)?;
            let stop = begin.checked_add(length).ok_or("network stop tail offset overflow")?;
            if wire.get(begin..stop) != batch.payload.get(record.range.clone()) {
                return Err("network stop source bytes changed".into());
            }
            next_index += 1;
        }
    }
    if next_index != expected.len() || expected.first().map(|item| item.0) != Some(start)
        || expected.last().and_then(|item| item.0.checked_add(item.1 as u64)) != Some(end) {
        return Err("network stop tail readback omitted a held range".into());
    }
    if let Some((offers, expected)) = previous {
        let mut seen = 0usize;
        for (pin, (offset, len, records)) in offers {
            let batch = archive::read_unknown_time_source_batch(&mut storage.deployment, pin, &ArchiveAccess,
                archive::Limits::default(), &mut fss_geometry::WorkBudget::new(4_000_000_000), &storage.replay)?;
            if batch.payload.len() != len || batch.records.len() != records || batch.records.first().map(|r| r.offset) != Some(offset) {
                return Err("reused old tail readback differs".into());
            }
            for record in &batch.records {
                let length = record.range.end.checked_sub(record.range.start).ok_or("bad old range")?;
                if expected.get(seen) != Some(&(record.offset, length, record.disposition)) { return Err("old metadata changed".into()); }
                let start = usize::try_from(record.offset)?;
                let end = start.checked_add(length).ok_or("old tail overflow")?;
                if wire.get(start..end) != batch.payload.get(record.range.clone()) { return Err("old tail bytes changed".into()); }
                seen += 1;
            }
        }
        if seen != expected.len() { return Err("reused old tail incomplete".into()); }
    }
    Ok(())
}

struct ReuseFixture<'scope, 'task, 'policy> {
    bootstrap: Option<Box<fss_reference::unifi_direct::http_stream::media_av_startup::Driver>>,
    recorder: Option<Box<fss_reference::unifi_direct::http_stream::media_av_archive::Driver>>,
    listener: listener::Listener<'scope, 'task, 'policy>,
    previous: fss_reference::unifi_direct::http_stream::media_av_reconnect::ReusedPrevious,
    retired: std::collections::VecDeque<fss_reference::unifi_direct::media_reconnect::Retired>,
    old_pins: Vec<fss_reference::unifi_direct::archive::UnknownTimePin>,
    old_offers: Vec<(fss_reference::unifi_direct::archive::UnknownTimePin, (u64, usize, usize))>,
    old_expected: Vec<(u64, usize, fss_reference::unifi_direct::recording::SourceDisposition)>,
    next_key: SourceKey,
    effect: ContentDigest,
    source_pins: Vec<fss_reference::unifi_direct::archive::UnknownTimePin>,
    observations: Vec<Option<fss_reference::unifi_direct::pipeline::AudioEvent>>,
    parked: Option<Box<fss_reference::unifi_direct::http_stream::media_av_managed::Parked<'scope, 'task>>>,
}

#[inline(never)]
fn build_reuse_manager(
    driver: fss_reference::unifi_direct::http_stream::media_av_archive::Driver,
    dir: &std::path::Path,
) -> Result<Box<fss_reference::unifi_direct::http_stream::media_av_managed::Managed>, Box<dyn Error>> {
    use fss_core::region::ContextAuthority;
    use fss_reference::{ReplayCx, unifi_direct::{archive, av_rollover_generation,
        http_stream::media_av_managed::Managed, recording_session::AudioAllowancePolicy}};
    let auth = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:http-reuse-managed".into(),
        operation_id: OperationId::parse("operation:http-reuse-managed")?,
        principal: "principal:fixture".into(), capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None, priority: 1, budgets: BudgetVector::builder().bytes(128 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"http reuse generation"), generation: 1,
    })?;
    let replay = Arc::new(ReplayCx::from_context_authority(&auth, dir.to_path_buf())?);
    let plan = av_rollover_generation::Plan::new(av_rollover_generation::Configuration {
        namespace: "reuse-managed".into(), scope_seed: ContentDigest::sha256(b"http reuse scope"),
        first: 7, count: 1, journal_replay: replay.clone(), pin_replay: replay,
        journal_io: Arc::new(HostSpoolIo), pin_io: Arc::new(HostSpoolIo),
        journal_limits: EffectJournalLimits::default(), pin_limits: EffectJournalLimits::default(),
        read: Arc::new(ArchiveAccess),
        object_limits: archive::StagedAvLimits { max_objects: 8192, max_object_bytes: 1024 * 1024, max_total_bytes: 8 * 1024 * 1024 },
        work_limit: 4_000_000_000,
    }).map_err(|_| "reuse generation plan refused")?;
    let audio = AudioAllowancePolicy::new(1_000_000, 1024, 65_536).ok_or("reuse audio policy refused")?;
    Ok(Box::new(Managed::new(driver, plan, audio, 2).map_err(|_| "reuse manager refused")?))
}

#[inline(never)]
fn park_reuse_manager<'scope, 'task>(
    driver: fss_reference::unifi_direct::http_stream::media_av_archive::Driver,
    task: &'scope fss_runtime::execution::TaskCx<'task>, cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>, dir: &std::path::Path,
) -> Result<(Box<fss_reference::unifi_direct::http_stream::media_av_managed::Parked<'scope, 'task>>,
    Box<fss_reference::unifi_direct::http_stream::media_av_archive::Parts>), Box<dyn Error>> {
    let manager = build_reuse_manager(driver, dir)?;
    manager.park_for_reconnect(task, cx, clock).map_err(|_| "reuse manager could not park".into())
}

#[inline(never)]
fn boxed_supervisor_step<'a, 'scope: 'a, 'task: 'scope, 'policy: 'scope>(
    supervisor: &'a mut fss_reference::unifi_direct::http_stream::media_av_supervisor::Supervisor<'scope, 'task, 'policy>,
    task: &'scope fss_runtime::execution::TaskCx<'task>, cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>, admission: fss_reference::unifi_direct::source_coordinator::ArchiveAdmission<'a>,
) -> Pin<Box<dyn std::future::Future<Output = fss_reference::unifi_direct::http_stream::media_av_supervisor::Step> + 'a>> {
    Box::pin(supervisor.step(task, cx, clock, Duration::from_secs(2), admission, admission, &BudgetVector::ZERO, admission))
}

struct SupervisorFixture<'scope, 'task, 'policy> {
    supervisor: Box<fss_reference::unifi_direct::http_stream::media_av_supervisor::Supervisor<'scope, 'task, 'policy>>,
    boundary: Box<fss_reference::unifi_direct::http_stream::media_av_supervisor::Boundary>,
    pins: Vec<fss_reference::unifi_direct::archive::UnknownTimePin>,
    source_receipts: Vec<fss_reference::unifi_direct::archive::UnknownTimePin>,
    old_tail_receipts: Vec<fss_reference::unifi_direct::archive::UnknownTimePin>,
    observations: Vec<Option<fss_reference::unifi_direct::pipeline::AudioEvent>>,
    effect: ContentDigest,
    rollover: bool,
}

enum SupervisorRun<'scope, 'task, 'policy> {
    Recorded(Box<SupervisorFixture<'scope, 'task, 'policy>>),
    GeneralStopped {
        scope: fss_reference::unifi_direct::http_stream::media_av_recovery::Scope<'scope, 'task, 'policy>,
        recovery: Box<fss_reference::unifi_direct::http_stream::media_av_recovery::Recovery>,
        pins: Vec<fss_reference::unifi_direct::archive::UnknownTimePin>,
        source_receipts: Vec<fss_reference::unifi_direct::archive::UnknownTimePin>,
        old_tail_receipts: Vec<fss_reference::unifi_direct::archive::UnknownTimePin>,
        observations: Vec<Option<fss_reference::unifi_direct::pipeline::AudioEvent>>,
    },
    RetryStopped {
        scope: fss_reference::unifi_direct::http_stream::media_av_supervisor::ReconnectingScope<'scope, 'task, 'policy>,
        recovery: Box<fss_reference::unifi_direct::http_stream::media_av_supervisor::ReconnectingRecovery>,
        pins: Vec<fss_reference::unifi_direct::archive::UnknownTimePin>,
        source_receipts: Vec<fss_reference::unifi_direct::archive::UnknownTimePin>,
        old_tail_receipts: Vec<fss_reference::unifi_direct::archive::UnknownTimePin>,
        observations: Vec<Option<fss_reference::unifi_direct::pipeline::AudioEvent>>,
    },
}

async fn exercise_managed_supervisor<'scope, 'task: 'scope, 'policy: 'scope>(
    manager: Box<fss_reference::unifi_direct::http_stream::media_av_managed::Managed>,
    listener: listener::Listener<'scope, 'task, 'policy>,
    task: &'scope fss_runtime::execution::TaskCx<'task>, cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
    admission: fss_reference::unifi_direct::source_coordinator::ArchiveAdmission<'_>,
    policy: fss_reference::unifi_direct::av_owned_sink::BootstrapPolicy, effect: ContentDigest, scenario: u8,
) -> Result<SupervisorRun<'scope, 'task, 'policy>, Box<dyn Error>> {
    use fss_reference::unifi_direct::{av_worker, pipeline, retirement_source, source_worker,
        http_stream::{media_av_archive as av_archive, media_av_managed as managed,
            media_av_reconnect as reconnect, media_av_startup as startup, media_av_supervisor as supervisor}};
    let address = listener.local_addr();
    let retry_test = matches!(scenario, 47 | 50 | 51);
    let rollover = matches!(scenario, 48 | 49 | 52);
    let mut bad_cost = BudgetVector::ZERO;
    bad_cost.bytes = u64::MAX;
    let denied_admission = fss_reference::unifi_direct::source_coordinator::ArchiveAdmission {
        resource: admission.resource, cost: &bad_cost,
    };
    let config = supervisor::Config {
        successor: reconnect::SuccessorConfig { flv: FlvLimits::default(), max_buffer: 1024 * 1024,
            search: fss_packet::extended_flv::stream::SearchMode::Conservative,
            recorder: recording::Limits::default(), inband: false,
            expected_dimensions: Some([160, 128]),
            chunk_bytes: 4096, max_bytes: 1024 * 1024,
            wait: if retry_test { Duration::from_millis(200) } else { Duration::from_secs(5) } },
        attempts_per_eof: 2, retention: if scenario == 54 { ContentDigest::sha256(b"wrong retention") } else { ContentDigest::sha256(b"preflight retention") },
        bootstrap: policy, supplied_unverified_audio: None,
    };
    let wrong_clock = MeteredClock::new(task, cx, TimestampNs(1))?;
    let (manager, listener) = match supervisor::Supervisor::new(manager, listener, task, cx, wrong_clock, config) {
        Err(owners) => owners,
        Ok(_) => return Err("supervisor accepted a different listener clock".into()),
    };
    let mut supervisor = supervisor::Supervisor::new(manager, listener, task, cx, clock, config)
        .map_err(|_| "supervisor refused matching listener")?;
    supervisor = match supervisor.detach_reconnecting() {
        Err(original) => original,
        Ok(_) => return Err("recording phase incorrectly detached as reconnecting".into()),
    };
    let mut pins = Vec::new();
    let mut source_receipts = Vec::new();
    let mut observations = Vec::new();
    let mut old_tail_receipts = Vec::new();
    let mut sender = None;
    let mut eof_count = 0;
    let mut resumed = false;
    let mut listener_refusals = 0;
    let mut rollovers = 0;
    let mut check_prepared = false;
    let mut check_verified = false;
    let mut check_start_refused = false;
    let mut inject_refusal = false;
    for _ in 0..1024 {
        let next_admission = if inject_refusal { denied_admission } else { admission };
        inject_refusal = false;
        match boxed_supervisor_step(&mut supervisor, task, cx, clock, next_admission).await {
            supervisor::Step::Recording(event) => {
                match *event {
                managed::Step::Planned(_) | managed::Step::CreatorStarted | managed::Step::CreatorReady
                | managed::Step::PlanExhausted | managed::Step::AwaitingSupplies(_)
                | managed::Step::PreflightPrepared | managed::Step::RolloverStarted
                | managed::Step::RolloverWaiting | managed::Step::PreflightReady => (),
                managed::Step::Resumed(_) if rollover => { rollovers += 1; },
                managed::Step::Recording(av_archive::AllowanceStep::Renewed { .. }) => (),
                managed::Step::Recording(av_archive::AllowanceStep::Recording(event)) => match event {
                    av_archive::Step::AvStarted if scenario == 53 => {
                        let (scope, recovery) = fss_reference::unifi_direct::http_stream::media_av_recovery::detach(supervisor);
                        return Ok(SupervisorRun::GeneralStopped { scope, recovery, pins,
                            source_receipts, old_tail_receipts, observations });
                    }
                    av_archive::Step::Offer(av_archive::Offer::Source { audio, .. })
                    | av_archive::Step::Offer(av_archive::Offer::Buffered(audio))
                    | av_archive::Step::Offer(av_archive::Offer::Segment(audio)) => observations.push(audio),
                    av_archive::Step::SourceStarted | av_archive::Step::SourceRunning | av_archive::Step::AvStarted
                    | av_archive::Step::AvRunning | av_archive::Step::Idle
                    | av_archive::Step::Media(pipeline::Step::Progress { .. }) => (),
                    av_archive::Step::SourceCompleted(done) if done.runtime.is_ok() => match done.outcome {
                        source_worker::Outcome::Publication(source_worker::Publication::Published { pin, .. }) => source_receipts.push(pin),
                        _ => return Err("supervised source publication refused".into()),
                    },
                    av_archive::Step::AvCompleted(done) if done.runtime.is_ok() => match done.outcome {
                        av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(value)) => pins.push(value.pin),
                        av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Refused {
                            reason: av_worker::FailureReason::JournalCapacity, rollover: Some(_), ..
                        }) if rollover => (),
                        av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Refused {
                            stage, reason, rollover, ..
                        }) => return Err(format!("supervised A/V publication refused: {stage:?} {reason:?} rollover={}", rollover.is_some()).into()),
                        _ => return Err("supervised A/V publication refused".into()),
                    },
                    av_archive::Step::Media(pipeline::Step::Eof) => {
                        eof_count += 1;
                        if eof_count == 1 && !retry_test {
                            let wire = synthetic_high_flv(if rollover { 12 } else { 4 })?;
                            sender = Some(std::thread::spawn(move || -> std::io::Result<()> {
                                let mut socket = std::net::TcpStream::connect_timeout(&address.into(), Duration::from_secs(5))?;
                                socket.write_all(&wire)
                            }));
                        } else if eof_count > 1 { break; }
                    }
                    _ => return Err("supervised archive stopped".into()),
                },
                _ => return Err("supervised manager stopped".into()),
            } },
            supervisor::Step::ReconnectStarted | supervisor::Step::ArchivesReused => (),
            supervisor::Step::VerificationPrepared if rollover => {
                check_prepared = true;
                inject_refusal = scenario == 49;
            }
            supervisor::Step::Verifying(event) if rollover => match *event {
                reconnect::VerifyStep::Started if scenario == 52 => {
                    sender.take().ok_or("verification sender missing")?.join()
                        .map_err(|_| "verification sender panicked")??;
                    let (scope, recovery) = fss_reference::unifi_direct::http_stream::media_av_recovery::detach(supervisor);
                    return Ok(SupervisorRun::GeneralStopped { scope, recovery, pins,
                        source_receipts, old_tail_receipts, observations });
                }
                reconnect::VerifyStep::Started | reconnect::VerifyStep::Running | reconnect::VerifyStep::Ready => (),
                reconnect::VerifyStep::StartRefused(_) if scenario == 49 => {
                    check_start_refused = true;
                    if !matches!(boxed_supervisor_step(&mut supervisor, task, cx, clock, admission).await,
                        supervisor::Step::VerificationBlocked) || !supervisor.authorize_verification_retry() {
                        return Err("custody verification refusal did not require an explicit retry".into());
                    }
                }
                reconnect::VerifyStep::Completed(done) if done.runtime.is_ok()
                    && matches!(done.outcome, fss_reference::unifi_direct::av_recovered_startup::Outcome::Verified) => {
                    check_verified = true;
                }
                _ => return Err("supervised custody verification failed".into()),
            },
            supervisor::Step::Reconnecting(event) => match *event {
                reconnect::AutoStep::Tail(retirement_source::DriverStep::Started) if scenario == 51 => {
                    let (scope, recovery) = fss_reference::unifi_direct::http_stream::media_av_recovery::detach(supervisor);
                    return Ok(SupervisorRun::GeneralStopped { scope, recovery, pins,
                        source_receipts, old_tail_receipts, observations });
                }
                reconnect::AutoStep::Tail(retirement_source::DriverStep::Started) if scenario == 50 => {
                    let (scope, recovery) = supervisor.detach_reconnecting()
                        .map_err(|_| "active tail recovery split refused")?;
                    if recovery.tail_finished || recovery.parked.is_none() {
                        return Err("active tail recovery lost its owners".into());
                    }
                    return Ok(SupervisorRun::RetryStopped { scope, recovery, pins,
                        source_receipts, old_tail_receipts, observations });
                }
                reconnect::AutoStep::Tail(retirement_source::DriverStep::Offered { .. }
                    | retirement_source::DriverStep::BatchOffered { .. }
                    | retirement_source::DriverStep::Started | retirement_source::DriverStep::Finished) => (),
                reconnect::AutoStep::Tail(retirement_source::DriverStep::Completed(done)) if done.runtime.is_ok() => match done.outcome {
                    source_worker::Outcome::Publication(source_worker::Publication::Published { pin, .. }) => old_tail_receipts.push(pin),
                    _ => return Err("supervised old tail refused".into()),
                },
                reconnect::AutoStep::Accepted(_) | reconnect::AutoStep::Ready(_) => (),
                reconnect::AutoStep::Refused(reconnect::AutoError::Admission(
                    fss_reference::unifi_direct::media_reconnect::Error::Listener(_))) if retry_test => {
                    listener_refusals += 1;
                    if !matches!(boxed_supervisor_step(&mut supervisor, task, cx, clock, admission).await,
                        supervisor::Step::ReconnectBlocked) || !supervisor.authorize_reconnect_retry() {
                        return Err("listener refusal did not require explicit retry".into());
                    }
                }
                reconnect::AutoStep::Refused(reconnect::AutoError::Admission(
                    fss_reference::unifi_direct::media_reconnect::Error::AttemptLimit)) if retry_test => {
                    if listener_refusals != 2 || !matches!(boxed_supervisor_step(&mut supervisor, task, cx, clock, admission).await,
                        supervisor::Step::ReconnectBlocked) || supervisor.authorize_reconnect_retry() {
                        return Err("attempt limit did not permanently fence retries".into());
                    }
                    let (scope, recovery) = supervisor.detach_reconnecting()
                        .map_err(|_| "reconnecting supervisor refused recovery split")?;
                    if recovery.parked.is_none() || recovery.boundary.is_some() || old_tail_receipts.is_empty() {
                        return Err("attempt limit lost retained owners".into());
                    }
                    return Ok(SupervisorRun::RetryStopped { scope, recovery, pins,
                        source_receipts, old_tail_receipts, observations });
                }
                _ => return Err("supervised reconnect stopped".into()),
            },
            supervisor::Step::Starting(event) => match *event {
                startup::Step::Retained | startup::Step::Progress | startup::Step::Idle
                | startup::Step::SourceStarted | startup::Step::SourceRunning | startup::Step::Ready => (),
                startup::Step::Buffered(audio) | startup::Step::SourceOffered { audio, .. } => observations.push(audio),
                startup::Step::SourceCompleted(done) if done.runtime.is_ok() => match done.outcome {
                    source_worker::Outcome::Publication(source_worker::Publication::Published { pin, .. }) => source_receipts.push(pin),
                    _ => return Err("supervised bootstrap source refused".into()),
                },
                _ => return Err("supervised bootstrap stopped".into()),
            },
            supervisor::Step::Resumed => { resumed = true; },
            supervisor::Step::ReuseStopped if scenario == 54 => {
                sender.take().ok_or("reuse refusal sender missing")?.join()
                    .map_err(|_| "reuse refusal sender panicked")??;
                let (scope, recovery) = fss_reference::unifi_direct::http_stream::media_av_recovery::detach(supervisor);
                return Ok(SupervisorRun::GeneralStopped { scope, recovery, pins,
                    source_receipts, old_tail_receipts, observations });
            }
            _ => return Err("supervised transition refused".into()),
        }
    }
    sender.ok_or("successor sender missing")?.join().map_err(|_| "successor sender panicked")??;
    if !matches!(boxed_supervisor_step(&mut supervisor, task, cx, clock, admission).await,
        supervisor::Step::BoundaryPending) {
        return Err("supervisor discarded or bypassed the old boundary".into());
    }
    let boundary = supervisor.take_boundary().ok_or("supervised old boundary missing")?;
    if !resumed || eof_count != 2 || pins.len() != if rollover { 6 } else { 4 } || old_tail_receipts.is_empty()
        || (rollover && (rollovers != 1 || !check_prepared || !check_verified))
        || (scenario == 49 && !check_start_refused)
        || boundary.attempts != 1 || boundary.max_attempts != 2 || !boundary.retired.is_empty() {
        return Err("supervised connections or retained boundary incomplete".into());
    }
    Ok(SupervisorRun::Recorded(Box::new(SupervisorFixture { supervisor, boundary, pins, source_receipts,
        old_tail_receipts, observations, effect, rollover })))
}

async fn finish_managed_supervisor<'scope, 'task, 'policy>(
    fixture: Box<SupervisorFixture<'scope, 'task, 'policy>>,
    task: &'scope fss_runtime::execution::TaskCx<'task>, cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
    admission: fss_reference::unifi_direct::source_coordinator::ArchiveAdmission<'_>,
) -> Test {
    use fss_reference::unifi_direct::{archive, http_stream::{media_av_managed as managed, media_av_recovery as recovery}};
    let SupervisorFixture { supervisor, boundary, pins, source_receipts, old_tail_receipts, observations, effect, rollover } = *fixture;
    let (scope, mut parts) = recovery::detach(supervisor);
    fn requires_static<T: 'static>(_: &T) {}
    requires_static(&parts);
    assert!(scope.supervisor_listener.is_some() && scope.phase_listener.is_none());
    let phase = parts.phase.take();
    let mut parts = match recovery::Drain::begin(parts) {
        Err(original) => original,
        Ok(_) => return Err("drain accepted missing phase".into()),
    };
    assert!(parts.phase.is_none());
    parts.phase = phase;
    let manager = match parts.phase.take() {
        Some(recovery::Phase::Recording(manager)) => manager,
        _ => return Err("supervised final recorder missing".into()),
    };
    let mut management = (*manager).into_parts();
    let driver = match management.owner.take() {
        Some(managed::Owner::Recording(driver)) => driver,
        _ => return Err("supervised archive owner missing".into()),
    };
    parts.phase = Some(recovery::Phase::ResumeStopped(driver));
    let mut drain = recovery::Drain::begin(parts).map_err(|_| "stopped archive drain refused")?;
    let report = Box::pin(drain.join_available()).await;
    assert_eq!(report.source, recovery::JoinResult::NoCompletion);
    assert_eq!(report.av, recovery::JoinResult::NoCompletion);
    let (mut parts, drain_receipts) = drain.finish_if_drained().map_err(|_| "stopped archive still has workers")?;
    let driver = match parts.phase.take() {
        Some(recovery::Phase::ResumeStopped(driver)) => driver,
        _ => return Err("drain refusal lost original archive owner".into()),
    };
    parts.phase = Some(recovery::Phase::StartupStopped(Box::new(
        fss_reference::unifi_direct::http_stream::media_av_startup::TransitionRefusal::Seal(*driver),
    )));
    let mut startup_drain = recovery::Drain::begin(parts).map_err(|_| "stopped startup drain refused")?;
    let startup_report = Box::pin(startup_drain.join_available()).await;
    assert_eq!(startup_report.source, recovery::JoinResult::NoCompletion);
    assert_eq!(startup_report.av, recovery::JoinResult::NoCompletion);
    let (mut parts, startup_receipts) = startup_drain.finish_if_drained().map_err(|_| "stopped startup still has workers")?;
    let driver = match parts.phase.take() {
        Some(recovery::Phase::StartupStopped(refusal)) => match *refusal {
            fss_reference::unifi_direct::http_stream::media_av_startup::TransitionRefusal::Seal(driver) => Box::new(driver),
            _ => return Err("startup drain changed refusal".into()),
        },
        _ => return Err("startup drain lost archive owner".into()),
    };
    let recording = (*driver).into_parts().map_err(|_| "supervised workers still running")?;
    let retired = recording.prepare_retirement().map_err(|_| "supervised final tail refused")?;
    Box::pin(exercise_original_tail_readback(retired.tail, task, cx, clock, admission, if rollover { 12 } else { 4 }, None)).await?;
    let assets = retired.assets;
    assert_eq!(assets.permit.prepared().digest(), effect);
    let mut retired_av = assets.av.retire().map_err(|_| "supervised A/V worker running")?;
    if rollover {
        let custody = retired_av.rollover_custody.as_mut().ok_or("rollover custody was lost")?;
        if custody.transition_count() != 1 { return Err("rollover chain changed across reconnect".into()); }
        custody.history(&retired_av.parts.journal, &retired_av.parts.keeper, &retired_av.parts.replay)?;
    } else if retired_av.rollover_custody.is_some() { return Err("unexpected rollover custody".into()); }
    let av_custody = retired_av.rollover_custody;
    let mut av = retired_av.parts;
    for pin in pins {
        let clip = archive::read_unknown_time_av_clip(&mut av.deployment, pin, &ArchiveAccess,
            archive::Limits::default(), &mut fss_geometry::WorkBudget::new(4_000_000_000), &av.replay)?;
        let movie = AvcMp4::parse(clip.bytes(), None, DemuxLimits::default())?;
        if clip.audio().frames == 0 || !movie.tracks().iter().any(|track| track.handler == *b"soun") {
            return Err("supervised clip missing audio".into());
        }
        let annex = movie.annex_b(0, 1)?;
        let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
        let mut pictures = decoder.decode_annex_b(annex.bytes())?;
        pictures.extend(decoder.finish()?);
        if pictures.first().map(|p| (p.width(), p.height())) != Some((160, 128)) {
            return Err("supervised video readback differs".into());
        }
    }
    let _retained = (scope, parts, drain_receipts, startup_receipts, management, boundary, av, av_custody, assets.permit, assets.readback,
        assets.comparison, source_receipts, old_tail_receipts, observations);
    Ok(())
}

#[inline(never)]
fn boxed_managed_supervisor<'scope, 'task: 'scope, 'policy: 'scope>(
    manager: Box<fss_reference::unifi_direct::http_stream::media_av_managed::Managed>,
    listener: listener::Listener<'scope, 'task, 'policy>,
    task: &'scope fss_runtime::execution::TaskCx<'task>, cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>, admission: fss_reference::unifi_direct::source_coordinator::ArchiveAdmission<'scope>,
    policy: fss_reference::unifi_direct::av_owned_sink::BootstrapPolicy, effect: ContentDigest, scenario: u8,
) -> Pin<Box<dyn std::future::Future<Output = Result<SupervisorRun<'scope, 'task, 'policy>, Box<dyn Error>>> + 'scope>> {
    Box::pin(exercise_managed_supervisor(manager, listener, task, cx, clock, admission, policy, effect, scenario))
}

#[inline(never)]
fn boxed_finish_managed_supervisor<'scope, 'task: 'scope, 'policy: 'scope>(
    fixture: Box<SupervisorFixture<'scope, 'task, 'policy>>,
    task: &'scope fss_runtime::execution::TaskCx<'task>, cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>, admission: fss_reference::unifi_direct::source_coordinator::ArchiveAdmission<'scope>,
) -> Pin<Box<dyn std::future::Future<Output = Test> + 'scope>> {
    Box::pin(finish_managed_supervisor(fixture, task, cx, clock, admission))
}

async fn exercise_reuse_bootstrap<'scope, 'task, 'policy>(
    transition: Box<fss_reference::unifi_direct::http_stream::media_av_reconnect::Transition<'scope, 'task, 'policy>>,
    task: &'scope fss_runtime::execution::TaskCx<'task>, cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
    admission: fss_reference::unifi_direct::source_coordinator::ArchiveAdmission<'_>,
    policy: fss_reference::unifi_direct::av_owned_sink::BootstrapPolicy,
    old_pins: Vec<fss_reference::unifi_direct::archive::UnknownTimePin>,
    old_offers: Vec<(fss_reference::unifi_direct::archive::UnknownTimePin, (u64, usize, usize))>,
    old_expected: Vec<(u64, usize, fss_reference::unifi_direct::recording::SourceDisposition)>,
    old_key: SourceKey, next_key: SourceKey, effect: ContentDigest,
    parked: Box<fss_reference::unifi_direct::http_stream::media_av_managed::Parked<'scope, 'task>>,
) -> Result<Box<ReuseFixture<'scope, 'task, 'policy>>, Box<dyn Error>> {
    use fss_reference::unifi_direct::{http_stream::media_av_startup as startup, source_worker};
    let reused = transition.finish_reusing(ContentDigest::sha256(b"preflight retention"), policy, None)
        .map_err(|_| "settled archives could not be reused")?;
    assert_eq!((reused.previous.key, reused.last, reused.attempts, reused.max_attempts), (old_key, Some(next_key), 2, 2));
    assert!(reused.previous.source_plan.is_empty());
    assert!(!reused.previous.sink.has_pending());
    assert!(reused.retired.is_empty());
    let mut bootstrap = Box::new(reused.startup);
    bootstrap = match bootstrap.finish_boxed() {
        Err(refusal) => match *refusal {
            startup::TransitionRefusal::NotReady(driver) => Box::new(driver),
            _ => return Err("wrong boxed bootstrap refusal".into()),
        },
        Ok(_) => return Err("incomplete boxed bootstrap was accepted".into()),
    };
    let mut source_pins = Vec::new();
    let mut observations = Vec::new();
    let mut ready = false;
    for _ in 0..256 {
        match bootstrap.step(task, cx, clock, Duration::from_secs(2), admission).await {
            startup::Step::Retained | startup::Step::Progress | startup::Step::Idle
            | startup::Step::SourceStarted | startup::Step::SourceRunning => (),
            startup::Step::Buffered(audio) | startup::Step::SourceOffered { audio, .. } => observations.push(audio),
            startup::Step::SourceCompleted(done) if done.runtime.is_ok() => match done.outcome {
                source_worker::Outcome::Publication(source_worker::Publication::Published { pin, .. }) => source_pins.push(pin),
                _ => return Err("reused bootstrap source publication refused".into()),
            },
            startup::Step::Ready => { ready = true; break; },
            startup::Step::MediaError(error) => return Err(format!("reused bootstrap media: {error:?}").into()),
            _ => return Err("reused bootstrap stopped".into()),
        }
    }
    if !ready || source_pins.is_empty() { return Err("reused bootstrap incomplete".into()); }
    Ok(Box::new(ReuseFixture {
        bootstrap: Some(bootstrap), recorder: None, listener: reused.listener,
        previous: reused.previous, retired: reused.retired, old_pins, old_offers,
        old_expected, next_key, effect, source_pins, observations, parked: Some(parked),
    }))
}

#[inline(never)]
fn boxed_reuse_bootstrap<'scope, 'task: 'scope, 'policy: 'scope>(
    transition: Box<fss_reference::unifi_direct::http_stream::media_av_reconnect::Transition<'scope, 'task, 'policy>>,
    task: &'scope fss_runtime::execution::TaskCx<'task>, cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>, admission: fss_reference::unifi_direct::source_coordinator::ArchiveAdmission<'scope>,
    policy: fss_reference::unifi_direct::av_owned_sink::BootstrapPolicy,
    old_pins: Vec<fss_reference::unifi_direct::archive::UnknownTimePin>,
    old_offers: Vec<(fss_reference::unifi_direct::archive::UnknownTimePin, (u64, usize, usize))>,
    old_expected: Vec<(u64, usize, fss_reference::unifi_direct::recording::SourceDisposition)>,
    old_key: SourceKey, next_key: SourceKey, effect: ContentDigest,
    parked: Box<fss_reference::unifi_direct::http_stream::media_av_managed::Parked<'scope, 'task>>,
) -> Pin<Box<dyn std::future::Future<Output = Result<Box<ReuseFixture<'scope, 'task, 'policy>>, Box<dyn Error>>> + 'scope>> {
    Box::pin(exercise_reuse_bootstrap(transition, task, cx, clock, admission, policy,
        old_pins, old_offers, old_expected, old_key, next_key, effect, parked))
}

#[inline(never)]
fn finish_reuse_bootstrap<'scope, 'task, 'policy>(
    mut fixture: Box<ReuseFixture<'scope, 'task, 'policy>>,
) -> Result<Box<ReuseFixture<'scope, 'task, 'policy>>, Box<dyn Error>> {
    let bootstrap = fixture.bootstrap.take().ok_or("reuse bootstrap missing")?;
    fixture.recorder = Some(bootstrap.finish_boxed().map_err(|_| "reused archive attach refused")?);
    Ok(fixture)
}

#[inline(never)]
fn reject_live_park<'scope, 'task>(
    manager: Box<fss_reference::unifi_direct::http_stream::media_av_managed::Managed>,
    task: &'scope fss_runtime::execution::TaskCx<'task>, cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
) -> Result<Box<fss_reference::unifi_direct::http_stream::media_av_managed::Managed>, Box<dyn Error>> {
    match manager.park_for_reconnect(task, cx, clock) {
        Err(manager) => Ok(manager),
        Ok(_) => Err("live recording was parked for reconnect".into()),
    }
}

#[inline(never)]
fn boxed_reuse_managed_step<'scope, 'task: 'scope>(
    mut manager: Box<fss_reference::unifi_direct::http_stream::media_av_managed::Managed>,
    task: &'scope fss_runtime::execution::TaskCx<'task>, cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>, admission: fss_reference::unifi_direct::source_coordinator::ArchiveAdmission<'scope>,
) -> Pin<Box<dyn std::future::Future<Output = Result<Box<fss_reference::unifi_direct::http_stream::media_av_managed::Managed>, Box<dyn Error>>> + 'scope>> {
    Box::pin(async move {
        use fss_reference::unifi_direct::http_stream::media_av_managed as managed;
        match Box::pin(manager.step(task, cx, clock, Duration::from_secs(2), admission, admission, &BudgetVector::ZERO, admission)).await {
            managed::Step::Planned(identity) if identity.generation == 7 => Ok(manager),
            _ => Err("successor did not retain generation plan".into()),
        }
    })
}

#[inline(never)]
fn detach_reuse_manager(
    manager: Box<fss_reference::unifi_direct::http_stream::media_av_managed::Managed>,
) -> Result<(Box<fss_reference::unifi_direct::http_stream::media_av_archive::Driver>,
    Box<fss_reference::unifi_direct::http_stream::media_av_managed::Parts>), Box<dyn Error>> {
    use fss_reference::unifi_direct::http_stream::media_av_managed as managed;
    let mut parts = Box::new((*manager).into_parts());
    if parts.plan.remaining() != 0 || parts.audio.remaining_budget() != 65_536
        || parts.creator.is_none() || parts.creator_started {
        return Err("successor changed managed policy or creator custody".into());
    }
    let recorder = match parts.owner.take() {
        Some(managed::Owner::Recording(driver)) => driver,
        _ => return Err("managed successor lost recording owner".into()),
    };
    Ok((recorder, parts))
}

async fn exercise_reuse_archive<'scope, 'task, 'policy>(
    mut fixture: Box<ReuseFixture<'scope, 'task, 'policy>>,
    task: &'scope fss_runtime::execution::TaskCx<'task>, cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
    admission: fss_reference::unifi_direct::source_coordinator::ArchiveAdmission<'_>,
) -> Test {
    use fss_reference::unifi_direct::{archive, av_worker, http_stream::media_av_archive as av_archive, source_worker};
    let recorder = fixture.recorder.take().ok_or("reused recorder missing")?;
    let parked = fixture.parked.take().ok_or("parked manager missing")?;
    let wrong_clock = MeteredClock::new(task, cx, TimestampNs(1))?;
    let (parked, recorder) = match parked.resume(recorder, task, cx, wrong_clock) {
        Err(owners) => owners,
        Ok(_) => return Err("wrong clock resumed managed recorder".into()),
    };
    let manager = parked.resume(recorder, task, cx, clock)
        .map_err(|_| "managed successor refused")?;
    let manager = reject_live_park(manager, task, cx, clock)?;
    let manager = boxed_reuse_managed_step(manager, task, cx, clock, admission).await?;
    let (mut recorder, managed_parts) = detach_reuse_manager(manager)?;
    let mut source_pins = std::mem::take(&mut fixture.source_pins);
    let mut observations = std::mem::take(&mut fixture.observations);
    let mut new_pins = Vec::new();
    let mut ended = false;
    for _ in 0..256 {
        match recorder.step(task, cx, clock, Duration::from_secs(2), admission, admission).await {
            av_archive::Step::Offer(av_archive::Offer::Source { audio, .. })
            | av_archive::Step::Offer(av_archive::Offer::Buffered(audio))
            | av_archive::Step::Offer(av_archive::Offer::Segment(audio)) => observations.push(audio),
            av_archive::Step::SourceStarted | av_archive::Step::SourceRunning
            | av_archive::Step::AvStarted | av_archive::Step::AvRunning | av_archive::Step::Idle
            | av_archive::Step::Media(fss_reference::unifi_direct::pipeline::Step::Progress { .. }) => (),
            av_archive::Step::SourceCompleted(done) if done.runtime.is_ok() => match done.outcome {
                source_worker::Outcome::Publication(source_worker::Publication::Published { pin, .. }) => source_pins.push(pin),
                _ => return Err("reused source publication refused".into()),
            },
            av_archive::Step::AvCompleted(done) if done.runtime.is_ok() => match done.outcome {
                av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(value)) => new_pins.push(value.pin),
                _ => return Err("reused A/V publication refused".into()),
            },
            av_archive::Step::Media(fss_reference::unifi_direct::pipeline::Step::Eof) => { ended = true; break; },
            av_archive::Step::MediaError(error) => return Err(format!("reused A/V media: {error:?}").into()),
            _ => return Err("reused A/V recorder stopped".into()),
        }
    }
    if !ended || new_pins.len() != 2 || fixture.old_pins.len() != 2 { return Err("reused A/V segments incomplete".into()); }
    let parts = (*recorder).into_parts().map_err(|_| "reused archive workers running")?;
    assert_eq!(parts.key, fixture.next_key);
    let retired = parts.prepare_retirement().map_err(|_| "reused successor tail refused")?;
    Box::pin(exercise_original_tail_readback(retired.tail, task, cx, clock, admission, 4,
        Some((std::mem::take(&mut fixture.old_offers), std::mem::take(&mut fixture.old_expected))))).await?;
    let assets = retired.assets;
    assert_eq!(assets.permit.prepared().digest(), fixture.effect);
    let av = assets.av.retire().map_err(|_| "reused A/V worker still running")?;
    if av.fenced { return Err("reused A/V worker fenced".into()); }
    let mut av = av.parts;
    for pin in std::mem::take(&mut fixture.old_pins).into_iter().chain(new_pins) {
        let clip = archive::read_unknown_time_av_clip(&mut av.deployment, pin, &ArchiveAccess,
            archive::Limits::default(), &mut fss_geometry::WorkBudget::new(4_000_000_000), &av.replay)?;
        if clip.audio().frames == 0 || clip.video_samples() == 0 { return Err("reused archive missing A/V".into()); }
        let movie = AvcMp4::parse(clip.bytes(), None, DemuxLimits::default())?;
        if !movie.tracks().iter().any(|track| track.handler == *b"soun") { return Err("reused archive lacks audio track".into()); }
        let annex = movie.annex_b(0, 1)?;
        let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
        let mut pictures = decoder.decode_annex_b(annex.bytes())?;
        pictures.extend(decoder.finish()?);
        if pictures.len() != 1 || (pictures[0].width(), pictures[0].height()) != (160, 128) { return Err("reused archived frame mismatch".into()); }
    }
    let _retained = (fixture, assets.permit, assets.readback, assets.comparison, av, source_pins, observations, managed_parts);
    Ok(())
}

#[inline(never)]
fn boxed_reuse_archive<'scope, 'task: 'scope, 'policy: 'scope>(
    fixture: Box<ReuseFixture<'scope, 'task, 'policy>>,
    task: &'scope fss_runtime::execution::TaskCx<'task>, cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>, admission: fss_reference::unifi_direct::source_coordinator::ArchiveAdmission<'scope>,
) -> Pin<Box<dyn std::future::Future<Output = Test> + 'scope>> {
    Box::pin(exercise_reuse_archive(fixture, task, cx, clock, admission))
}

#[inline(never)]
fn exercise_reuse_refusal(
    transition: Box<fss_reference::unifi_direct::http_stream::media_av_reconnect::Transition<'_, '_, '_>>,
    policy: fss_reference::unifi_direct::av_owned_sink::BootstrapPolicy,
    old_key: SourceKey,
    next_key: SourceKey,
    effect: ContentDigest,
) -> Test {
    use fss_reference::unifi_direct::{http_stream::media_av_reconnect as reconnect, source_worker};
    let refused = match transition.finish_reusing(ContentDigest::sha256(b"wrong retention"), policy, None) {
        Err(refusal) => match *refusal {
            reconnect::ReuseRefusal::SourceUnsettled { bridge, tail, previous } => (bridge, tail, previous),
            _ => return Err("wrong reuse refusal".into()),
        },
        _ => return Err("wrong retention was accepted for reuse".into()),
    };
    let (bridge, tail, previous) = refused;
    assert!(tail.plan.is_empty());
    assert_eq!(tail.worker.status(), source_worker::Status::Idle);
    assert_eq!(previous.key, old_key);
    let bridge = bridge.into_parts();
    assert_eq!(bridge.media.active.as_ref().ok_or("reused source missing")?.source_key(), next_key);
    assert_eq!((bridge.media.attempts, bridge.media.max_attempts, bridge.media.last), (2, 2, Some(next_key)));
    assert_eq!(bridge.effect.permit.prepared().digest(), effect);
    let _retained = (bridge, tail, previous);
    Ok(())
}

async fn exercise_http_av_bootstrap_exhaustion<'scope, 'task>(
    mut driver: fss_reference::unifi_direct::http_stream::media_av_startup::Driver,
    task: &'scope fss_runtime::execution::TaskCx<'task>,
    cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
    admission: fss_reference::unifi_direct::source_coordinator::ArchiveAdmission<'_>,
    resource: &str,
) -> Test {
    use fss_reference::unifi_direct::{http_stream::media_av_startup as startup, ingress, pipeline, source_worker};
    let mut cost = BudgetVector::ZERO;
    cost.network_bytes = task.remaining_budget()?.network_bytes;
    if cost.network_bytes == 0 { return Err("fixture exhausted before bootstrap injection".into()); }
    task.checkpoint_for(RuntimeGrant::AdapterNet, resource, clock.now()?, &cost)?;
    let mut stopped = false;
    for _ in 0..4096 {
        let event = driver.step(task, cx, clock, Duration::from_secs(2), admission).await;
        if matches!(event, startup::Step::MediaError(pipeline::Error::Ingress(ingress::Error::Source(
            fss_runtime::tcp_ingress::IngressError::BudgetExhausted
        )))) {
            if !event.has_retirable_tail() { return Err("bootstrap budget stop not classified".into()); }
            stopped = true;
            break;
        }
        match event {
            startup::Step::Retained | startup::Step::Progress | startup::Step::Idle
            | startup::Step::Buffered(_) | startup::Step::SourceOffered { .. }
            | startup::Step::SourceStarted | startup::Step::SourceRunning => (),
            startup::Step::SourceCompleted(done) if done.runtime.is_ok()
                && matches!(done.outcome, source_worker::Outcome::Publication(source_worker::Publication::Published { .. })) => (),
            _ => return Err("unexpected bootstrap stop before network exhaustion".into()),
        }
    }
    if !stopped || startup::Step::MediaError(pipeline::Error::Cancelled).has_retirable_tail() {
        return Err("bootstrap stop classification incorrect".into());
    }
    driver.abort();
    let _joined = driver.join_source().await;
    let mut parts = driver.into_parts().map_err(|_| "bootstrap source worker still active")?;
    parts.source_armed = true;
    parts = match parts.prepare_tail_retirement() {
        Err(startup::RetirementRefusal::NotDrained(parts)) => parts,
        _ => return Err("armed bootstrap source was allowed to retire".into()),
    };
    parts.source_armed = false;
    let retired = parts.prepare_tail_retirement().map_err(|_| "bootstrap tail retirement refused")?;
    if retired.collector_copies != 1 || retired.tail.plan().items_in_order().filter(|item|
        item.disposition == recording::SourceDisposition::BootstrapCopy).count() != 1 {
        return Err("bootstrap configuration copy missing from source plan".into());
    }
    let collector = retired.assets.collector.into_parts();
    let video = collector.video.ok_or("bootstrap lost original video configuration")?;
    let wire = synthetic_high_flv(10)?;
    let begin = usize::try_from(video.offset())?;
    let end = begin.checked_add(video.bytes().len()).ok_or("configuration offset overflow")?;
    if wire.get(begin..end) != Some(video.bytes()) || collector.first_segment.is_some() {
        return Err("bootstrap collector changed retained configuration".into());
    }
    exercise_original_tail_readback(retired.tail, task, cx, clock, admission, 10, None).await
}

#[inline(never)]
fn build_automatic_rollover_manager(
    driver: fss_reference::unifi_direct::http_stream::media_av_archive::Driver,
    dir: &std::path::Path, mode: u8,
) -> Result<Box<fss_reference::unifi_direct::http_stream::media_av_managed::Managed>, Box<dyn Error>> {
    use fss_core::region::ContextAuthority;
    use fss_reference::{ReplayCx, unifi_direct::{archive, av_rollover_generation,
        http_stream::media_av_managed as managed, recording_session::AudioAllowancePolicy}};
    let auth = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:http-auto-rollover".into(),
        operation_id: OperationId::parse("operation:http-auto-rollover")?,
        principal: "principal:fixture".into(), capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None, priority: 1, budgets: BudgetVector::builder().bytes(128 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"http automatic generation"), generation: 1,
    })?;
    let replay = Arc::new(ReplayCx::from_context_authority(&auth, dir.to_path_buf())?);
    if mode == 2 {
        std::fs::DirBuilder::new().mode(0o700).create(dir.join("fss-av-http-test-0000000000000001"))?;
    }
    let plan = av_rollover_generation::Plan::new(av_rollover_generation::Configuration {
        namespace: "http-test".into(), scope_seed: ContentDigest::sha256(b"http generation scope"),
        first: 1, count: if mode >= 4 { 2 } else { 1 }, journal_replay: replay.clone(), pin_replay: replay,
        journal_io: Arc::new(HostSpoolIo), pin_io: Arc::new(HostSpoolIo),
        journal_limits: EffectJournalLimits::default(), pin_limits: EffectJournalLimits::default(),
        read: Arc::new(ArchiveAccess),
        object_limits: archive::StagedAvLimits { max_objects: 8192, max_object_bytes: 1024 * 1024, max_total_bytes: 8 * 1024 * 1024 },
        work_limit: 4_000_000_000,
    }).map_err(|_| "automatic generation plan refused")?;
    let audio = AudioAllowancePolicy::new(1_000_000, 1024, 65_536).ok_or("audio policy refused")?;
    Ok(Box::new(managed::Managed::new(driver, plan, audio, if mode >= 4 { 1 } else { 2 }).map_err(|_| "automatic manager refused")?))
}

#[inline(never)]
fn boxed_automatic_manager_step<'a, 'scope: 'a, 'task: 'scope>(
    manager: &'a mut fss_reference::unifi_direct::http_stream::media_av_managed::Managed,
    task: &'scope fss_runtime::execution::TaskCx<'task>, cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
    admission: fss_reference::unifi_direct::source_coordinator::ArchiveAdmission<'a>,
) -> Pin<Box<dyn std::future::Future<Output = fss_reference::unifi_direct::http_stream::media_av_managed::Step> + 'a>> {
    Box::pin(manager.step(task, cx, clock, Duration::from_secs(2), admission, admission, &BudgetVector::ZERO, admission))
}

async fn exercise_automatic_http_rollover<'scope, 'task>(
    driver: fss_reference::unifi_direct::http_stream::media_av_archive::Driver,
    task: &'scope fss_runtime::execution::TaskCx<'task>,
    cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
    dir: &std::path::Path,
    admission: fss_reference::unifi_direct::source_coordinator::ArchiveAdmission<'_>,
    mode: u8,
) -> Test {
    use fss_reference::unifi_direct::{av_worker,
        http_stream::{media_av_archive as av_archive, media_av_managed as managed}, source_worker};
    let mut manager = build_automatic_rollover_manager(driver, dir, mode)?;
    let mut pins = Vec::new();
    let mut observed_sources = 0usize;
    let mut created = 0usize;
    let mut rollovers = 0usize;
    let mut renewals = 0usize;
    let mut ended = false;
    let mut creator_failed = false;
    let mut intervention = false;
    let mut cancelled_av = false;
    for _ in 0..512 {
        match boxed_automatic_manager_step(&mut manager, task, cx, clock, admission).await {
            managed::Step::Planned(_) | managed::Step::CreatorStarted | managed::Step::PlanExhausted
            | managed::Step::PreflightPrepared | managed::Step::RolloverStarted | managed::Step::RolloverWaiting
            | managed::Step::PreflightReady | managed::Step::AwaitingSupplies(_) => (),
            managed::Step::CreatorReady => created += 1,
            managed::Step::CreatorFailed if mode == 2 => creator_failed = true,
            managed::Step::InterventionRequired if mode == 2 && creator_failed => { intervention = true; break; },
            managed::Step::Resumed(_) => rollovers += 1,
            managed::Step::Recording(av_archive::AllowanceStep::Renewed { .. }) => renewals += 1,
            managed::Step::Recording(av_archive::AllowanceStep::Recording(event)) => match event {
                av_archive::Step::AvStarted if mode == 3 => { cancelled_av = true; break; },
                av_archive::Step::Offer(av_archive::Offer::Source { .. } | av_archive::Offer::Buffered(_) | av_archive::Offer::Segment(_))
                | av_archive::Step::SourceStarted | av_archive::Step::SourceRunning | av_archive::Step::AvStarted
                | av_archive::Step::AvRunning | av_archive::Step::Idle
                | av_archive::Step::Media(fss_reference::unifi_direct::pipeline::Step::Progress { .. }) => (),
                av_archive::Step::SourceCompleted(done) if done.runtime.is_ok()
                    && matches!(done.outcome, source_worker::Outcome::Publication(source_worker::Publication::Published { .. })) => observed_sources += 1,
                av_archive::Step::AvCompleted(done) if done.runtime.is_ok() => match done.outcome {
                    av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(value)) => pins.push(value.pin),
                    av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Refused {
                        reason: av_worker::FailureReason::JournalCapacity, rollover: Some(_), ..
                    }) => (),
                    _ => return Err("automatic A/V archive refused".into()),
                },
                av_archive::Step::Media(fss_reference::unifi_direct::pipeline::Step::Eof) => { ended = true; break; },
                _ => return Err("automatic archive stopped unexpectedly".into()),
            },
            _ => return Err("automatic provisioning or rollover stopped".into()),
        }
    }
    if mode == 3 {
        if !cancelled_av { return Err("A/V worker did not start".into()); }
        return boxed_automatic_cancel(manager).await;
    }
    if mode == 2 {
        if !intervention || !creator_failed || pins.len() != 2 || rollovers != 0 {
            return Err("creator collision did not stop at the capacity boundary".into());
        }
        return finish_automatic_collision(manager);
    }
    if !ended || pins.len() != 3 || created != 1 || rollovers != 1 || renewals == 0 {
        return Err(format!("automatic results: ended={ended} pins={} created={created} rolls={rollovers} renewals={renewals} sources={observed_sources}", pins.len()).into());
    }
    if mode >= 4 {
        return boxed_automatic_rollover_tail(manager, task, cx, clock, admission, mode).await;
    }
    finish_automatic_archive(manager, pins)
}

#[inline(never)]
fn boxed_automatic_cancel<'a>(
    mut manager: Box<fss_reference::unifi_direct::http_stream::media_av_managed::Managed>,
) -> Pin<Box<dyn std::future::Future<Output = Test> + 'a>> {
    Box::pin(async move {
        manager.abort();
        manager.join_creator().await;
        manager.join_rollover().await;
        let (source, av) = manager.join_recording_workers().await;
        if source.is_some() || av.is_none() { return Err("cancelled A/V completion missing or unexpected source completion".into()); }
        finish_cancelled_automatic(manager)
    })
}

#[inline(never)]
fn finish_cancelled_automatic(
    manager: Box<fss_reference::unifi_direct::http_stream::media_av_managed::Managed>,
) -> Test {
    use fss_reference::unifi_direct::http_stream::media_av_managed as managed;
    let parts = (*manager).into_parts();
    let driver = match parts.owner { Some(managed::Owner::Recording(driver)) => driver, _ => return Err("cancelled recording owner missing".into()) };
    let _owners = (*driver).into_parts().map_err(|_| "cancelled recording worker was not joined")?;
    Ok(())
}

#[inline(never)]
fn finish_automatic_collision(
    manager: Box<fss_reference::unifi_direct::http_stream::media_av_managed::Managed>,
) -> Test {
    use fss_reference::unifi_direct::http_stream::media_av_managed as managed;
    let parts = (*manager).into_parts();
    let failure = parts.failure.ok_or("creator failure custody missing")?;
    if !matches!(failure.completion.outcome, fss_reference::unifi_direct::av_rollover_supplies::Outcome::Refused(fss_reference::unifi_direct::av_rollover_supplies::Stage::Root))
        || failure.identity.is_none() || failure.retirement.root_created {
        return Err("creator collision classification or custody incorrect".into());
    }
    let driver = match parts.owner { Some(managed::Owner::Recording(driver)) => driver, _ => return Err("collision recording owner missing".into()) };
    if driver.rollover_need().is_none() { return Err("collision lost capacity observation".into()); }
    let owners = (*driver).into_parts().map_err(|_| "collision worker still active")?;
    let retired = owners.av.retire().map_err(|_| "collision A/V worker still active")?;
    if !retired.parts.sink.has_pending() { return Err("collision lost pending segment".into()); }
    Ok(())
}

#[inline(never)]
fn finish_automatic_archive(
    manager: Box<fss_reference::unifi_direct::http_stream::media_av_managed::Managed>,
    pins: Vec<fss_reference::unifi_direct::archive::UnknownTimePin>,
) -> Test {
    use fss_reference::unifi_direct::{archive, http_stream::media_av_managed as managed};
    let parts = (*manager).into_parts();
    if parts.creator.is_some() || parts.ready.is_some() || parts.failure.is_some() || parts.custody.len() != 1 || parts.plan.remaining() != 0 {
        return Err("automatic owner did not retain its exact generation custody".into());
    }
    let driver = match parts.owner { Some(managed::Owner::Recording(driver)) => driver, _ => return Err("automatic recording owner missing".into()) };
    let owners = (*driver).into_parts().map_err(|_| "automatic archive worker still active")?;
    let retired = owners.av.retire().map_err(|_| "automatic A/V worker still active")?;
    let mut storage = retired.parts;
    for pin in pins {
        let clip = archive::read_unknown_time_av_clip(&mut storage.deployment, pin, &ArchiveAccess,
            archive::Limits::default(), &mut fss_geometry::WorkBudget::new(4_000_000_000), &storage.replay)?;
        if clip.audio().frames == 0 || clip.video_samples() == 0 { return Err("automatic segment missing A/V".into()); }
        let movie = AvcMp4::parse(clip.bytes(), None, DemuxLimits::default())?;
        let annex = movie.annex_b(0, 1)?;
        let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
        let mut pictures = decoder.decode_annex_b(annex.bytes())?;
        pictures.extend(decoder.finish()?);
        if pictures.first().map(|p| (p.width(), p.height())) != Some((2688, 1512)) {
            return Err("automatic A/V resolution mismatch".into());
        }
    }
    Ok(())
}


async fn exercise_automatic_rollover_tail<'scope, 'task>(
    mut manager: Box<fss_reference::unifi_direct::http_stream::media_av_managed::Managed>,
    task: &'scope fss_runtime::execution::TaskCx<'task>, cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
    admission: fss_reference::unifi_direct::source_coordinator::ArchiveAdmission<'_>, mode: u8,
) -> Test {
    use fss_reference::unifi_direct::{archive, http_stream::{media_av_archive as av_archive, media_av_managed as managed}, source_worker};
        let custody = manager.take_custody().ok_or("completed generation custody missing")?;
        for _ in 0..2 {
            if !matches!(
                boxed_automatic_manager_step(&mut manager, task, cx, clock, admission).await,
                managed::Step::Recording(av_archive::AllowanceStep::Recording(av_archive::Step::Halted))
            ) {
                return Err("halted source admitted further provisioning".into());
            }
        }
        let parts = (*manager).into_parts();
        if parts.plan.remaining() != 1 || parts.creator.is_some() || parts.ready.is_some() || parts.failure.is_some() || !parts.custody.is_empty() {
            return Err("halted source changed generation ownership".into());
        }
        let driver = match parts.owner { Some(managed::Owner::Recording(driver)) => driver, _ => return Err("halted recording owner missing".into()) };
        let mut owners = (*driver).into_parts().map_err(|_| "halted archive worker still active")?;
        owners.source_armed = true;
        owners = match owners.prepare_retirement() {
            Err(av_archive::RetirementRefusal::NotDrained(owners)) => owners,
            _ => return Err("armed source was allowed to retire".into()),
        };
        owners.source_armed = false;
        let original_claim = owners.camera_claim;
        let original_key = owners.key;
        owners.camera_claim = ContentDigest::sha256(b"wrong camera claim");
        owners = match owners.prepare_retirement() {
            Err(av_archive::RetirementRefusal::NotDrained(owners)) => owners,
            _ => return Err("mismatched camera claim was allowed to retire".into()),
        };
        owners.camera_claim = original_claim;
        let retired = owners.prepare_retirement().map_err(|_| "HTTP A/V tail retirement refused")?;
        if retired.assets.camera_claim != original_claim || retired.assets.first_segment.is_some()
            || retired.assets.av_state != av_archive::ArchiveState::Idle {
            return Err("HTTP A/V retirement lost its retained owners".into());
        }
        let mut tail = retired.tail;
        if mode >= 5 && !tail.enable_batching(256, 1024 * 1024) { return Err("batch admission refused".into()); }
        let start = tail.plan().start.ok_or("HTTP A/V tail start missing")?;
        let end = tail.plan().end.ok_or("HTTP A/V tail end missing")?;
        if tail.plan().received != end || tail.plan().is_empty() {
            return Err("HTTP A/V tail range incomplete".into());
        }
        let wire = synthetic_high_flv(10)?;
        let mut pending = None;
        let mut published = Vec::new();
        let mut finished = false;
        let mut force_refusal = false;
        let mut awaiting_retry = false;
        let mut retried = false;
        let mut bad_cost = BudgetVector::ZERO;
        bad_cost.bytes = u64::MAX;
        let bad_admission = fss_reference::unifi_direct::source_coordinator::ArchiveAdmission { resource: admission.resource, cost: &bad_cost };
        for _ in 0..2048 {
            let attempt = if force_refusal { bad_admission } else { admission };
            match Box::pin(tail.step(task, cx, clock, attempt)).await {
                fss_reference::unifi_direct::retirement_source::DriverStep::Offered { offset, len, disposition } => {
                    if pending.replace((offset, len, Some(disposition), 1usize)).is_some() { return Err("overlapping tail offers".into()); }
                }
                fss_reference::unifi_direct::retirement_source::DriverStep::BatchOffered { offset, len, records } if mode >= 5 => {
                    if pending.replace((offset, len, None, records)).is_some() { return Err("overlapping tail batches".into()); }
                    if mode == 6 && !retried { force_refusal = true; }
                    if mode == 7 {
                        tail.abort();
                        let parts = tail.into_parts().map_err(|_| "cancelled tail still running")?;
                        let worker = parts.worker.retire().map_err(|_| "cancelled worker still running")?;
                        let Some(source_worker::Input::Batch { batch, .. }) = worker.pending else {
                            return Err("cancelled batch lost source custody".into());
                        };
                        let mut next = start;
                        for item in batch.items_in_order().chain(parts.plan.items_in_order()) {
                            let begin = usize::try_from(item.record.offset())?;
                            let stop = begin.checked_add(item.record.bytes().len()).ok_or("batch range overflow")?;
                            if item.record.offset() != next || wire.get(begin..stop) != Some(item.record.bytes()) {
                                return Err("cancelled batch changed original bytes".into());
                            }
                            next = u64::try_from(stop)?;
                        }
                        if next != end || worker.fenced { return Err("cancelled batch lost its suffix".into()); }
                        return Ok(());
                    }
                }
                fss_reference::unifi_direct::retirement_source::DriverStep::StartRefused(_) if force_refusal => {
                    force_refusal = false;
                    awaiting_retry = true;
                }
                fss_reference::unifi_direct::retirement_source::DriverStep::RetryRequired if awaiting_retry => {
                    if !tail.authorize_retry() || tail.authorize_retry() { return Err("batch retry authorization failed".into()); }
                    awaiting_retry = false;
                    retried = true;
                }
                fss_reference::unifi_direct::retirement_source::DriverStep::Started if mode == 8 => {
                    tail.abort();
                    let done = tail.join().await.ok_or("cancelled batch completion missing")?;
                    let published_pin = match (&done.runtime, &done.outcome) {
                        (Ok(()), source_worker::Outcome::Publication(source_worker::Publication::Published { pin, .. })) => Some(*pin),
                        _ => None,
                    };
                    let parts = tail.into_parts().map_err(|_| "cancelled batch did not drain")?;
                    let worker = parts.worker.retire().map_err(|_| "cancelled worker did not drain")?;
                    let mut storage = worker.parts;
                    let mut next = start;
                    match worker.pending {
                        Some(source_worker::Input::Batch { batch, .. }) => {
                            for item in batch.items_in_order() {
                                let begin = usize::try_from(item.record.offset())?;
                                let stop = begin.checked_add(item.record.bytes().len()).ok_or("batch range overflow")?;
                                if item.record.offset() != next || wire.get(begin..stop) != Some(item.record.bytes()) {
                                    return Err("cancelled attempt lost original bytes".into());
                                }
                                next = u64::try_from(stop)?;
                            }
                        }
                        None => {
                            let pin = published_pin.ok_or("cancelled attempt lost its batch and receipt")?;
                            let batch = archive::read_unknown_time_source_batch(&mut storage.deployment, pin, &ArchiveAccess,
                                archive::Limits::default(), &mut fss_geometry::WorkBudget::new(4_000_000_000), &storage.replay)?;
                            let begin = usize::try_from(start)?;
                            let stop = begin.checked_add(batch.payload.len()).ok_or("batch range overflow")?;
                            if batch.records.first().map(|r| r.offset) != Some(start) || wire.get(begin..stop) != Some(batch.payload.as_slice()) {
                                return Err("published batch differs after cancellation".into());
                            }
                            next = u64::try_from(stop)?;
                        }
                        Some(_) => return Err("cancelled attempt retained wrong source type".into()),
                    }
                    for item in parts.plan.items_in_order() {
                        let begin = usize::try_from(item.record.offset())?;
                        let stop = begin.checked_add(item.record.bytes().len()).ok_or("tail range overflow")?;
                        if item.record.offset() != next || wire.get(begin..stop) != Some(item.record.bytes()) {
                            return Err("cancelled attempt lost remaining tail".into());
                        }
                        next = u64::try_from(stop)?;
                    }
                    if next != end { return Err("cancelled attempt did not account for its suffix".into()); }
                    return Ok(());
                }
                fss_reference::unifi_direct::retirement_source::DriverStep::Started => (),
                fss_reference::unifi_direct::retirement_source::DriverStep::Completed(done) if done.runtime.is_ok() => {
                    let pin = match done.outcome {
                        source_worker::Outcome::Publication(source_worker::Publication::Published { pin, .. }) => pin,
                        _ => return Err("tail source publication refused".into()),
                    };
                    let item = pending.take().ok_or("tail completion without offer")?;
                    published.push((pin, item));
                }
                fss_reference::unifi_direct::retirement_source::DriverStep::Finished if pending.is_none() => { finished = true; break; }
                _ => return Err("tail archival stopped unexpectedly".into()),
            }
        }
        if !finished || published.is_empty() { return Err("tail archival did not finish".into()); }
        let tail = tail.into_parts().map_err(|_| "tail worker still running")?;
        if !tail.plan.is_empty() || tail.key != original_key || tail.camera_claim != original_claim {
            return Err("tail archival lost its source binding".into());
        }
        let source = tail.worker.retire().map_err(|_| "tail source did not retire")?;
        if source.fenced || source.pending.is_some() { return Err("tail source remains unresolved".into()); }
        let mut source = source.parts;
        let mut next = start;
        let mut original_count = 0usize;
        for (pin, (offset, len, disposition, records)) in published {
            let begin = usize::try_from(offset)?;
            let stop = begin.checked_add(len).ok_or("tail readback overflow")?;
            if offset != next { return Err("tail source offset differs".into()); }
            if let Some(disposition) = disposition {
                let record = archive::read_unknown_time_source(&mut source.deployment, pin, &ArchiveAccess,
                    archive::Limits::default(), &mut fss_geometry::WorkBudget::new(4_000_000_000), &source.replay)?;
                if record.offset() != offset || record.disposition() != disposition || wire.get(begin..stop) != Some(record.bytes()) {
                    return Err("tail source readback differs from original wire".into());
                }
            } else {
                let batch = archive::read_unknown_time_source_batch(&mut source.deployment, pin, &ArchiveAccess,
                    archive::Limits::default(), &mut fss_geometry::WorkBudget::new(4_000_000_000), &source.replay)?;
                if batch.records.len() != records || batch.records.first().map(|r| r.offset) != Some(offset)
                    || wire.get(begin..stop) != Some(batch.payload.as_slice()) {
                    return Err("tail batch readback differs from original wire".into());
                }
            }
            original_count += records;
            next = offset.checked_add(u64::try_from(len)?).ok_or("tail offset overflow")?;
        }
        if mode >= 5 && original_count < 2 { return Err("fixture did not exercise batching".into()); }
        if mode == 6 && !retried { return Err("fixture did not exercise batch refusal".into()); }
        if next != end { return Err("tail source readback has a gap".into()); }
        let _assets = retired.assets;
        let _custody = custody;
        return Ok(());
}

#[inline(never)]
fn boxed_automatic_rollover_tail<'scope, 'task: 'scope>(
    manager: Box<fss_reference::unifi_direct::http_stream::media_av_managed::Managed>,
    task: &'scope fss_runtime::execution::TaskCx<'task>, cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
    admission: fss_reference::unifi_direct::source_coordinator::ArchiveAdmission<'scope>, mode: u8,
) -> Pin<Box<dyn std::future::Future<Output = Test> + 'scope>> {
    Box::pin(exercise_automatic_rollover_tail(manager, task, cx, clock, admission, mode))
}

#[inline(never)]
fn boxed_automatic_rollover_test<'scope, 'task: 'scope>(
    driver: fss_reference::unifi_direct::http_stream::media_av_archive::Driver,
    task: &'scope fss_runtime::execution::TaskCx<'task>, cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>, dir: &'scope std::path::Path,
    admission: fss_reference::unifi_direct::source_coordinator::ArchiveAdmission<'scope>, mode: u8,
) -> Pin<Box<dyn std::future::Future<Output = Test> + 'scope>> {
    Box::pin(exercise_automatic_http_rollover(driver, task, cx, clock, dir, admission, mode))
}

#[inline(never)]
fn boxed_manual_av_rollover<'scope, 'task: 'scope>(
    driver: fss_reference::unifi_direct::http_stream::media_av_archive::Driver,
    task: &'scope fss_runtime::execution::TaskCx<'task>, cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>, dir: &'scope std::path::Path, deny: bool,
) -> Pin<Box<dyn std::future::Future<Output = Result<Box<fss_reference::unifi_direct::http_stream::media_av_archive::RolloverResult>, Box<dyn Error>>> + 'scope>> {
    Box::pin(async move {
        use fss_reference::unifi_direct::{archive, http_stream::media_av_archive as av_archive};
        let limits = EffectJournalLimits::default();
        let store = |name: &str| -> Result<Box<dyn EffectJournalStore>, Box<dyn Error>> {
            Ok(Box::new(FileEffectJournal::create(dir.join(name), limits, Arc::new(HostSpoolIo))?))
        };
        let root = FileTrustedRootPinRetainer::create(dir.join("http-switch-root"), limits, Arc::new(HostSpoolIo), ContentDigest::sha256(b"http switch custody"))?;
        let supplies = fss_reference::unifi_direct::av_rollover_worker::Supplies {
            next_journal: store("http-next-journal")?, next_keeper: store("http-next-keeper")?,
            switch: PinRetainedEffectJournal::new(store("http-switch")?, Box::new(root))?,
            read: if deny { Arc::new(DeniedArchiveAccess) } else { Arc::new(ArchiveAccess) },
            object_limits: archive::StagedAvLimits { max_objects: 8192, max_object_bytes: 1024 * 1024, max_total_bytes: 8 * 1024 * 1024 },
            work_limit: 4_000_000_000,
        };
        let preflight = av_archive::RolloverPreflight::prepare(driver, supplies).map_err(|_| "rollover preparation refused")?;
        let (driver, supplies) = preflight.into_unstarted().map_err(|_| "unstarted preflight lost owners")?;
        let mut preflight = Box::new(av_archive::RolloverPreflight::prepare(driver, supplies).map_err(|_| "rollover preparation after restore refused")?);
        preflight.start(task, cx, clock, "fixture:archive", &BudgetVector::ZERO).map_err(|e| format!("rollover preflight start: {e:?}"))?;
        if !preflight.join().await { return Err("rollover preflight did not drain".into()); }
        let rollover = match *preflight.finish_boxed().map_err(|_| "rollover preflight finish refused")? {
            av_archive::RolloverPreflightResult::Ready(rollover) => rollover,
            _ => return Err("rollover preflight unresolved".into()),
        };
        let (driver, supplies) = match rollover.into_unstarted().map_err(|_| "unstarted rollover lost owners")? {
            av_archive::RolloverUnstarted::Restored { driver, supplies } => (driver, supplies),
            _ => return Err("unstarted rollover restore refused".into()),
        };
        let mut preflight = Box::new(av_archive::RolloverPreflight::prepare(driver, supplies).map_err(|_| "rollover preparation after switch restore refused")?);
        preflight.start(task, cx, clock, "fixture:archive", &BudgetVector::ZERO).map_err(|e| format!("restored rollover preflight start: {e:?}"))?;
        if !preflight.join().await { return Err("restored rollover preflight did not drain".into()); }
        let mut rollover = match *preflight.finish_boxed().map_err(|_| "restored rollover preflight finish refused")? {
            av_archive::RolloverPreflightResult::Ready(rollover) => Box::new(rollover),
            _ => return Err("restored rollover preflight unresolved".into()),
        };
        rollover.start(task, cx, clock, "fixture:archive", &BudgetVector::ZERO).map_err(|e| format!("rollover start: {e:?}"))?;
        if !rollover.join().await { return Err("rollover did not drain".into()); }
        rollover.finish_boxed().map_err(|_| "rollover finish refused".into())
    })
}

fn exercise(
    partial: bool,
    bad_response: bool,
    owned: bool,
    match_request: bool,
    native_media: bool,
    archive_media: bool,
    combined_start: bool,
    audio_mode: u8,
) -> Test {
    exercise_rollover(partial, bad_response, owned, match_request, native_media, archive_media, combined_start, audio_mode, false, 0)
}

fn exercise_rollover(
    partial: bool,
    bad_response: bool,
    owned: bool,
    match_request: bool,
    native_media: bool,
    archive_media: bool,
    combined_start: bool,
    audio_mode: u8,
    rollover_deny: bool,
    automatic_rollover: u8,
) -> Test {
    let private_media = if audio_mode == 9 || audio_mode == 11 {
        let mut bytes = Vec::new();
        let limit = if audio_mode == 11 { 8 * 1024 * 1024 } else { 1024 * 1024 };
        std::io::stdin().lock().take(limit + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > limit || !bytes.starts_with(b"FLV\x01") {
            return Err("invalid bounded camera-derived input".into());
        }
        Some(bytes)
    } else {
        None
    };
    let dir = std::env::temp_dir().join(format!(
        "fss-http-serializer-{}-{}-{}-{}-{}-{}-{}-{}-{}-{}-{}",
        std::process::id(),
        partial,
        bad_response,
        owned,
        match_request,
        native_media,
        archive_media,
        combined_start,
        audio_mode,
        rollover_deny,
        automatic_rollover
    ));
    std::fs::create_dir(&dir)?;
    let journal = FileEffectJournal::create(
        dir.join("journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut effects = EffectCoordinator::with_journal(Box::new(journal))?;
    let mut budget = BudgetVector::ZERO;
    budget.bytes = 64 * 1024 * 1024;
    budget.network_bytes = if audio_mode == 11 { 16 * 1024 * 1024 } else { 1_000_000 };
    budget.storage_operations = 64;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:serializer-test".into(),
            operation_id: OperationId::parse("operation:serializer-owner")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::AdapterAuth.as_str().into(),
                RuntimeGrant::ObserveStatus.as_str().into(),
                RuntimeGrant::ReadMedia.as_str().into(),
                RuntimeGrant::CameraSettingPrepare.as_str().into(),
                RuntimeGrant::CameraSettingCommit.as_str().into(),
                RuntimeGrant::ObjectStage.as_str().into(),
                RuntimeGrant::ObjectPublish.as_str().into(),
            ],
            deadline: Some(TimestampNs(600_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"fixture"),
            generation: 1,
        },
        RegionId::new("region:serializer-test")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let peer = Ipv4Addr::new(192, 168, 42, 10);
    let mut session = Session::new(peer, 1)?;
    let r = session.prepare_login(br#"{"username":"fixture","password":"synthetic"}"#)?;
    session.finish_write(r, WriteOutcome::Written)?;
    session.accept_login(
        Response::new(200, "OK", Vec::new()).with_header("Set-Cookie", "authId=synthetic"),
    )?;
    let r = session.prepare_status()?;
    session.finish_write(r, WriteOutcome::Written)?;
    session.accept_status(Response::new(200, "OK", b"{}".to_vec()))?;
    let r = session.prepare_serializer_settings()?;
    session.finish_write(r, WriteOutcome::Written)?;
    let (_, baseline) = session.accept_settings_with_serializers(Response::new(200, "OK", br#"{"av":{"video":{"video1":{"avSerializer":null},"video2":{"avSerializer":{"destinations":["tcp://fixture:1"]}}}}}"#.to_vec()))?;
    let mut other_session = Session::new(peer, 1)?;
    let r = other_session.prepare_login(br#"{"username":"fixture","password":"synthetic"}"#)?;
    other_session.finish_write(r, WriteOutcome::Written)?;
    other_session.accept_login(
        Response::new(200, "OK", Vec::new()).with_header("Set-Cookie", "authId=synthetic"),
    )?;
    let r = other_session.prepare_status()?;
    other_session.finish_write(r, WriteOutcome::Written)?;
    other_session.accept_status(Response::new(200, "OK", b"{}".to_vec()))?;
    let r = other_session.prepare_serializer_settings()?;
    other_session.finish_write(r, WriteOutcome::Written)?;
    let (_, changed) = other_session.accept_settings_with_serializers(Response::new(200, "OK", br#"{"av":{"video":{"video1":{"avSerializer":null},"video2":{"avSerializer":{"destinations":["tcp://fixture:2"]}}}}}"#.to_vec()))?;
    let camera = ContentDigest::sha256(b"fixture camera");
    let resource = format!("camera:{}", camera.to_text());
    let mut leases = LeaseRegistry::new();
    let fence = leases
        .acquire(&resource, authority.region().as_str(), None, TimestampNs(2))?
        .fence;
    let listener = if native_media {
        let probe = std::net::TcpListener::bind("127.0.0.1:0")?;
        let std::net::SocketAddr::V4(value) = probe.local_addr()? else {
            return Err("IPv4 fixture required".into());
        };
        drop(probe);
        value
    } else {
        SocketAddrV4::new(Ipv4Addr::new(192, 168, 42, 11), 17777)
    };
    let conditions = Preconditions {
        camera,
        peer_admission: ContentDigest::sha256(b"peer"),
        session_generation: 1,
        lease_fence: fence,
        serializers: baseline.binding(|_, _| true)?,
        listener,
    };
    let start = StreamStart::new(
        VideoChannel::Video1,
        listener,
        VideoCodec::H264,
        AudioCodec::Aac,
        "0123456789abcdef",
    )?;
    let plan = Plan::new(peer, &start, conditions, &baseline, Framing::ContentLength)?;
    let op = OperationId::parse("operation:serializer-dispatch")?;
    let prepared = effects.prepare(
        &authority,
        &mut tree,
        &mut leases,
        PrepareSpec {
            operation: &op,
            idempotency_key: IdempotencyKey::parse(op.as_str())?,
            request_digest: plan.request_digest(),
            precondition_digest: plan.precondition_digest(),
            resource: &resource,
            fence,
            prepare_grant: RuntimeGrant::CameraSettingPrepare,
            commit_grant: RuntimeGrant::CameraSettingCommit,
            terminal_predicate: "independent readback or reconciliation",
        },
        TimestampNs(3),
    )?;
    let forward_preparation = prepared.digest();
    let approval = CommitApproval {
        prepared_digest: forward_preparation,
        current_precondition_digest: plan.precondition_digest(),
    };
    let permit = effects.commit(
        &authority,
        &tree,
        &mut leases,
        prepared,
        TimestampNs(4),
        approval,
    )?;
    // A synthetic expected readback supplies the exact intended reverse effect
    // before this fixture runs. The owner must still independently revalidate
    // the actual response before dispatching the separate restoration permit.
    let restore_op = OperationId::parse("operation:serializer-restore")?;
    let restore_parts = if owned && match_request && !native_media {
        let r = other_session.prepare_serializer_settings()?;
        other_session.finish_write(r, WriteOutcome::Written)?;
        let (_, anticipated) = other_session.accept_settings_with_serializers(Response::new(200, "OK", br#"{"av":{"video":{"video1":{"avSerializer":{"type":"extendedFlv","parameters":{"streamName":"0123456789abcdef","withOpus":false},"destinations":["tcp://192.168.42.11:17777?retryInterval=1&connectTimeout=5"]}},"video2":{"avSerializer":{"destinations":["tcp://fixture:1"]}}}}}"#.to_vec()))?;
        let restore_conditions = Preconditions {
            serializers: anticipated.binding(|_, _| true)?,
            ..conditions
        };
        let restore_plan = plan.prepare_restore(
            &baseline,
            &anticipated,
            restore_conditions,
            Framing::ContentLength,
            |_, _| true,
        )?;
        let prepared = effects.prepare(
            &authority,
            &mut tree,
            &mut leases,
            PrepareSpec {
                operation: &restore_op,
                idempotency_key: IdempotencyKey::parse(restore_op.as_str())?,
                request_digest: restore_plan.request_digest(),
                precondition_digest: restore_plan.precondition_digest(),
                resource: &resource,
                fence,
                prepare_grant: RuntimeGrant::CameraSettingPrepare,
                commit_grant: RuntimeGrant::CameraSettingCommit,
                terminal_predicate: "independent restore observation or reconciliation",
            },
            TimestampNs(5),
        )?;
        let approval = CommitApproval {
            prepared_digest: prepared.digest(),
            current_precondition_digest: restore_plan.precondition_digest(),
        };
        let permit = effects.commit(
            &authority,
            &tree,
            &mut leases,
            prepared,
            TimestampNs(6),
            approval,
        )?;
        Some((restore_plan, restore_conditions, permit))
    } else {
        None
    };
    let runtime = if archive_media || combined_start || audio_mode != 0 {
        RuntimeBuilder::current_thread()
            .blocking_threads(1, 1)
            .build()?
    } else {
        RuntimeBuilder::current_thread().build()?
    };
    let checkpoint_scope =
        checkpoint::Scope::from_plan(&plan, ContentDigest::sha256(b"fixture certificate"))?;
    let key = checkpoint::Key::new([7; 32])?;
    let sealed = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        Ok::<_, Box<dyn Error>>(checkpoint::Sealed::capture(
            &cx,
            &CheckpointPolicy(true),
            checkpoint_scope,
            &key,
            &plan,
            &baseline,
        )?)
    })?;
    let mut checkpoint_spool = StagingSpool::open(
        dir.join("checkpoint-spool"),
        SpoolLimits::new(4, 1_000_000, 100_000, 8),
    )?;
    let key_dir = dir.join("keys");
    std::fs::DirBuilder::new().mode(0o700).create(&key_dir)?;
    let lease = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        Ok::<_, Box<dyn Error>>(checkpoint::keyfile::KeyLease::create(
            &cx,
            &CheckpointPolicy(true),
            checkpoint_scope,
            &key_dir.join("key"),
        )?)
    })?;
    let wrong_lease = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        Ok::<_, Box<dyn Error>>(checkpoint::keyfile::KeyLease::create(
            &cx,
            &CheckpointPolicy(true),
            checkpoint_scope,
            &key_dir.join("wrong-key"),
        )?)
    })?;
    let stored = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        assert!(
            checkpoint::Stored::capture_with_keyfile(
                &cx,
                &DenyCheckpoint(checkpoint::Action::Stage),
                checkpoint_scope,
                &lease,
                &plan,
                &baseline,
                &mut checkpoint_spool
            )
            .is_err()
        );
        Ok::<_, Box<dyn Error>>(checkpoint::Stored::capture_with_keyfile(
            &cx,
            &CheckpointPolicy(true),
            checkpoint_scope,
            &lease,
            &plan,
            &baseline,
            &mut checkpoint_spool,
        )?)
    })?;
    let other_conditions = Preconditions {
        peer_admission: ContentDigest::sha256(b"other peer admission"),
        ..conditions
    };
    let other_plan = Plan::new(
        peer,
        &start,
        other_conditions,
        &baseline,
        Framing::ContentLength,
    )?;
    let other_scope =
        checkpoint::Scope::from_plan(&other_plan, ContentDigest::sha256(b"fixture certificate"))?;
    let other_lease = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        Ok::<_, Box<dyn Error>>(checkpoint::keyfile::KeyLease::create(
            &cx,
            &CheckpointPolicy(true),
            other_scope,
            &key_dir.join("other-key"),
        )?)
    })?;
    let other_stored = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        Ok::<_, Box<dyn Error>>(checkpoint::Stored::capture_with_keyfile(
            &cx,
            &CheckpointPolicy(true),
            other_scope,
            &other_lease,
            &other_plan,
            &baseline,
            &mut checkpoint_spool,
        )?)
    })?;
    drop(checkpoint_spool);
    let mut reopened_spool = StagingSpool::open(
        dir.join("checkpoint-spool"),
        SpoolLimits::new(4, 1_000_000, 100_000, 8),
    )?;
    let stored_bytes = reopened_spool.read_bounded(stored.digest(), 100_000)?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        lease.with_key(&cx, &CheckpointPolicy(true), |key| {
            checkpoint::Sealed::from_bytes(&stored_bytes)?.open(
                &cx,
                &CheckpointPolicy(true),
                stored.scope(),
                key,
            )
        })??;
        Ok::<(), Box<dyn Error>>(())
    })?;
    let mut anchor_journal = metadata_journal(&dir, "checkpoint-anchor")?;
    let mut other_journal = metadata_journal(&dir, "other-anchor")?;
    let anchored = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        assert!(
            stored
                .anchor_with_keyfile(
                    &cx,
                    &DenyCheckpoint(checkpoint::Action::Anchor),
                    &lease,
                    &mut reopened_spool,
                    &mut anchor_journal
                )
                .is_err()
        );
        assert!(anchor_journal.head().is_none());
        assert!(
            stored
                .anchor_with_keyfile(
                    &cx,
                    &CheckpointPolicy(true),
                    &wrong_lease,
                    &mut reopened_spool,
                    &mut anchor_journal
                )
                .is_err()
        );
        assert!(anchor_journal.head().is_none());
        Ok::<_, Box<dyn Error>>(stored.anchor_with_keyfile(
            &cx,
            &CheckpointPolicy(true),
            &lease,
            &mut reopened_spool,
            &mut anchor_journal,
        )?)
    })?;
    let other_anchored = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        Ok::<_, Box<dyn Error>>(other_stored.anchor_with_keyfile(
            &cx,
            &CheckpointPolicy(true),
            &other_lease,
            &mut reopened_spool,
            &mut other_journal,
        )?)
    })?;
    assert_eq!(anchored.digest(), stored.digest());
    let anchor_pin = anchored.pin();
    drop(anchor_journal);
    let limits = EffectJournalLimits::default();
    let mut root = FileTrustedRootPinRetainer::open_trusting_storage(
        dir.join("checkpoint-anchor-root"),
        limits,
        Arc::new(HostSpoolIo),
        ContentDigest::sha256(b"checkpoint-anchor"),
    )?;
    assert_eq!(root.retained_pin()?, Some(anchor_pin));
    let file = FileEffectJournal::open(
        dir.join("checkpoint-anchor-journal"),
        limits,
        Arc::new(HostSpoolIo),
        anchor_pin,
    )?;
    let mut reopened_anchor =
        PinRetainedEffectJournal::for_reconciliation(Box::new(file), Box::new(root))?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let recovered = checkpoint::recover_record(
            &cx,
            &CheckpointPolicy(true),
            &mut reopened_anchor,
            anchor_pin,
        )?;
        assert_eq!(recovered.scope(), checkpoint_scope);
        assert_eq!(recovered.digest(), stored.digest());
        assert!(
            checkpoint::recover_record(
                &cx,
                &DenyCheckpoint(checkpoint::Action::Anchor),
                &mut reopened_anchor,
                anchor_pin
            )
            .is_err()
        );
        let wrong = fss_runtime::effect_journal::EffectJournalPin {
            sequence: anchor_pin.sequence,
            root: ContentDigest::sha256(b"wrong metadata pin"),
        };
        assert!(
            checkpoint::recover_record(&cx, &CheckpointPolicy(true), &mut reopened_anchor, wrong)
                .is_err()
        );
        Ok::<(), Box<dyn Error>>(())
    })?;
    let stored = anchored;
    let other_stored = other_anchored;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:serializer-test")?,
                started_at: TimestampNs(7),
            },
            &cx,
            async |task, cx| {
                let output: Test = Box::pin(async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(8))?;
                    if owned {
                        let media_policy = MediaPolicy(listener);
                        let mut native_listener = if native_media {
                            Some(
                                listener::Listener::bind(
                                    task,
                                    cx,
                                    clock,
                                    &media_policy,
                                    listener,
                                    &resource,
                                    Duration::from_secs(5),
                                )
                                .await?,
                            )
                        } else {
                            None
                        };
                        let http_listener = TcpListener::bind("127.0.0.1:0").await?;
                        let address = http_listener.local_addr()?;
                        let fixture = std::thread::spawn(move || {
                            fixture_server(address, match_request, native_media.then_some(listener),
                                if automatic_rollover == 55 { u8::MAX } else if matches!(automatic_rollover, 48 | 49 | 52) { 12 } else { audio_mode }, private_media)
                        });
                        let (socket, _) =
                            timeout(cx.now(), Duration::from_secs(5), http_listener.accept())
                                .await??;
                        let io = MeteredIo::with_clock(socket, clock, &resource, 4096)?;
                        let policy = OwnerPolicy(Cell::new(false));
                        let mut owner = camera_http::Owner::new(
                            io, task, cx, clock, &policy, peer, 1, &resource,
                        )?;
                        owner
                            .login(
                                br#"{"username":"fixture","password":"synthetic"}"#,
                                Duration::from_secs(5),
                            )
                            .await?;
                        owner.status(Duration::from_secs(5)).await?;
                        let (_, observed) =
                            owner.settings_serializers(Duration::from_secs(5)).await?;
                        let missing = owner
                            .dispatch_serializer(
                                &plan,
                                conditions,
                                &observed,
                                None,
                                permit,
                                &Guard(true),
                                Duration::from_secs(5),
                            )
                            .await
                            .expect_err("missing checkpoint must not write");
                        assert_eq!(missing.reason, HandoffError::CheckpointRequired);
                        if native_media {
                            policy.0.set(true);
                            let wrong_listener = SocketAddrV4::new(
                                Ipv4Addr::LOCALHOST,
                                if listener.port() == u16::MAX {
                                    1
                                } else {
                                    listener.port() + 1
                                },
                            );
                            let preflight_request = media::Request {
                                plan: &plan,
                                current: Preconditions {
                                    listener: wrong_listener,
                                    ..conditions
                                },
                                baseline: &observed,
                                checkpoint: &stored,
                                authority: &Guard(true),
                                wait: Duration::from_secs(5),
                                framer: Framer::new(FlvLimits::default(), 1024 * 1024)?,
                                recorder: recording::Recorder::new(
                                    SourceKey {
                                        connection: 2,
                                        generation: 1,
                                    },
                                    recording::Limits::default(),
                                )?,
                                chunk_bytes: 4096,
                                max_bytes: 1024 * 1024,
                            };
                            let preflight = match media::start(
                                &mut owner,
                                native_listener.as_mut().ok_or("missing media listener")?,
                                preflight_request,
                                missing.permit,
                                |p, g| p == peer && g == 1,
                            )
                            .await
                            {
                                Err(refusal) => refusal,
                                Ok(_) => return Err("wrong listener accepted".into()),
                            };
                            assert_eq!(preflight.failure, media::Failure::Preflight);
                            assert!(!preflight.may_have_written);
                            let mut permit = preflight.permit;
                            for (chunk_bytes, max_bytes, wait) in [
                                (0, 1024 * 1024, Duration::from_secs(5)),
                                (
                                    fss_runtime::tcp_ingress::MAX_CHUNK_BYTES + 1,
                                    1024 * 1024,
                                    Duration::from_secs(5),
                                ),
                                (4096, 0, Duration::from_secs(5)),
                                (4096, 1024 * 1024, Duration::ZERO),
                                (4096, 1024 * 1024, Duration::from_secs(31)),
                            ] {
                                let invalid = media::Request {
                                    plan: &plan,
                                    current: conditions,
                                    baseline: &observed,
                                    checkpoint: &stored,
                                    authority: &Guard(true),
                                    wait,
                                    framer: Framer::new(FlvLimits::default(), 1024 * 1024)?,
                                    recorder: recording::Recorder::new(
                                        SourceKey {
                                            connection: 2,
                                            generation: 1,
                                        },
                                        recording::Limits::default(),
                                    )?,
                                    chunk_bytes,
                                    max_bytes,
                                };
                                let refusal = match media::start(
                                    &mut owner,
                                    native_listener.as_mut().ok_or("missing media listener")?,
                                    invalid,
                                    permit,
                                    |p, g| p == peer && g == 1,
                                )
                                .await
                                {
                                    Err(refusal) => refusal,
                                    Ok(_) => return Err("invalid media limits accepted".into()),
                                };
                                assert_eq!(refusal.failure, media::Failure::Preflight);
                                assert!(!refusal.may_have_written);
                                permit = refusal.permit;
                            }
                            for mismatch_clock in [true, false] {
                                let io_polled = Cell::new(false);
                                let alternate_clock = if mismatch_clock {
                                    let origin =
                                        clock.now()?.0.checked_add(1).ok_or("clock overflow")?;
                                    MeteredClock::new(task, cx, TimestampNs(origin))?
                                } else {
                                    clock
                                };
                                let alternate_resource = if mismatch_clock {
                                    resource.as_str()
                                } else {
                                    "fixture:different-camera"
                                };
                                let io = MeteredIo::with_clock(
                                    NoIo(&io_polled),
                                    alternate_clock,
                                    alternate_resource,
                                    4096,
                                )?;
                                let mut alternate_owner = camera_http::Owner::new(
                                    io,
                                    task,
                                    cx,
                                    alternate_clock,
                                    &policy,
                                    peer,
                                    1,
                                    alternate_resource,
                                )?;
                                let mismatched = media::Request {
                                    plan: &plan,
                                    current: conditions,
                                    baseline: &observed,
                                    checkpoint: &stored,
                                    authority: &Guard(true),
                                    wait: Duration::from_secs(5),
                                    framer: Framer::new(FlvLimits::default(), 1024 * 1024)?,
                                    recorder: recording::Recorder::new(
                                        SourceKey {
                                            connection: 2,
                                            generation: 1,
                                        },
                                        recording::Limits::default(),
                                    )?,
                                    chunk_bytes: 4096,
                                    max_bytes: 1024 * 1024,
                                };
                                let refusal = match media::start(
                                    &mut alternate_owner,
                                    native_listener.as_mut().ok_or("missing media listener")?,
                                    mismatched,
                                    permit,
                                    |p, g| p == peer && g == 1,
                                )
                                .await
                                {
                                    Err(refusal) => refusal,
                                    Ok(_) => return Err("mismatched media owner accepted".into()),
                                };
                                assert_eq!(refusal.failure, media::Failure::Preflight);
                                assert!(!refusal.may_have_written);
                                assert!(!io_polled.get());
                                permit = refusal.permit;
                            }
                            {
                                use fss_reference::unifi_direct::http_stream::media_archive;
                                let (storage, mut archive_policy) = preflight_archive_storage(
                                    task,
                                    cx,
                                    clock,
                                    &dir,
                                    "preflight-archive",
                                    conditions.camera,
                                )?;
                                let expected = if archive_media || combined_start || audio_mode != 0 {
                                    archive_policy.media_limits.max_samples = 0;
                                    media_archive::StartPreflight::Policy
                                } else {
                                    media_archive::StartPreflight::MissingBlockingPool
                                };
                                let io_polled = Cell::new(false);
                                let io = MeteredIo::with_clock(
                                    NoIo(&io_polled),
                                    clock,
                                    &resource,
                                    4096,
                                )?;
                                let mut fake_owner = camera_http::Owner::new(
                                    io, task, cx, clock, &policy, peer, 1, &resource,
                                )?;
                                let request = media::Request {
                                    plan: &plan,
                                    current: conditions,
                                    baseline: &observed,
                                    checkpoint: &stored,
                                    authority: &Guard(true),
                                    wait: Duration::from_secs(5),
                                    framer: Framer::new(FlvLimits::default(), 1024 * 1024)?,
                                    recorder: recording::Recorder::new(
                                        SourceKey {
                                            connection: 1,
                                            generation: 1,
                                        },
                                        recording::Limits::default(),
                                    )?,
                                    chunk_bytes: 4096,
                                    max_bytes: 1024 * 1024,
                                };
                                let refusal = media_archive::start(
                                    task,
                                    cx,
                                    clock,
                                    &mut fake_owner,
                                    native_listener.as_mut().ok_or("missing media listener")?,
                                    media_archive::Start {
                                        request,
                                        storage,
                                        policy: archive_policy,
                                    },
                                    permit,
                                    |p, g| p == peer && g == 1,
                                )
                                .await;
                                let (mut returned_inputs, returned_permit) = match refusal {
                                    Err(media_archive::StartRefusal::Preflight {
                                        reason,
                                        inputs,
                                        permit: returned,
                                    }) => {
                                        assert_eq!(reason, expected);
                                        assert!(!io_polled.get());
                                        (*inputs, returned)
                                    }
                                    _ => return Err("archive preflight did not refuse".into()),
                                };
                                returned_inputs.policy.media_limits =
                                    fss_container::Mp4Limits::default();
                                returned_inputs.policy.inband = true;
                                match media_archive::start(
                                    task,
                                    cx,
                                    clock,
                                    &mut fake_owner,
                                    native_listener.as_mut().ok_or("missing media listener")?,
                                    returned_inputs,
                                    returned_permit,
                                    |p, g| p == peer && g == 1,
                                )
                                .await
                                {
                                    Err(media_archive::StartRefusal::Preflight {
                                        reason,
                                        inputs,
                                        permit: returned,
                                    }) => {
                                        assert_eq!(reason, media_archive::StartPreflight::Binding);
                                        assert!(!io_polled.get());
                                        permit = returned;
                                        let _retained_inputs = inputs;
                                    }
                                    _ => {
                                        return Err(
                                            "incompatible archive format was accepted".into()
                                        );
                                    }
                                };
                            }
                            if combined_start && archive_media {
                                let (storage, archive_policy) = preflight_archive_storage(
                                    task, cx, clock, &dir, "combined-archive", conditions.camera,
                                )?;
                                let checkpoint_parent = dir.join("live-checkpoint-parent");
                                std::fs::DirBuilder::new().mode(0o700).create(&checkpoint_parent)?;
                                let checkpoint = trial_http_checkpoint::prepare(
                                    task,
                                    cx,
                                    clock,
                                    checkpoint_parent.join("checkpoint"),
                                    plan,
                                    observed,
                                    ContentDigest::sha256(b"fixture certificate"),
                                ).await?;
                                let capture = trial_http_checkpoint::Capture {
                                    framer: Framer::new(FlvLimits::default(), 1024 * 1024)?,
                                    recorder: recording::Recorder::new(
                                        SourceKey { connection: 1, generation: 1 },
                                        recording::Limits::default(),
                                    )?,
                                    storage,
                                    policy: archive_policy,
                                    wait: Duration::from_secs(5),
                                    chunk_bytes: 4096,
                                    max_bytes: 1024 * 1024,
                                };
                                let mut wrong = conditions;
                                wrong.listener.set_port(if wrong.listener.port() == u16::MAX { 1 } else { wrong.listener.port() + 1 });
                                let refused = trial_http_checkpoint::start(
                                    task, cx, clock, &mut owner,
                                    native_listener.as_mut().ok_or("missing media listener")?,
                                    checkpoint, wrong, &Guard(true), capture, permit, &mut effects, &resource,
                                    |p, g| p == peer && g == 1,
                                ).await;
                                let (capture, permit) = match refused.state {
                                    trial_http_checkpoint::StartState::Preflight { reason, capture, permit } => {
                                        assert_eq!(reason, fss_reference::unifi_direct::http_stream::media_archive::StartPreflight::Binding);
                                        (capture, permit)
                                    }
                                    _ => return Err("checkpointed start accepted wrong listener".into()),
                                };
                                let started = trial_http_checkpoint::start(
                                    task, cx, clock, &mut owner,
                                    native_listener.as_mut().ok_or("missing media listener")?,
                                    refused.checkpoint, conditions, &Guard(true), capture, permit, &mut effects, &resource,
                                    |p, g| p == peer && g == 1,
                                ).await;
                                let driver = match started.state {
                                    trial_http_checkpoint::StartState::Started(driver) => driver,
                                    _ => return Err("checkpointed archive start refused".into()),
                                };
                                let _checkpoint = started.checkpoint;
                                Box::pin(archive_http_media(None, Some(driver), task, cx, clock, &dir, conditions.camera)).await?;
                                drop(owner);
                                fixture.join().map_err(|_| "fixture panic")??;
                                return Ok(());
                            }
                            let expected_effect_digest = permit.prepared().digest();
                            let request = media::Request {
                                plan: &plan,
                                current: conditions,
                                baseline: &observed,
                                checkpoint: &stored,
                                authority: &Guard(true),
                                wait: Duration::from_secs(5),
                                framer: if audio_mode == 9 || audio_mode == 11 {
                                    Framer::with_mode(FlvLimits::default(), 1024 * 1024, fss_packet::extended_flv::stream::SearchMode::ZeroStreamId)?
                                } else {
                                    Framer::new(FlvLimits::default(), 1024 * 1024)?
                                },
                                recorder: recording::Recorder::new(
                                    SourceKey {
                                        connection: 1,
                                        generation: 1,
                                    },
                                    recording::Limits::default(),
                                )?,
                                chunk_bytes: 4096,
                                max_bytes: 1024 * 1024,
                            };
                            let mut coordinated_start = None;
                            let mut seed_owners = None;
                            let mut av_checkpoint = None;
                            let result = if audio_mode == 10 || audio_mode == 11 {
                                use fss_reference::unifi_direct::{av_owned_sink, http_stream::media_av_startup as startup};
                                let (storage, _) = preflight_archive_storage(task, cx, clock, &dir,
                                    if audio_mode == 10 { "checkpointed-av-rollover" } else { "checkpointed-av" }, conditions.camera)?;
                                let av_policy = av_owned_sink::BootstrapPolicy {
                                    allow_initial_video_only: false, max_separation_ms: 5_000, jitter_ms: 5,
                                    max_epoch_frames: 1_000_000,
                                    max_audio_frames: fss_container::Mp4Limits::default().max_samples,
                                    media_limits: fss_container::Mp4Limits::default(),
                                    evidence_limits: fss_reference::unifi_direct::evidence::Limits::default(),
                                };
                                let fresh = serializer_snapshot(peer, 1, br#"{"av":{"video":{"video1":{"avSerializer":null},"video2":{"avSerializer":{"destinations":["tcp://fixture:1"]}}}}}"#)?;
                                let fresh_plan = Plan::new(peer, &start, conditions, &fresh, Framing::ContentLength)?;
                                let checkpoint_parent = dir.join("av-checkpoint-parent");
                                std::fs::DirBuilder::new().mode(0o700).create(&checkpoint_parent)?;
                                let checkpoint = trial_http_checkpoint::prepare(task, cx, clock, checkpoint_parent.join("checkpoint"), fresh_plan, fresh, ContentDigest::sha256(b"fixture certificate")).await?;
                                let capture = trial_http_checkpoint::AvCapture {
                                    framer: if audio_mode == 11 {
                                        Framer::with_mode(FlvLimits::default(), 8 * 1024 * 1024, fss_packet::extended_flv::stream::SearchMode::ZeroStreamId)?
                                    } else { Framer::new(FlvLimits::default(), 1024 * 1024)? },
                                    recorder: recording::Recorder::new(SourceKey { connection: 1, generation: 1 }, recording::Limits::default())?,
                                    storage, retention: ContentDigest::sha256(b"preflight retention"), policy: av_policy,
                                    supplied_unverified_audio: Some([0x14, 0x08]), wait: Duration::from_secs(5), chunk_bytes: 4096,
                                    max_bytes: if audio_mode == 11 { 8 * 1024 * 1024 } else { 1024 * 1024 },
                                };
                                let mut wrong = conditions;
                                wrong.listener.set_port(if wrong.listener.port() == u16::MAX { 1 } else { wrong.listener.port() + 1 });
                                let refused = Box::pin(trial_http_checkpoint::start_av(task, cx, clock, &mut owner,
                                    native_listener.as_mut().ok_or("missing media listener")?, checkpoint, wrong, &Guard(true), capture, permit, &mut effects, &resource,
                                    |p, g| p == peer && g == 1)).await;
                                let (capture, permit) = match refused.state {
                                    trial_http_checkpoint::AvStartState::Preflight { reason, capture, permit } => {
                                        assert_eq!(reason, startup::StartPreflight::Binding);
                                        assert_eq!(capture.supplied_unverified_audio, Some([0x14, 0x08]));
                                        (capture, permit)
                                    }
                                    _ => return Err("checkpointed A/V accepted wrong listener".into()),
                                };
                                let started = Box::pin(trial_http_checkpoint::start_av(task, cx, clock, &mut owner,
                                    native_listener.as_mut().ok_or("missing media listener")?, refused.checkpoint, conditions, &Guard(true), capture, permit, &mut effects, &resource,
                                    |p, g| p == peer && g == 1)).await;
                                coordinated_start = Some(match started.state {
                                    trial_http_checkpoint::AvStartState::Started(driver) => driver,
                                    _ => return Err("checkpointed A/V start refused".into()),
                                });
                                av_checkpoint = Some(Box::new(started.checkpoint));
                                None
                            } else if (5..=9).contains(&audio_mode) {
                                use fss_reference::unifi_direct::{av_owned_sink, http_stream::media_av_startup as startup};
                                let (storage, _) = preflight_archive_storage(task, cx, clock, &dir, "http-coordinated-av", conditions.camera)?;
                                let storage = if audio_mode == 6 {
                                    let seeded = Box::pin(seed_av_rollover(task, cx, clock, &dir, storage)).await?;
                                    seed_owners = Some(Box::new((seeded._forwarded, seeded._old_sink)));
                                    seeded.storage
                                } else { storage };
                                let av_policy = av_owned_sink::BootstrapPolicy {
                                    allow_initial_video_only: false,
                                    max_separation_ms: 5_000,
                                    jitter_ms: 5,
                                    max_epoch_frames: 1_000_000,
                                    max_audio_frames: fss_container::Mp4Limits::default().max_samples,
                                    media_limits: fss_container::Mp4Limits::default(),
                                    evidence_limits: fss_reference::unifi_direct::evidence::Limits::default(),
                                };
                                let wrong_start = StreamStart::new(VideoChannel::Video1, listener, VideoCodec::H264, AudioCodec::Opus, "0123456789abcdef")?;
                                let wrong_plan = Plan::new(peer, &wrong_start, conditions, &baseline, Framing::ContentLength)?;
                                let inputs = Box::new(startup::Start { request, storage, retention: ContentDigest::sha256(b"preflight retention"), policy: av_policy, supplied_unverified_audio: (audio_mode >= 7).then_some([0x14, 0x08]) });
                                coordinated_start = Some(Box::pin(guarded_audio_start(task, cx, clock, &mut owner, native_listener.as_mut().ok_or("missing media listener")?, inputs, permit, peer, &resource, &policy, &wrong_plan, audio_mode == 6)).await?);
                                None
                            } else if combined_start {
                                use fss_reference::unifi_direct::http_stream::media_archive;
                                let (storage, archive_policy) = preflight_archive_storage(
                                    task,
                                    cx,
                                    clock,
                                    &dir,
                                    "combined-archive",
                                    conditions.camera,
                                )?;
                                let driver = match media_archive::start(
                                    task,
                                    cx,
                                    clock,
                                    &mut owner,
                                    native_listener.as_mut().ok_or("missing media listener")?,
                                    media_archive::Start {
                                        request,
                                        storage,
                                        policy: archive_policy,
                                    },
                                    permit,
                                    |p, g| p == peer && g == 1,
                                )
                                .await
                                {
                                    Ok(driver) => driver,
                                    Err(_) => return Err("combined archive start refused".into()),
                                };
                                if archive_media {
                                    Box::pin(archive_http_media(
                                        None,
                                        Some(driver),
                                        task,
                                        cx,
                                        clock,
                                        &dir,
                                        conditions.camera,
                                    ))
                                    .await?;
                                    drop(owner);
                                    fixture.join().map_err(|_| "fixture panic")??;
                                    return Ok(());
                                }
                                let parts = driver
                                    .into_parts()
                                    .map_err(|_| "new driver unexpectedly running")?;
                                Some(Ok(parts.connected))
                            } else if automatic_rollover == 55 {
                                let calls = Cell::new(0);
                                let refused = match media::start_with_response(
                                    &mut owner,
                                    native_listener.as_mut().ok_or("missing media listener")?,
                                    request, permit, |p, g| p == peer && g == 1,
                                    &mut |_, response| {
                                        calls.set(calls.get() + 1);
                                        assert_eq!(response, fss_reference::unifi_direct::camera_api::HandoffResponseObservation::Object { success: None, status_code: None });
                                        Err(media::ResponseCustodyError::Storage)
                                    },
                                ).await {
                                    Err(refused) => refused,
                                    Ok(_) => return Err("response custody refusal did not stop startup".into()),
                                };
                                assert_eq!(calls.get(), 1);
                                assert!(matches!(refused.failure, media::Failure::ResponseCustody { reason: media::ResponseCustodyError::Storage, .. }));
                                assert!(refused.may_have_written && refused.readback.is_none());
                                assert_eq!(effects.state(&refused.permit)?, fss_core::EffectState::Committed);
                                drop(owner);
                                fixture.join().map_err(|_| "fixture panic")??;
                                return Ok(());
                            } else {
                                Some(media::start(
                                    &mut owner,
                                    native_listener.as_mut().ok_or("missing media listener")?,
                                    request,
                                    permit,
                                    |p, g| p == peer && g == 1,
                                )
                                .await)
                            };
                            if !match_request {
                                let refusal = match result.ok_or("missing media result")? {
                                    Err(refusal) => refusal,
                                    Ok(_) => return Err("unchanged readback accepted".into()),
                                };
                                assert!(matches!(
                                    refusal.failure,
                                    media::Failure::UnexpectedReadback(_)
                                ));
                                assert!(refusal.may_have_written);
                                assert!(refusal.readback.is_some());
                                drop(owner);
                                fixture.join().map_err(|_| "fixture panic")??;
                                return Ok(());
                            }
                            let connected = match result {
                                Some(result) => {
                                    let connected = result.map_err(|_| "native media startup refused")?;
                                    assert_eq!(connected.comparison().change, ReadbackChange::TargetTrackOnly);
                                    assert!(connected.comparison().requested_fields_match);
                                    Some(connected)
                                }
                                None => None,
                            };
                            if audio_mode != 0 {
                                use fss_reference::unifi_direct::{av_owned_sink, http_stream::media_av_bootstrap};
                                let policy = av_owned_sink::BootstrapPolicy {
                                    allow_initial_video_only: false,
                                    max_separation_ms: 5_000,
                                    jitter_ms: 5,
                                    max_epoch_frames: 1_000_000,
                                    max_audio_frames: fss_container::Mp4Limits::default().max_samples,
                                    media_limits: fss_container::Mp4Limits::default(),
                                    evidence_limits: fss_reference::unifi_direct::evidence::Limits::default(),
                                };
                                if (5..=11).contains(&audio_mode) {
                                    use fss_reference::unifi_direct::{archive, av_worker, http_stream::{media_av_archive as av_archive, media_av_startup as startup}, source_coordinator::ArchiveAdmission, source_worker};
                                    let mut bootstrap = coordinated_start.ok_or("missing coordinated startup")?;
                                    bootstrap = match bootstrap.finish() {
                                        Err(refusal) => match *refusal {
                                            startup::TransitionRefusal::NotReady(driver) => driver,
                                            _ => return Err("wrong incomplete transition refusal".into()),
                                        },
                                        Ok(_) => return Err("incomplete coordinated bootstrap accepted".into()),
                                    };
                                    let cost = BudgetVector::ZERO;
                                    let admission = ArchiveAdmission { resource: "fixture:archive", cost: &cost };
                                    let mut source_pins = Vec::new();
                                    let mut observations = Vec::new();
                                    let mut ready = false;
                                    let mut checked_pending = false;
                                    for _ in 0..if audio_mode == 9 || audio_mode == 11 { 4096 } else { 256 } {
                                        match bootstrap.step(task, cx, clock, Duration::from_secs(2), admission).await {
                                            startup::Step::Retained if automatic_rollover == 10 => {
                                                Box::pin(exercise_http_av_bootstrap_exhaustion(bootstrap, task, cx, clock, admission, &resource)).await?;
                                                drop(owner);
                                                fixture.join().map_err(|_| "fixture panic")??;
                                                return Ok(());
                                            }
                                            startup::Step::Retained | startup::Step::Progress | startup::Step::Idle
                                            | startup::Step::SourceStarted | startup::Step::SourceRunning => (),
                                            startup::Step::Buffered(audio) => observations.push(audio),
                                            startup::Step::SourceOffered { audio, .. } => {
                                                observations.push(audio);
                                                bootstrap = match bootstrap.finish() {
                                                    Err(refusal) => match *refusal {
                                                        startup::TransitionRefusal::NotReady(driver) => driver,
                                                        _ => return Err("wrong pending source refusal".into()),
                                                    },
                                                    Ok(_) => return Err("transition bypassed pending source".into()),
                                                };
                                                checked_pending = true;
                                            }
                                            startup::Step::SourceCompleted(done) => {
                                                if done.runtime.is_err() { return Err("bootstrap source runtime failed".into()); }
                                                match done.outcome {
                                                    source_worker::Outcome::Publication(source_worker::Publication::Published { pin, .. }) => source_pins.push(pin),
                                                    _ => return Err("bootstrap source publication failed".into()),
                                                }
                                            }
                                            startup::Step::Forward { push, audio } if audio_mode == 8 => {
                                                assert!(matches!(audio.as_ref(), Some(fss_reference::unifi_direct::pipeline::AudioEvent::Observed(fss_packet::extended_flv::aac_track::Observation::Configuration { .. }))));
                                                assert!(matches!(bootstrap.step(task, cx, clock, Duration::from_secs(2), admission).await, startup::Step::Halted));
                                                let _retained_custody = (Box::new(bootstrap), Box::new(push), audio);
                                                drop(owner);
                                                fixture.join().map_err(|_| "fixture panic")??;
                                                return Ok(());
                                            }
                                            startup::Step::Ready => { ready = true; break; },
                                            startup::Step::MediaError(error) => return Err(format!("coordinated bootstrap media: {error:?}").into()),
                                            _ => return Err("unexpected coordinated bootstrap decision".into()),
                                        }
                                    }
                                    if !ready || !checked_pending || source_pins.is_empty() { return Err("coordinated bootstrap did not archive prefix".into()); }
                                    let mut archive = bootstrap.finish().map_err(|_| "coordinated bootstrap transition failed")?;
                                    if audio_mode == 10 && automatic_rollover == 0 {
                                        use fss_reference::unifi_direct::recording_session::AudioAllowancePolicy;
                                        let mut denied = AudioAllowancePolicy::new(2_000_000, 1_000_000, 0).ok_or("bad allowance")?;
                                        match Box::pin(archive.step_with_audio_allowance(&mut denied, task, cx, clock, Duration::from_secs(2), admission, admission)).await {
                                            av_archive::AllowanceStep::Exhausted { remaining, budget } => {
                                                assert!(remaining < 2_000_000);
                                                assert_eq!(budget, 0);
                                            }
                                            _ => return Err("exhausted allowance did not pause media".into()),
                                        }
                                        let mut permitted = AudioAllowancePolicy::new(2_000_000, 1_000_000, 2_000_000).ok_or("bad allowance")?;
                                        match Box::pin(archive.step_with_audio_allowance(&mut permitted, task, cx, clock, Duration::ZERO, admission, admission)).await {
                                            av_archive::AllowanceStep::Recording(av_archive::Step::Configuration) => (),
                                            _ => return Err("invalid wait changed allowance".into()),
                                        }
                                        assert_eq!(permitted.remaining_budget(), 2_000_000);
                                        match Box::pin(archive.step_with_audio_allowance(&mut permitted, task, cx, clock, Duration::from_secs(2), admission, admission)).await {
                                            av_archive::AllowanceStep::Renewed { before, after, budget } => {
                                                assert_eq!(after, before + 1_000_000);
                                                assert_eq!(budget, 1_000_000);
                                                assert_eq!(permitted.remaining_budget(), budget);
                                            }
                                            _ => return Err("authorized allowance was not renewed".into()),
                                        }
                                    }
                                    if automatic_rollover == 9 {
                                        Box::pin(exercise_http_av_network_exhaustion(archive, task, cx, clock, admission, &resource)).await?;
                                        drop(owner);
                                        fixture.join().map_err(|_| "fixture panic")??;
                                        return Ok(());
                                    }
                                    if automatic_rollover != 0 {
                                        boxed_automatic_rollover_test(archive, task, cx, clock, &dir, admission, automatic_rollover).await?;
                                        drop(owner);
                                        fixture.join().map_err(|_| "fixture panic")??;
                                        return Ok(());
                                    }
                                    let mut pins = Vec::new();
                                    let mut ended = false;
                                    let mut rollovers = 0;
                                    for _ in 0..if audio_mode == 9 || audio_mode == 11 { 4096 } else { 256 } {
                                        match archive.step(task, cx, clock, Duration::from_secs(2), admission, admission).await {
                                            av_archive::Step::Offer(av_archive::Offer::Source { audio, .. })
                                            | av_archive::Step::Offer(av_archive::Offer::Buffered(audio))
                                            | av_archive::Step::Offer(av_archive::Offer::Segment(audio)) => observations.push(audio),
                                            av_archive::Step::SourceStarted | av_archive::Step::SourceRunning | av_archive::Step::AvStarted
                                            | av_archive::Step::AvRunning | av_archive::Step::Idle
                                            | av_archive::Step::Media(fss_reference::unifi_direct::pipeline::Step::Progress { .. }) => (),
                                            av_archive::Step::SourceCompleted(done) => {
                                                if done.runtime.is_err() { return Err("source runtime failed".into()); }
                                                match done.outcome {
                                                    source_worker::Outcome::Publication(source_worker::Publication::Published { pin, .. }) => source_pins.push(pin),
                                                    _ => return Err("source publication failed".into()),
                                                }
                                            }
                                            av_archive::Step::AvCompleted(done) => {
                                                if done.runtime.is_err() { return Err("A/V runtime failed".into()); }
                                                match done.outcome {
                                                    av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(value)) => {
                                                        pins.push(value.pin);
                                                        if audio_mode == 9 || audio_mode == 11 { break; }
                                                    },
                                                    av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Refused {
                                                        reason: av_worker::FailureReason::JournalCapacity, rollover: Some(need), ..
                                                    }) if audio_mode == 10 && rollovers == 0 => {
                                                        if archive.authorize_av_retry() { return Err("capacity retry was incorrectly authorized".into()); }
                                                        match archive.step(task, cx, clock, Duration::from_secs(2), admission, admission).await {
                                                            av_archive::Step::RolloverRequired(actual) if actual == need => (),
                                                            _ => return Err("capacity observation was not retained".into()),
                                                        }
                                                        let outcome = boxed_manual_av_rollover(archive, task, cx, clock, &dir, rollover_deny).await?;
                                                        if rollover_deny {
                                                            match *outcome {
                                                                av_archive::RolloverResult::Unresolved { paused, retirement, completion } => {
                                                                    if completion.runtime.is_err() || retirement.fenced || !retirement.resources.has_pending() {
                                                                        return Err("denied replay lost pending media or fenced unexpectedly".into());
                                                                    }
                                                                    if !matches!(completion.outcome, fss_reference::unifi_direct::av_rollover_worker::Outcome::ReplayRefused { .. }) {
                                                                        return Err("denied replay did not retain its exact outcome".into());
                                                                    }
                                                                    let _retained_custody = (paused, retirement, completion);
                                                                    drop(owner);
                                                                    fixture.join().map_err(|_| "fixture panic")??;
                                                                    return Ok(());
                                                                }
                                                                _ => return Err("denied replay incorrectly resumed".into()),
                                                            }
                                                        }
                                                        archive = match *outcome {
                                                            av_archive::RolloverResult::Resumed { driver, .. } => driver,
                                                            _ => return Err("rollover unresolved".into()),
                                                        };
                                                        rollovers += 1;
                                                    },
                                                    av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Refused { stage, reason, .. }) => return Err(format!("high-resolution A/V refused: {stage:?} {reason:?}").into()),
                                                    _ => return Err("high-resolution A/V publication failed".into()),
                                                }
                                            }
                                            av_archive::Step::Media(fss_reference::unifi_direct::pipeline::Step::Eof) => { ended = true; break; }
                                            av_archive::Step::MediaError(error) => return Err(format!("high-resolution A/V media: {error:?}").into()),
                                            _ => return Err("unexpected high-resolution A/V decision".into()),
                                        }
                                    }
                                    let private_replay = audio_mode == 9 || audio_mode == 11;
                                    let expected_pins = if audio_mode == 10 { 3 } else { 2 };
                                    if (private_replay && pins.len() != 1) || (!private_replay && (!ended || pins.len() != expected_pins)) || (audio_mode == 10 && rollovers != 1) { return Err(format!("unexpected A/V segment count {} rollover {}", pins.len(), rollovers).into()); }
                                    let parts = archive.into_parts().map_err(|_| "high-resolution A/V did not drain")?;
                                    let retired = parts.av.retire().map_err(|_| "high-resolution A/V worker did not retire")?;
                                    let mut archive_parts = retired.parts;
                                    for pin in pins {
                                        let clip = archive::read_unknown_time_av_clip(
                                            &mut archive_parts.deployment, pin, &ArchiveAccess, archive::Limits::default(),
                                            &mut fss_geometry::WorkBudget::new(4_000_000_000), &archive_parts.replay,
                                        )?;
                                        if clip.audio().frames == 0 || clip.video_samples() == 0 { return Err("high-resolution segment missing A/V".into()); }
                                        assert_eq!(clip.audio().configuration_origin,
                                            if audio_mode >= 7 { fss_reference::unifi_direct::av_evidence::AudioConfigurationOrigin::SuppliedUnverified }
                                            else { fss_reference::unifi_direct::av_evidence::AudioConfigurationOrigin::InBand });
                                        let movie = AvcMp4::parse(clip.bytes(), None, DemuxLimits::default())?;
                                        if !movie.tracks().iter().any(|track| track.handler == *b"soun") { return Err("high-resolution segment has no audio track".into()); }
                                        let annex = movie.annex_b(0, 1)?;
                                        let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                                        let mut pictures = decoder.decode_annex_b(annex.bytes())?;
                                        pictures.extend(decoder.finish()?);
                                        let expected = if private_replay { (1280, 720) } else { (2688, 1512) };
                                        if pictures.len() != 1 || (pictures[0].width(), pictures[0].height()) != expected { return Err("A/V frame dimensions mismatch".into()); }
                                        if private_replay {
                                            let mut cost = BudgetVector::ZERO;
                                            cost.bytes = u64::try_from(clip.bytes().len())?;
                                            cost.storage_operations = 1;
                                            task.checkpoint_for(RuntimeGrant::ObjectStage, "fixture:archive", clock.now()?, &cost)?;
                                            let mut options = std::fs::OpenOptions::new();
                                            options.write(true).create_new(true);
                                            #[cfg(unix)]
                                            {
                                                use std::os::unix::fs::OpenOptionsExt;
                                                options.mode(0o600);
                                            }
                                            let mut output = options.open(dir.join("private-camera-av-readback.mp4"))?;
                                            output.write_all(clip.bytes())?;
                                            output.sync_all()?;
                                            println!("private_http_av_replay=passed video_samples={} audio_frames={} width={} height={} configuration=supplied_unverified capture_time=unknown", clip.video_samples(), clip.audio().frames, expected.0, expected.1);
                                        }
                                    }
                                    let _retained_custody = (parts.connected, parts.source, archive_parts, source_pins, observations, seed_owners, av_checkpoint);
                                    drop(owner);
                                    fixture.join().map_err(|_| "fixture panic")??;
                                    return Ok(());
                                }
                                let connected = connected.ok_or("missing connected media")?;
                                let connected = if audio_mode == 4 {
                                    let bound = native_listener.take().ok_or("missing live listener")?;
                                    match fss_reference::unifi_direct::http_stream::media_reaccept::Reaccept::new(bound, connected, 2, 1) {
                                        Err(fss_reference::unifi_direct::http_stream::media_reaccept::CreateRefusal::NotStoppedOrBound { listener, connected }) => {
                                            native_listener = Some(listener);
                                            connected
                                        }
                                        _ => return Err("live source was accepted for retirement".into()),
                                    }
                                } else { connected };
                                let mut driver = media_av_bootstrap::Driver::attach(
                                    connected, ContentDigest::sha256(b"preflight retention"), policy,
                                ).map_err(|_| "audio bootstrap attach refused")?;
                                assert!(matches!(driver.step(task, cx, clock, Duration::ZERO).await,
                                    media_av_bootstrap::Step::Configuration));
                                driver = match driver.bootstrap() {
                                    Err(media_av_bootstrap::HandoffRefusal::NotReady(driver)) => driver,
                                    _ => return Err("incomplete audio bootstrap was accepted".into()),
                                };
                                let mut forwarded = Vec::new();
                                let mut ready = false;
                                for _ in 0..128 {
                                    match driver.step(task, cx, clock, Duration::from_secs(2)).await {
                                        media_av_bootstrap::Step::Retained | media_av_bootstrap::Step::Progress | media_av_bootstrap::Step::Idle => (),
                                        media_av_bootstrap::Step::Forward { push, audio } => {
                                            let duplicate = matches!(audio.as_ref(), Some(fss_reference::unifi_direct::pipeline::AudioEvent::Observed(fss_packet::extended_flv::aac_track::Observation::Configuration { .. })));
                                            forwarded.push((push, audio));
                                            if audio_mode == 2 && duplicate {
                                                assert!(matches!(driver.step(task, cx, clock, Duration::from_secs(2)).await, media_av_bootstrap::Step::Fenced));
                                                let parts = driver.into_parts();
                                                assert!(parts.fenced);
                                                let collected = parts.collector.into_parts();
                                                assert!(collected.video.is_some() && collected.audio.is_some());
                                                let detached = parts.connected.into_parts();
                                                assert!(detached.permit.prepared().effect_class().contains("CAMERA-SETTING"));
                                                let _retained_custody = (detached, collected, forwarded);
                                                drop(owner);
                                                fixture.join().map_err(|_| "fixture panic")??;
                                                return Ok(());
                                            }
                                        },
                                        media_av_bootstrap::Step::Ready => { ready = true; break; }
                                        other => return Err(format!("audio bootstrap stopped: {other:?}").into()),
                                    }
                                }
                                if audio_mode == 2 { return Err("duplicate audio configuration was not fenced".into()); }
                                if !ready { return Err("audio bootstrap did not become ready".into()); }
                                if !forwarded.iter().any(|(_, audio)| matches!(audio, Some(fss_reference::unifi_direct::pipeline::AudioEvent::Observed(_)))) {
                                    return Err("audio sample observation was not forwarded".into());
                                }
                                let handoff = match driver.bootstrap() {
                                    Ok(handoff) => handoff,
                                    Err(media_av_bootstrap::HandoffRefusal::NotReady(_)) => return Err("audio bootstrap unexpectedly incomplete".into()),
                                    Err(media_av_bootstrap::HandoffRefusal::Bootstrap { refusal, .. }) => return Err(format!("audio bootstrap refused: {:?}", refusal.reason).into()),
                                };
                                assert!(handoff.bootstrap.first_segment.fragment().bytes().len() > 0);
                                use fss_reference::unifi_direct::{archive, av_worker};
                                let (mut storage, _) = preflight_archive_storage(
                                    task, cx, clock, &dir,
                                    if matches!(automatic_rollover, 48 | 49 | 52) { "http-av-rollover" } else { "http-av-archive" }, conditions.camera,
                                )?;
                                if audio_mode == 3 {
                                    storage.av.work_limit = 0;
                                    let refusal = match handoff.into_archive(*storage.av) {
                                        Err(refusal) => refusal,
                                        Ok(_) => return Err("invalid worker was accepted".into()),
                                    };
                                    match *refusal {
                                        media_av_bootstrap::ArchiveHandoffRefusal::Worker { connected, parts, first_segment, origin } => {
                                            assert_eq!(parts.work_limit, 0);
                                            assert!(!first_segment.fragment().bytes().is_empty());
                                            let detached = connected.into_parts();
                                            assert!(detached.permit.prepared().effect_class().contains("CAMERA-SETTING"));
                                            let _retained_custody = (detached, parts, first_segment, origin, storage.coordinator, forwarded);
                                        }
                                        _ => return Err("wrong worker refusal".into()),
                                    }
                                    drop(owner);
                                    fixture.join().map_err(|_| "fixture panic")??;
                                    return Ok(());
                                }
                                let mut archive_handoff = handoff.into_archive(*storage.av)
                                    .map_err(|_| "audio archive worker construction refused")?;
                                if audio_mode == 4 {
                                    use fss_reference::unifi_direct::{http_stream::media_av_archive as av_archive, source_coordinator::ArchiveAdmission, source_worker};
                                    let mut archive = av_archive::Driver::attach(archive_handoff, storage.coordinator)
                                        .map_err(|_| "HTTP audio archive attachment refused")?;
                                    let cost = BudgetVector::ZERO;
                                    let admission = ArchiveAdmission { resource: "fixture:archive", cost: &cost };
                                    let mut observations = Vec::new();
                                    let mut source_pins = Vec::new();
                                    for (push, audio) in forwarded {
                                        match archive.offer_prefix(push, audio) {
                                            av_archive::Offer::Source { audio, .. } => {
                                                observations.push(audio);
                                                assert!(!archive.seal_prefix());
                                                loop {
                                                    match archive.step(task, cx, clock, Duration::from_secs(2), admission, admission).await {
                                                        av_archive::Step::SourceStarted | av_archive::Step::SourceRunning => (),
                                                        av_archive::Step::SourceCompleted(done) => {
                                                            if done.runtime.is_err() { return Err("prefix source runtime failed".into()); }
                                                            match done.outcome {
                                                                source_worker::Outcome::Publication(source_worker::Publication::Published { pin, .. }) => source_pins.push(pin),
                                                                _ => return Err("prefix source publication failed".into()),
                                                            }
                                                            break;
                                                        }
                                                        _ => return Err("unexpected prefix source decision".into()),
                                                    }
                                                }
                                            }
                                            av_archive::Offer::Buffered(audio) => observations.push(audio),
                                            _ => return Err("bootstrap prefix was refused".into()),
                                        }
                                    }
                                    if source_pins.is_empty() || !archive.seal_prefix() { return Err("bootstrap prefix was not published".into()); }
                                    if matches!(automatic_rollover, 46 | 47 | 48 | 49 | 50 | 51 | 52 | 53 | 54) {
                                        let manager = build_reuse_manager(archive, &dir)?;
                                        let bound = native_listener.take().ok_or("missing supervisor listener")?;
                                        let result = boxed_managed_supervisor(manager, bound, task, cx, clock, admission, policy,
                                            expected_effect_digest, automatic_rollover).await?;
                                        let completed = match result {
                                            SupervisorRun::Recorded(fixture) if matches!(automatic_rollover, 46 | 48 | 49) => fixture,
                                            SupervisorRun::GeneralStopped { scope, recovery, pins, source_receipts, old_tail_receipts, observations: retry_observations }
                                                if automatic_rollover == 54 => {
                                                use fss_reference::unifi_direct::http_stream::media_av_recovery as general;
                                                assert!(scope.phase_listener.is_some() && scope.supervisor_listener.is_none());
                                                let refusal = match recovery.phase.as_ref() {
                                                    Some(general::Phase::ReuseStopped(refusal)) => match &**refusal {
                                                        general::ReuseRefusal::SourceUnsettled(value) => value,
                                                        _ => return Err("wrong retention produced wrong refusal".into()),
                                                    },
                                                    _ => return Err("reuse refusal not retained".into()),
                                                };
                                                assert_eq!(refusal.0.effect.permit.prepared().digest(), expected_effect_digest);
                                                assert!(refusal.0.media.active.is_some());
                                                let creator_started = recovery.parked.as_ref().ok_or("refusal lost parked manager")?.parts.creator_started;
                                                let mut drain = general::Drain::begin(recovery).map_err(|_| "reuse refusal drain refused")?;
                                                let report = Box::pin(drain.join_available()).await;
                                                if creator_started && report.parked_creator != general::JoinResult::Retained {
                                                    return Err("reuse refusal creator not joined".into());
                                                }
                                                let (recovery, receipts) = drain.finish_if_drained().map_err(|_| "reuse refusal still has workers")?;
                                                let refusal = match recovery.phase.as_ref() {
                                                    Some(general::Phase::ReuseStopped(refusal)) => match &**refusal {
                                                        general::ReuseRefusal::SourceUnsettled(value) => value,
                                                        _ => return Err("drain changed reuse refusal".into()),
                                                    },
                                                    _ => return Err("drain lost reuse refusal".into()),
                                                };
                                                assert!(refusal.1.halted && !refusal.1.armed && !refusal.1.worker.is_running());
                                                assert_eq!(refusal.0.effect.permit.prepared().digest(), expected_effect_digest);
                                                let _retained = (scope, recovery, receipts, pins, source_receipts,
                                                    old_tail_receipts, retry_observations, source_pins, observations);
                                                drop(owner);
                                                fixture.join().map_err(|_| "fixture panic")??;
                                                return Ok(());
                                            }
                                            SupervisorRun::GeneralStopped { scope, recovery, pins, source_receipts, old_tail_receipts, observations: retry_observations }
                                                if automatic_rollover == 53 => {
                                                use fss_reference::unifi_direct::http_stream::{media_av_managed as managed, media_av_recovery as general};
                                                assert!(scope.supervisor_listener.is_some() && scope.phase_listener.is_none());
                                                assert!(matches!(&recovery.phase, Some(general::Phase::Recording(_))));
                                                let mut drain = general::Drain::begin(recovery).map_err(|_| "recording drain refused")?;
                                                assert!(drain.running_workers().av);
                                                drain = match drain.finish_if_drained() {
                                                    Err(original) => original,
                                                    Ok(_) => return Err("running A/V worker was reported drained".into()),
                                                };
                                                assert_eq!(Box::pin(drain.join_av()).await, general::JoinResult::Retained);
                                                let mut interrupted = Box::pin(async {
                                                    assert_eq!(drain.join_av().await, general::JoinResult::Retained);
                                                    std::future::pending::<()>().await;
                                                });
                                                std::future::poll_fn(|cx| match std::future::Future::poll(interrupted.as_mut(), cx) {
                                                    Poll::Pending => Poll::Ready(()),
                                                    Poll::Ready(()) => panic!("interrupted drain unexpectedly completed"),
                                                }).await;
                                                drop(interrupted);
                                                assert_eq!(Box::pin(drain.join_av()).await, general::JoinResult::Retained);
                                                let report = Box::pin(drain.join_available()).await;
                                                assert_eq!(report.av, general::JoinResult::Retained);
                                                let (mut recovery, receipts) = drain.finish_if_drained().map_err(|_| "recording still has workers")?;
                                                assert!(receipts.av.is_some());
                                                let manager = match recovery.phase.take() {
                                                    Some(general::Phase::Recording(manager)) => manager,
                                                    _ => return Err("recording drain lost manager".into()),
                                                };
                                                let mut manager = (*manager).into_parts();
                                                let driver = match manager.owner.take() {
                                                    Some(managed::Owner::Recording(driver)) => driver,
                                                    _ => return Err("recording drain lost archive".into()),
                                                };
                                                let recording = (*driver).into_parts().map_err(|_| "recording drain left worker running")?;
                                                let connected = recording.connected.into_parts();
                                                assert_eq!(connected.permit.prepared().digest(), expected_effect_digest);
                                                let _retained = (scope, recovery, receipts, manager, connected, recording.source,
                                                    recording.av, recording.first_segment, recording.origin, recording.key,
                                                    recording.camera_claim, recording.source_armed, recording.av_state,
                                                    recording.rollover_need, recording.prefix_sealed, recording.halted, pins, source_receipts,
                                                    old_tail_receipts, retry_observations, source_pins, observations);
                                                drop(owner);
                                                fixture.join().map_err(|_| "fixture panic")??;
                                                return Ok(());
                                            }
                                            SupervisorRun::GeneralStopped { scope, recovery, pins, source_receipts, old_tail_receipts, observations: retry_observations }
                                                if automatic_rollover == 52 => {
                                                use fss_reference::unifi_direct::http_stream::media_av_recovery as general;
                                                fn requires_static<T: 'static>(_: &T) {}
                                                requires_static(&recovery);
                                                assert!(scope.supervisor_listener.is_none() && scope.phase_listener.is_some());
                                                let verification = match recovery.phase.as_ref() {
                                                    Some(general::Phase::Verifying(verification)) => verification,
                                                    _ => return Err("general recovery lost verifying phase".into()),
                                                };
                                                assert!(verification.started && verification.bridge.media.active.is_some());
                                                assert_eq!(verification.bridge.effect.permit.prepared().digest(), expected_effect_digest);
                                                let creator_started = recovery.parked.as_ref().ok_or("general recovery lost parked manager")?.parts.creator_started;
                                                let mut drain = general::Drain::begin(recovery).map_err(|_| "verification drain refused")?;
                                                assert!(drain.running_workers().verification);
                                                drain = match drain.finish_if_drained() {
                                                    Err(original) => original,
                                                    Ok(_) => return Err("running verification was reported drained".into()),
                                                };
                                                let report = Box::pin(drain.join_available()).await;
                                                assert_eq!(report.verification, general::JoinResult::Retained);
                                                assert_eq!(Box::pin(drain.join_verification()).await, general::JoinResult::Retained);
                                                if creator_started && report.parked_creator != general::JoinResult::Retained {
                                                    return Err("general recovery did not join creator".into());
                                                }
                                                let (recovery, receipts) = drain.finish_if_drained().map_err(|_| "verification still has workers")?;
                                                assert!(receipts.verification.is_some());
                                                let _retained = (scope, recovery, receipts, pins, source_receipts,
                                                    old_tail_receipts, retry_observations, source_pins, observations);
                                                drop(owner);
                                                fixture.join().map_err(|_| "fixture panic")??;
                                                return Ok(());
                                            }
                                            SupervisorRun::GeneralStopped { scope, recovery, pins, source_receipts, old_tail_receipts, observations: retry_observations }
                                                if automatic_rollover == 51 => {
                                                use fss_reference::unifi_direct::http_stream::media_av_recovery as general;
                                                fn requires_static<T: 'static>(_: &T) {}
                                                requires_static(&recovery);
                                                assert!(scope.supervisor_listener.is_none() && scope.phase_listener.is_some());
                                                assert!(scope.parked_clock.is_some_and(|parked| parked.same_mapping(&scope.clock)));
                                                let transition = match recovery.phase.as_ref() {
                                                    Some(general::Phase::Reconnecting(transition)) => transition,
                                                    _ => return Err("general recovery lost reconnecting phase".into()),
                                                };
                                                assert!(!transition.tail_finished);
                                                assert_eq!(transition.bridge.effect.permit.prepared().digest(), expected_effect_digest);
                                                let creator_started = recovery.parked.as_ref().ok_or("general recovery lost parked manager")?.parts.creator_started;
                                                let mut drain = general::Drain::begin(recovery).map_err(|_| "reconnect drain refused")?;
                                                assert!(drain.running_workers().source);
                                                drain = match drain.finish_if_drained() {
                                                    Err(original) => original,
                                                    Ok(_) => return Err("running source was reported drained".into()),
                                                };
                                                let report = Box::pin(drain.join_available()).await;
                                                assert_eq!(report.source, general::JoinResult::Retained);
                                                assert_eq!(Box::pin(drain.join_source()).await, general::JoinResult::Retained);
                                                if creator_started && report.parked_creator != general::JoinResult::Retained {
                                                    return Err("general recovery did not join creator".into());
                                                }
                                                let (recovery, receipts) = drain.finish_if_drained().map_err(|_| "reconnect still has workers")?;
                                                assert!(receipts.source.is_some());
                                                let _retained = (scope, recovery, receipts, pins, source_receipts,
                                                    old_tail_receipts, retry_observations, source_pins, observations);
                                                drop(owner);
                                                fixture.join().map_err(|_| "fixture panic")??;
                                                return Ok(());
                                            }
                                            SupervisorRun::RetryStopped { scope, mut recovery, pins, source_receipts, old_tail_receipts, observations: retry_observations }
                                                if matches!(automatic_rollover, 47 | 50) => {
                                                fn requires_static<T: 'static>(_: &T) {}
                                                requires_static(&recovery);
                                                assert_eq!(recovery.bridge.effect.permit.prepared().digest(), expected_effect_digest);
                                                assert_eq!((recovery.bridge.media.attempts, recovery.bridge.media.max_attempts),
                                                    (if automatic_rollover == 47 { 2 } else { 0 }, 2));
                                                assert!(recovery.bridge.media.active.is_none() && !recovery.bridge.media.interrupted);
                                                if automatic_rollover == 47 {
                                                    assert!(recovery.reconnect_blocked && !recovery.reconnect_retryable);
                                                } else {
                                                    assert!(!recovery.reconnect_blocked && !recovery.tail_finished);
                                                }
                                                assert!(scope.parked_clock.is_some_and(|parked| parked.same_mapping(&scope.clock)));
                                                recovery.abort();
                                                recovery.abort();
                                                let parked = recovery.parked.as_mut().ok_or("missing parked recovery")?;
                                                assert!(parked.parts.aborted);
                                                let creator_joined = Box::pin(parked.join_creator()).await;
                                                if creator_joined {
                                                    assert!(parked.parts.creator_completion.is_some());
                                                    assert!(Box::pin(parked.join_creator()).await);
                                                }
                                                let tail_joined = Box::pin(recovery.join_tail()).await;
                                                if automatic_rollover == 50 && !tail_joined {
                                                    return Err("active tail cancellation was not drained".into());
                                                }
                                                if tail_joined {
                                                    assert!(recovery.tail_completion.is_some());
                                                    assert!(Box::pin(recovery.join_tail()).await);
                                                }
                                                let previous_joined = Box::pin(recovery.join_previous()).await;
                                                if previous_joined {
                                                    assert!(recovery.previous_completion.is_some());
                                                    assert!(Box::pin(recovery.join_previous()).await);
                                                }
                                                assert_eq!(recovery.bridge.effect.permit.prepared().digest(), expected_effect_digest);
                                                let _retained = (scope, recovery,
                                                    pins, source_receipts, old_tail_receipts, retry_observations,
                                                    source_pins, observations);
                                                drop(owner);
                                                fixture.join().map_err(|_| "fixture panic")??;
                                                return Ok(());
                                            }
                                            _ => return Err("unexpected supervisor fixture outcome".into()),
                                        };
                                        boxed_finish_managed_supervisor(completed, task, cx, clock, admission).await?;
                                        let _retained = (source_pins, observations);
                                        drop(owner);
                                        fixture.join().map_err(|_| "fixture panic")??;
                                        return Ok(());
                                    }
                                    let mut pins = Vec::new();
                                    let mut ended = false;
                                    for _ in 0..256 {
                                        match archive.step(task, cx, clock, Duration::from_secs(2), admission, admission).await {
                                            av_archive::Step::Offer(av_archive::Offer::Source { audio, .. })
                                            | av_archive::Step::Offer(av_archive::Offer::Buffered(audio))
                                            | av_archive::Step::Offer(av_archive::Offer::Segment(audio)) => observations.push(audio),
                                            av_archive::Step::SourceStarted | av_archive::Step::SourceRunning
                                            | av_archive::Step::AvStarted | av_archive::Step::AvRunning | av_archive::Step::Idle
                                            | av_archive::Step::Media(fss_reference::unifi_direct::pipeline::Step::Progress { .. }) => (),
                                            av_archive::Step::SourceCompleted(done) => {
                                                if done.runtime.is_err() { return Err("source runtime failed".into()); }
                                                match done.outcome {
                                                    source_worker::Outcome::Publication(source_worker::Publication::Published { pin, .. }) => source_pins.push(pin),
                                                    _ => return Err("source publication failed".into()),
                                                }
                                            }
                                            av_archive::Step::AvCompleted(done) => {
                                                if done.runtime.is_err() { return Err("A/V runtime failed".into()); }
                                                match done.outcome {
                                                    av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(value)) => pins.push(value.pin),
                                                    av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Refused { stage, reason, .. }) => return Err(format!("A/V stream publication refused: {stage:?} {reason:?}").into()),
                                                    _ => return Err("A/V stream publication failed".into()),
                                                }
                                            }
                                            av_archive::Step::Media(fss_reference::unifi_direct::pipeline::Step::Eof) => { ended = true; break; }
                                            av_archive::Step::MediaError(error) => return Err(format!("A/V stream failed: {error:?}").into()),
                                            _ => return Err("unexpected A/V stream decision".into()),
                                        }
                                    }
                                    if !ended || pins.len() != 2 { return Err(format!("expected two A/V segments and EOF, got {}", pins.len()).into()); }
                                    let (parked, parts) = if automatic_rollover == 44 {
                                        let (parked, parts) = park_reuse_manager(archive, task, cx, clock, &dir)?;
                                        (Some(parked), *parts)
                                    } else {
                                        (None, archive.into_parts().map_err(|_| "A/V stream did not drain")?)
                                    };
                                    let old_key = parts.key;
                                    let bound = native_listener.take().ok_or("missing reaccept listener")?;
                                    let address = bound.local_addr();
                                    use fss_reference::unifi_direct::http_stream::media_av_reconnect as reconnect;
                                    let mut transition = Box::new(reconnect::Transition::new(parts, bound, 2)
                                        .map_err(|_| "recording transition refused")?);
                                    let auto = reconnect::SuccessorConfig {
                                        flv: FlvLimits::default(), max_buffer: 1024 * 1024,
                                        search: fss_packet::extended_flv::stream::SearchMode::Conservative,
                                        recorder: recording::Limits::default(), inband: false,
                                        expected_dimensions: Some([160, 128]), chunk_bytes: 4096,
                                        max_bytes: 1024 * 1024, wait: Duration::from_secs(5),
                                    };
                                    let wrong_clock = MeteredClock::new(task, cx, TimestampNs(1))?;
                                    assert!(matches!(transition.step_auto(task, cx, wrong_clock, admission, auto).await,
                                        reconnect::AutoStep::Refused(reconnect::AutoError::Configuration)));
                                    assert!(matches!(transition.step_tail(task, cx, wrong_clock, admission).await,
                                        fss_reference::unifi_direct::retirement_source::DriverStep::StartRefused(
                                            fss_reference::unifi_direct::av_worker::StartError::Context)));
                                    let canceled_key = SourceKey {
                                        connection: old_key.connection.checked_add(1).ok_or("connection overflow")?,
                                        generation: old_key.generation.checked_add(1).ok_or("generation overflow")?,
                                    };
                                    let next_key = SourceKey {
                                        connection: old_key.connection.checked_add(2).ok_or("connection overflow")?,
                                        generation: old_key.generation.checked_add(2).ok_or("generation overflow")?,
                                    };
                                    let next_storage = if matches!(automatic_rollover, 44 | 45) {
                                        None
                                    } else {
                                        let (storage, _) = preflight_archive_storage_for(
                                            task, cx, clock, &dir, "http-reconnected-av", conditions.camera,
                                            if automatic_rollover == 43 { old_key } else { next_key },
                                        )?;
                                        Some(match (*transition).finish_recording(
                                            storage, ContentDigest::sha256(b"preflight retention"), policy, None,
                                        ) {
                                            Err(reconnect::FinishRecordingRefusal::NotReady { transition: returned, storage }) => {
                                                transition = Box::new(returned);
                                                storage
                                            }
                                            _ => return Err("premature recording transition accepted".into()),
                                        })
                                    };
                                    let new_inputs = || -> Result<_, Box<dyn Error>> {
                                        Ok(fss_reference::unifi_direct::media_reconnect::Inputs {
                                            framer: Framer::new(FlvLimits::default(), 1024 * 1024)?,
                                            recorder: recording::Recorder::new(next_key, recording::Limits::default())?,
                                        })
                                    };
                                    let refused = transition.accept_next(new_inputs()?, 4096, 1024 * 1024, Duration::from_secs(5))
                                        .err().ok_or("unpublished tail did not fence reaccept")?;
                                    assert!(matches!(refused, reconnect::AcceptRefusal::TailNotPublished(_)));
                                    transition = match (*transition).finish(ContentDigest::sha256(b"preflight retention"), policy, None) {
                                        Err(reconnect::FinishRefusal::NotReady(transition)) => Box::new(transition),
                                        _ => return Err("unfinished transition was accepted".into()),
                                    };
                                    let expected: Vec<_> = transition.tail_plan().items_in_order().map(|item|
                                        (item.record.offset(), item.record.bytes().len(), item.disposition)).collect();
                                    if expected.is_empty() || !transition.enable_batching(256, 1024 * 1024) {
                                        return Err("old tail was empty or not batchable".into());
                                    }
                                    if automatic_rollover == 42 {
                                        use fss_reference::unifi_direct::retirement_source::DriverStep;
                                        if !matches!(transition.step_auto(task, cx, clock, admission, auto).await,
                                            reconnect::AutoStep::Tail(DriverStep::BatchOffered { .. })) {
                                            return Err("old tail batch was not offered".into());
                                        }
                                        let mut bad_cost = BudgetVector::ZERO;
                                        bad_cost.bytes = u64::MAX;
                                        let denied = fss_reference::unifi_direct::source_coordinator::ArchiveAdmission {
                                            resource: admission.resource, cost: &bad_cost,
                                        };
                                        if !matches!(transition.step_auto(task, cx, clock, denied, auto).await,
                                            reconnect::AutoStep::Tail(DriverStep::StartRefused(_))) {
                                            return Err("old tail admission was not refused".into());
                                        }
                                        assert!(matches!(transition.step_auto(task, cx, clock, admission, auto).await, reconnect::AutoStep::TailFenced));
                                        let refusal = transition.accept_next(new_inputs()?, 4096, 1024 * 1024, Duration::from_secs(5))
                                            .err().ok_or("failed tail admitted successor")?;
                                        assert!(matches!(refusal, reconnect::AcceptRefusal::TailNotPublished(_)));
                                        let retained = (*transition).into_parts();
                                        assert!(retained.tail_fenced && !retained.tail_finished);
                                        let tail = retained.tail.into_parts().map_err(|_| "refused tail still running")?;
                                        let worker = tail.worker.retire().map_err(|_| "refused source still running")?;
                                        let Some(source_worker::Input::Batch { batch, .. }) = worker.pending else {
                                            return Err("refused tail lost batch".into());
                                        };
                                        let wire = synthetic_high_flv(4)?;
                                        let mut seen = 0usize;
                                        for item in batch.items_in_order().chain(tail.plan.items_in_order()) {
                                            let length = item.record.bytes().len();
                                            if expected.get(seen) != Some(&(item.record.offset(), length, item.disposition)) {
                                                return Err("refused tail range changed".into());
                                            }
                                            let start = usize::try_from(item.record.offset())?;
                                            let end = start.checked_add(length).ok_or("refused tail overflow")?;
                                            if wire.get(start..end) != Some(item.record.bytes()) { return Err("refused tail bytes changed".into()); }
                                            seen += 1;
                                        }
                                        if seen != expected.len() || worker.fenced { return Err("refused tail custody incomplete".into()); }
                                        let _retained = (retained.bridge, retained.previous, worker.parts, batch, tail.plan, next_storage, source_pins, observations);
                                        drop(owner);
                                        fixture.join().map_err(|_| "fixture panic")??;
                                        return Ok(());
                                    }
                                    let mut offers = Vec::new();
                                    let mut pending = None;
                                    let mut finished = false;
                                    for _ in 0..2048 {
                                        use fss_reference::unifi_direct::retirement_source::DriverStep;
                                        match transition.step_auto(task, cx, clock, admission, auto).await {
                                            reconnect::AutoStep::Tail(DriverStep::BatchOffered { offset, len, records }) => {
                                                if pending.replace((offset, len, records)).is_some() { return Err("overlapping tail batch".into()); }
                                            }
                                            reconnect::AutoStep::Tail(DriverStep::Started) => (),
                                            reconnect::AutoStep::Tail(DriverStep::Completed(done)) if done.runtime.is_ok() => {
                                                let pin = match done.outcome {
                                                    source_worker::Outcome::Publication(source_worker::Publication::Published { pin, .. }) => pin,
                                                    _ => return Err("old tail publication refused".into()),
                                                };
                                                offers.push((pin, pending.take().ok_or("receipt without batch")?));
                                            }
                                            reconnect::AutoStep::Tail(DriverStep::Finished) if pending.is_none() => { finished = true; break; }
                                            _ => return Err("old tail transition stopped".into()),
                                        }
                                    }
                                    if !finished || offers.is_empty() { return Err("old tail publication incomplete".into()); }
                                    assert!(matches!(transition.step_auto(task, cx, wrong_clock, admission, auto).await,
                                        reconnect::AutoStep::Refused(reconnect::AutoError::Configuration)));
                                    let duplicate = fss_reference::unifi_direct::media_reconnect::Inputs {
                                        framer: Framer::new(FlvLimits::default(), 1024 * 1024)?,
                                        recorder: recording::Recorder::new(old_key, recording::Limits::default())?,
                                    };
                                    let refusal = transition.accept_next(duplicate, 4096, 1024 * 1024, Duration::from_secs(5))
                                        .err().ok_or("old HTTP source key was accepted")?;
                                    match refusal {
                                        reconnect::AcceptRefusal::Bridge(refusal) => {
                                            assert_eq!(refusal.reason, fss_reference::unifi_direct::media_reconnect::Error::SourceOrder);
                                            assert!(refusal.inputs.is_some());
                                        }
                                        _ => return Err("wrong duplicate-key refusal".into()),
                                    }
                                    let mut interrupted = Box::pin(transition.step_auto(task, cx, clock, admission, auto));
                                    std::future::poll_fn(|context| match std::future::Future::poll(interrupted.as_mut(), context) {
                                        Poll::Pending => Poll::Ready(()),
                                        Poll::Ready(_) => panic!("automatic accept did not wait"),
                                    }).await;
                                    drop(interrupted);
                                    assert!(matches!(transition.step_auto(task, cx, clock, admission, auto).await, reconnect::AutoStep::Interrupted));
                                    assert_eq!(transition.acknowledge_interrupted(), Some(canceled_key));
                                    let new_wire = synthetic_high_flv(4)?;
                                    let sender = std::thread::spawn(move || -> std::io::Result<()> {
                                        let mut socket = std::net::TcpStream::connect_timeout(&address.into(), Duration::from_secs(5))?;
                                        socket.write_all(&new_wire)
                                    });
                                    assert!(matches!(transition.step_auto(task, cx, clock, admission, auto).await,
                                        reconnect::AutoStep::Accepted(key) if key == next_key));
                                    sender.join().map_err(|_| "new media peer panicked")??;
                                    assert!(matches!(transition.step_auto(task, cx, clock, admission, auto).await,
                                        reconnect::AutoStep::Ready(key) if key == next_key));
                                    if automatic_rollover == 44 {
                                        if dir.join("http-reconnected-av").exists() { return Err("reuse created a successor root".into()); }
                                        let reuse_state = boxed_reuse_bootstrap(transition, task, cx, clock, admission, policy,
                                            pins, offers, expected, old_key, next_key, expected_effect_digest,
                                            parked.ok_or("parked manager missing")?).await?;
                                        let reuse_state = finish_reuse_bootstrap(reuse_state)?;
                                        boxed_reuse_archive(reuse_state, task, cx, clock, admission).await?;
                                        if dir.join("http-reconnected-av").exists() { return Err("reuse created a successor root".into()); }
                                        drop(owner);
                                        fixture.join().map_err(|_| "fixture panic")??;
                                        return Ok(());
                                    }
                                    if automatic_rollover == 45 {
                                        exercise_reuse_refusal(transition, policy, old_key, next_key, expected_effect_digest)?;
                                        let _retained = (pins, offers, expected, source_pins, observations);
                                        drop(owner);
                                        fixture.join().map_err(|_| "fixture panic")??;
                                        return Ok(());
                                    }
                                    let resumed = (*transition).finish_recording(next_storage.ok_or("missing successor storage")?, ContentDigest::sha256(b"preflight retention"), policy, None);
                                    if automatic_rollover == 43 {
                                        let refusal = match resumed {
                                            Err(reconnect::FinishRecordingRefusal::Attach { refusal, listener, tail, previous, retired, attempts, max_attempts, last }) =>
                                                (refusal, listener, tail, previous, retired, attempts, max_attempts, last),
                                            _ => return Err("wrong successor storage was accepted".into()),
                                        };
                                        let (refusal, listener, tail, previous, retired, attempts, max_attempts, last) = refusal;
                                        assert_eq!(previous.key, old_key);
                                        assert_eq!((attempts, max_attempts, last), (2, 2, Some(next_key)));
                                        assert!(retired.is_empty());
                                        let detached = refusal.connected.into_parts();
                                        assert_eq!(detached.pipeline.source_key(), next_key);
                                        assert_eq!(detached.permit.prepared().digest(), expected_effect_digest);
                                        assert_eq!(refusal.storage.coordinator.source_status(), source_worker::Status::Idle);
                                        let _retained = (detached, refusal.storage, listener, tail, previous, retired, offers, source_pins, observations);
                                        drop(owner);
                                        fixture.join().map_err(|_| "fixture panic")??;
                                        return Ok(());
                                    }
                                    let resumed = resumed.map_err(|_| "A/V transition did not finish")?;
                                    assert_eq!(resumed.attempts, 2);
                                    assert_eq!(resumed.max_attempts, 2);
                                    assert_eq!(resumed.last, Some(next_key));
                                    assert!(resumed.retired.is_empty());
                                    assert_eq!(resumed.previous.key, old_key);
                                    let source = resumed.tail.into_parts().map_err(|_| "old tail worker running")?;
                                    assert!(source.plan.is_empty());
                                    let source = source.worker.retire().map_err(|_| "old source worker running")?;
                                    if source.pending.is_some() || source.fenced { return Err("old source custody unresolved".into()); }
                                    let mut source_parts = source.parts;
                                    let old_wire = synthetic_high_flv(4)?;
                                    let mut seen = 0usize;
                                    for (pin, (offset, len, count)) in offers {
                                        let batch = archive::read_unknown_time_source_batch(&mut source_parts.deployment, pin, &ArchiveAccess,
                                            archive::Limits::default(), &mut fss_geometry::WorkBudget::new(4_000_000_000), &source_parts.replay)?;
                                        if batch.payload.len() != len || batch.records.len() != count || batch.records.first().map(|r| r.offset) != Some(offset) {
                                            return Err("old tail readback differs".into());
                                        }
                                        for record in &batch.records {
                                            let length = record.range.end.checked_sub(record.range.start).ok_or("bad old range")?;
                                            if expected.get(seen) != Some(&(record.offset, length, record.disposition)) { return Err("old source metadata changed".into()); }
                                            let start = usize::try_from(record.offset)?;
                                            let end = start.checked_add(length).ok_or("old source overflow")?;
                                            if old_wire.get(start..end) != batch.payload.get(record.range.clone()) { return Err("old source bytes changed".into()); }
                                            seen += 1;
                                        }
                                    }
                                    if seen != expected.len() { return Err("old source readback incomplete".into()); }
                                    let retired = resumed.previous.av.retire().map_err(|_| "old A/V worker running")?;
                                    let mut archive_parts = retired.parts;
                                    for pin in pins {
                                        let clip = archive::read_unknown_time_av_clip(&mut archive_parts.deployment, pin, &ArchiveAccess,
                                            archive::Limits::default(), &mut fss_geometry::WorkBudget::new(4_000_000_000), &archive_parts.replay)?;
                                        if clip.audio().frames == 0 || clip.video_samples() == 0 { return Err("archived segment missing A/V".into()); }
                                        let movie = AvcMp4::parse(clip.bytes(), None, DemuxLimits::default())?;
                                        if !movie.tracks().iter().any(|track| track.handler == *b"soun") { return Err("archived segment lacks audio track".into()); }
                                        let annex = movie.annex_b(0, 1)?;
                                        let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                                        let mut pictures = decoder.decode_annex_b(annex.bytes())?;
                                        pictures.extend(decoder.finish()?);
                                        if pictures.len() != 1 || (pictures[0].width(), pictures[0].height()) != (160, 128) { return Err("archived frame mismatch".into()); }
                                    }
                                    use fss_reference::unifi_direct::http_stream::media_av_startup as next_startup;
                                    let mut next_bootstrap = resumed.startup;
                                    let mut next_source_pins = Vec::new();
                                    let mut next_observations = Vec::new();
                                    let mut ready = false;
                                    for _ in 0..256 {
                                        match next_bootstrap.step(task, cx, clock, Duration::from_secs(2), admission).await {
                                            next_startup::Step::Retained | next_startup::Step::Progress | next_startup::Step::Idle
                                            | next_startup::Step::SourceStarted | next_startup::Step::SourceRunning => (),
                                            next_startup::Step::Buffered(audio) | next_startup::Step::SourceOffered { audio, .. } => next_observations.push(audio),
                                            next_startup::Step::SourceCompleted(done) if done.runtime.is_ok() => match done.outcome {
                                                source_worker::Outcome::Publication(source_worker::Publication::Published { pin, .. }) => next_source_pins.push(pin),
                                                _ => return Err("new bootstrap source publication refused".into()),
                                            },
                                            next_startup::Step::Ready => { ready = true; break; },
                                            next_startup::Step::MediaError(error) => return Err(format!("new bootstrap media: {error:?}").into()),
                                            _ => return Err("new bootstrap stopped".into()),
                                        }
                                    }
                                    if !ready || next_source_pins.is_empty() { return Err("new A/V bootstrap incomplete".into()); }
                                    let mut next_archive = next_bootstrap.finish().map_err(|_| "new A/V archive attach refused")?;
                                    let mut next_pins = Vec::new();
                                    let mut next_ended = false;
                                    for _ in 0..256 {
                                        match next_archive.step(task, cx, clock, Duration::from_secs(2), admission, admission).await {
                                            av_archive::Step::Offer(av_archive::Offer::Source { audio, .. })
                                            | av_archive::Step::Offer(av_archive::Offer::Buffered(audio))
                                            | av_archive::Step::Offer(av_archive::Offer::Segment(audio)) => next_observations.push(audio),
                                            av_archive::Step::SourceStarted | av_archive::Step::SourceRunning
                                            | av_archive::Step::AvStarted | av_archive::Step::AvRunning | av_archive::Step::Idle
                                            | av_archive::Step::Media(fss_reference::unifi_direct::pipeline::Step::Progress { .. }) => (),
                                            av_archive::Step::SourceCompleted(done) if done.runtime.is_ok() => match done.outcome {
                                                source_worker::Outcome::Publication(source_worker::Publication::Published { pin, .. }) => next_source_pins.push(pin),
                                                _ => return Err("new source publication refused".into()),
                                            },
                                            av_archive::Step::AvCompleted(done) if done.runtime.is_ok() => match done.outcome {
                                                av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(value)) => next_pins.push(value.pin),
                                                _ => return Err("new A/V publication refused".into()),
                                            },
                                            av_archive::Step::Media(fss_reference::unifi_direct::pipeline::Step::Eof) => { next_ended = true; break; },
                                            av_archive::Step::MediaError(error) => return Err(format!("new A/V media: {error:?}").into()),
                                            _ => return Err("new A/V recording stopped".into()),
                                        }
                                    }
                                    if !next_ended || next_pins.len() != 2 { return Err("new A/V recording incomplete".into()); }
                                    let next_parts = next_archive.into_parts().map_err(|_| "new archive workers running")?;
                                    assert_eq!(next_parts.key, next_key);
                                    let next_retired = next_parts.prepare_retirement().map_err(|_| "new tail retirement refused")?;
                                    exercise_original_tail_readback(next_retired.tail, task, cx, clock, admission, 4, None).await?;
                                    let next_assets = next_retired.assets;
                                    assert!(next_assets.permit.prepared().effect_class().contains("CAMERA-SETTING"));
                                    assert_eq!(next_assets.permit.prepared().digest(), expected_effect_digest);
                                    let next_worker = next_assets.av.retire().map_err(|_| "new A/V worker running")?;
                                    if next_worker.fenced { return Err("new A/V archive fenced".into()); }
                                    let mut next_archive_parts = next_worker.parts;
                                    for pin in next_pins {
                                        let clip = archive::read_unknown_time_av_clip(&mut next_archive_parts.deployment, pin, &ArchiveAccess,
                                            archive::Limits::default(), &mut fss_geometry::WorkBudget::new(4_000_000_000), &next_archive_parts.replay)?;
                                        if clip.audio().frames == 0 || clip.video_samples() == 0 { return Err("new archive missing A/V".into()); }
                                        let movie = AvcMp4::parse(clip.bytes(), None, DemuxLimits::default())?;
                                        if !movie.tracks().iter().any(|track| track.handler == *b"soun") { return Err("new archive lacks audio track".into()); }
                                        let annex = movie.annex_b(0, 1)?;
                                        let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                                        let mut pictures = decoder.decode_annex_b(annex.bytes())?;
                                        pictures.extend(decoder.finish()?);
                                        if pictures.len() != 1 || (pictures[0].width(), pictures[0].height()) != (160, 128) { return Err("new archived frame mismatch".into()); }
                                    }
                                    let _retained_custody = (next_assets.permit, next_assets.readback, next_assets.comparison,
                                        resumed.listener, resumed.retired, source_parts, archive_parts, next_archive_parts,
                                        source_pins, observations, next_source_pins, next_observations);
                                    drop(owner);
                                    fixture.join().map_err(|_| "fixture panic")??;
                                    return Ok(());
                                }
                                archive_handoff.worker.offer(archive_handoff.first_segment)
                                    .map_err(|_| "audio archive segment refused")?;
                                archive_handoff.worker.start(task, cx, clock, "fixture:camera-replay", &BudgetVector::ZERO)
                                    .map_err(|e| format!("audio archive start: {e:?}"))?;
                                let completion = archive_handoff.worker.join().await.ok_or("audio archive did not complete")?;
                                if completion.runtime.is_err() { return Err("audio archive runtime failed".into()); }
                                let pin = match completion.outcome {
                                    av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(value)) => value.pin,
                                    av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Refused { stage, reason, .. }) => return Err(format!("audio archive refused: {stage:?} {reason:?}").into()),
                                    _ => return Err("audio archive publication did not succeed".into()),
                                };
                                let retired = archive_handoff.worker.retire().map_err(|_| "audio archive worker did not retire")?;
                                if retired.fenced { return Err("audio archive worker fenced".into()); }
                                let mut parts = retired.parts;
                                let clip = archive::read_unknown_time_av_clip(
                                    &mut parts.deployment, pin, &ArchiveAccess, archive::Limits::default(),
                                    &mut fss_geometry::WorkBudget::new(4_000_000_000), &parts.replay,
                                )?;
                                if clip.audio().frames == 0 || clip.video_samples() == 0 {
                                    return Err("archived clip is missing audio or video samples".into());
                                }
                                let movie = AvcMp4::parse(clip.bytes(), None, DemuxLimits::default())?;
                                if !movie.tracks().iter().any(|track| track.handler == *b"soun") {
                                    return Err("archived clip has no audio track".into());
                                }
                                let annex = movie.annex_b(0, 1)?;
                                let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                                let mut pictures = decoder.decode_annex_b(annex.bytes())?;
                                pictures.extend(decoder.finish()?);
                                if pictures.len() != 1 || (pictures[0].width(), pictures[0].height()) != (160, 128) {
                                    return Err("archived audio/video frame mismatch".into());
                                }
                                let _retained_custody = (archive_handoff.connected, archive_handoff.origin, parts, storage.coordinator, forwarded);
                                drop(owner);
                                fixture.join().map_err(|_| "fixture panic")??;
                                return Ok(());
                            }
                            let connected = connected.ok_or("missing connected media")?;
                            if archive_media {
                                Box::pin(archive_http_media(
                                    Some(connected),
                                    None,
                                    task,
                                    cx,
                                    clock,
                                    &dir,
                                    conditions.camera,
                                ))
                                .await?;
                                drop(owner);
                                fixture.join().map_err(|_| "fixture panic")??;
                                return Ok(());
                            }
                            let detached = connected.into_parts();
                            let mut pipeline = detached.pipeline;
                            let mut valid = false;
                            for _ in 0..16 {
                                match timeout(
                                    cx.now(),
                                    Duration::from_secs(5),
                                    pipeline.probe_header_step(task, cx, clock.now()?),
                                )
                                .await??
                                {
                                    fss_reference::unifi_direct::ingress::HeaderProbe::Progress => {
                                    }
                                    fss_reference::unifi_direct::ingress::HeaderProbe::Valid => {
                                        valid = true;
                                        break;
                                    }
                                    _ => return Err("native media fixture header refused".into()),
                                }
                            }
                            assert!(valid);
                            let mut decoded = false;
                            let mut source_records = Vec::new();
                            for _ in 0..128 {
                                let step = timeout(
                                    cx.now(),
                                    Duration::from_secs(10),
                                    pipeline.step(task, cx, clock.now()?),
                                )
                                .await??;
                                match step {
                                    fss_reference::unifi_direct::pipeline::Step::Recording(
                                        recording::Push::Source { record, .. },
                                    ) => source_records.push(record),
                                    fss_reference::unifi_direct::pipeline::Step::Recording(
                                        recording::Push::Segment(segment),
                                    ) => {
                                        let mut mp4 = pipeline
                                            .initialization()
                                            .ok_or("missing synthetic initialization")?
                                            .bytes()
                                            .to_vec();
                                        mp4.extend_from_slice(segment.fragment().bytes());
                                        let movie =
                                            AvcMp4::parse(&mp4, None, DemuxLimits::default())?;
                                        if movie.samples().is_empty() {
                                            return Err("synthetic segment has no samples".into());
                                        }
                                        let annex = movie.annex_b(0, 1)?;
                                        let mut decoder = fss_codec_h264::Decoder::new(
                                            fss_codec_h264::DecoderLimits {
                                                max_pictures: 8,
                                                ..Default::default()
                                            },
                                        )?;
                                        let mut pictures = decoder.decode_annex_b(annex.bytes())?;
                                        pictures.extend(decoder.finish()?);
                                        if pictures.len() != 1
                                            || (pictures[0].width(), pictures[0].height())
                                                != (2688, 1512)
                                        {
                                            return Err(
                                                "synthetic high-resolution decode mismatch".into(),
                                            );
                                        }
                                        decoded = true;
                                        break;
                                    }
                                    fss_reference::unifi_direct::pipeline::Step::Eof
                                    | fss_reference::unifi_direct::pipeline::Step::LimitReached => {
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                            assert!(decoded);
                            assert!(!source_records.is_empty());
                            let _retired = pipeline.retire();
                            drop(owner);
                            fixture.join().map_err(|_| "fixture panic")??;
                            return Ok(());
                        }
                        let denied = owner
                            .dispatch_serializer(
                                &plan,
                                conditions,
                                &observed,
                                Some(&stored),
                                missing.permit,
                                &Guard(true),
                                Duration::from_secs(5),
                            )
                            .await
                            .expect_err("owner must deny write");
                        assert_eq!(denied.reason, HandoffError::Denied);
                        policy.0.set(true);
                        let permit = match owner
                            .dispatch_serializer(
                                &plan,
                                conditions,
                                &observed,
                                Some(&stored),
                                denied.permit,
                                &Guard(true),
                                Duration::from_secs(5),
                            )
                            .await
                            .map_err(|_| "owner dispatch refused")?
                        {
                            HandoffWrite::Written { permit } => permit,
                            _ => return Err("owner write indeterminate".into()),
                        };
                        owner
                            .read_serializer_response_observed(&permit, Duration::from_secs(5))
                            .await?;
                        assert_eq!(owner.phase(), Phase::ReconcileSerializers);
                        assert!(owner.settings(Duration::from_secs(5)).await.is_err());
                        let (_, readback) =
                            owner.settings_serializers(Duration::from_secs(5)).await?;
                        let comparison = plan
                            .observe_readback(&observed, &readback, |p, g| p == peer && g == 1)?;
                        assert_eq!(
                            comparison,
                            if match_request {
                                ReadbackObservation {
                                    change: ReadbackChange::TargetTrackOnly,
                                    requested_fields_match: true,
                                }
                            } else {
                                ReadbackObservation {
                                    change: ReadbackChange::Unchanged,
                                    requested_fields_match: false,
                                }
                            }
                        );
                        assert_eq!(owner.phase(), Phase::Snapshot);
                        if let Some((prepared_restore, restore_conditions, permit)) = restore_parts
                        {
                            let restore = plan.prepare_restore(
                                &observed,
                                &readback,
                                restore_conditions,
                                Framing::ContentLength,
                                |p, g| p == peer && g == 1,
                            )?;
                            assert_eq!(restore.operation(), SerializerOperation::Restore);
                            assert_eq!(restore.request_digest(), prepared_restore.request_digest());
                            let permit = match owner
                                .dispatch_serializer(
                                    &restore,
                                    restore_conditions,
                                    &readback,
                                    None,
                                    permit,
                                    &Guard(true),
                                    Duration::from_secs(5),
                                )
                                .await
                                .map_err(|_| "restore dispatch refused")?
                            {
                                HandoffWrite::Written { permit } => permit,
                                _ => return Err("restore write indeterminate".into()),
                            };
                            owner
                                .read_serializer_response_observed(&permit, Duration::from_secs(5))
                                .await?;
                            let (_, restored) =
                                owner.settings_serializers(Duration::from_secs(5)).await?;
                            assert_eq!(
                                observed.binding(|_, _| true)?,
                                restored.binding(|_, _| true)?
                            );
                            assert!(
                                restore
                                    .observe_readback(&readback, &restored, |p, g| p == peer
                                        && g == 1)?
                                    .requested_fields_match
                            );
                        }
                        drop(owner);
                        fixture.join().map_err(|_| "fixture panic")??;
                        return Ok(());
                    }
                    let bytes = Rc::new(RefCell::new(Vec::new()));
                    let polled = Rc::new(Cell::new(false));
                    let mut io = MeteredIo::with_clock(
                        Sink {
                            bytes: bytes.clone(),
                            polled: polled.clone(),
                            partial,
                        },
                        clock,
                        "fixture:camera",
                        4096,
                    )?;
                    let missing = session
                        .dispatch_serializer(
                            cx,
                            &mut io,
                            &plan,
                            conditions,
                            &baseline,
                            None,
                            permit,
                            &Guard(true),
                            Duration::from_secs(1),
                        )
                        .await
                        .expect_err("missing checkpoint must not write");
                    assert_eq!(missing.reason, HandoffError::CheckpointRequired);
                    assert!(!polled.get());
                    let wrong = session
                        .dispatch_serializer(
                            cx,
                            &mut io,
                            &plan,
                            conditions,
                            &baseline,
                            Some(&other_stored),
                            missing.permit,
                            &Guard(true),
                            Duration::from_secs(1),
                        )
                        .await
                        .expect_err("mismatched checkpoint must not write");
                    assert_eq!(wrong.reason, HandoffError::CheckpointRequired);
                    assert!(!polled.get());
                    let refusal = session
                        .dispatch_serializer(
                            cx,
                            &mut io,
                            &plan,
                            conditions,
                            &baseline,
                            Some(&stored),
                            wrong.permit,
                            &Guard(false),
                            Duration::from_secs(1),
                        )
                        .await
                        .expect_err("denied must not write");
                    assert_eq!(refusal.reason, HandoffError::Denied);
                    assert!(!polled.get());
                    let stale = Preconditions {
                        lease_fence: fence + 1,
                        ..conditions
                    };
                    let refusal = session
                        .dispatch_serializer(
                            cx,
                            &mut io,
                            &plan,
                            stale,
                            &baseline,
                            Some(&stored),
                            refusal.permit,
                            &Guard(true),
                            Duration::from_secs(1),
                        )
                        .await
                        .expect_err("stale fence must not write");
                    assert_eq!(refusal.reason, HandoffError::Stale);
                    assert!(!polled.get());
                    let refusal = session
                        .dispatch_serializer(
                            cx,
                            &mut io,
                            &plan,
                            conditions,
                            &changed,
                            Some(&stored),
                            refusal.permit,
                            &Guard(true),
                            Duration::from_secs(1),
                        )
                        .await
                        .expect_err("changed other track must not write");
                    assert_eq!(refusal.reason, HandoffError::Stale);
                    assert!(!polled.get());
                    let result = session
                        .dispatch_serializer(
                            cx,
                            &mut io,
                            &plan,
                            conditions,
                            &baseline,
                            Some(&stored),
                            refusal.permit,
                            &Guard(true),
                            Duration::from_millis(if partial { 50 } else { 1000 }),
                        )
                        .await
                        .map_err(|_| "dispatch refused")?;
                    if partial {
                        let mut permit = match result {
                            HandoffWrite::Indeterminate { permit } => permit,
                            _ => return Err("partial write was reported complete".into()),
                        };
                        assert!(!permit.try_claim_dispatch());
                        assert_eq!(bytes.borrow().len(), 1);
                        assert_eq!(session.phase(), Phase::Fenced);
                    } else {
                        let mut permit = match result {
                            HandoffWrite::Written { permit } => permit,
                            _ => return Err("unexpected partial write".into()),
                        };
                        assert!(!permit.try_claim_dispatch());
                        let wire = bytes.borrow();
                        let text = std::str::from_utf8(&wire)?;
                        assert!(text.starts_with("PUT /api/1.1/settings HTTP/1.1\r\n"));
                        assert!(text.contains("\"video1\":{\"avSerializer\":"));
                        assert!(!text.contains("\"controller\""));
                        assert!(!text.contains("\"video2\""));
                        drop(wire);
                        if bad_response {
                            assert!(
                                session
                                    .accept_serializer_response_observed(Response::new(
                                        503,
                                        "Unavailable",
                                        Vec::new()
                                    ))
                                    .is_err()
                            );
                            assert_eq!(session.phase(), Phase::Fenced);
                            return Ok(());
                        }
                        session.accept_serializer_response_observed(Response::new(
                            200,
                            "OK",
                            b"{}".to_vec(),
                        ))?;
                        assert_eq!(session.phase(), Phase::ReconcileSerializers);
                        assert!(session.prepare_settings().is_err());
                        assert!(session.prepare_status().is_err());
                        let r = session.prepare_serializer_settings()?;
                        session.finish_write(r, WriteOutcome::NotWritten)?;
                        assert_eq!(session.phase(), Phase::ReconcileSerializers);
                        let r = session.prepare_serializer_settings()?;
                        session.finish_write(r, WriteOutcome::Written)?;
                        session.accept_settings_with_serializers(Response::new(
                            200,
                            "OK",
                            b"{}".to_vec(),
                        ))?;
                        assert_eq!(session.phase(), Phase::Snapshot);
                    }
                    Ok(())
                })
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(59_000_000_000),
                }
            },
        )
        .await?;
        run.receipt?;
        run.output
    })?;
    let receipt = effects.journal().operation(&op).ok_or("missing journal")?;
    let recorded_response = owned && match_request && native_media
        && ((combined_start && archive_media) || matches!(audio_mode, 10 | 11));
    assert_eq!(receipt.state, if recorded_response {
        fss_core::EffectState::AdapterAccepted
    } else {
        fss_core::EffectState::Committed
    });
    if recorded_response {
        let prepared = effects.prepared(&op).ok_or("missing preparation")?;
        let expected = trial_http_checkpoint::response_receipt(
            "fss.unifi-direct.http-start-response.v1", prepared.digest(),
            fss_reference::unifi_direct::camera_api::HandoffResponseObservation::Object { success: None, status_code: None },
        );
        assert_eq!(receipt.result_digest, Some(expected));
    }
    let acceptance_digest = receipt.result_digest;
    if owned && match_request && !native_media {
        assert_eq!(
            effects
                .journal()
                .operation(&restore_op)
                .ok_or("missing restore journal")?
                .state,
            fss_core::EffectState::Committed
        );
    }
    let verified = !owned && !partial && !bad_response;
    if verified {
        let handle = effects.prepared(&op).ok_or("missing preparation")?;
        let proof = ContentDigest::sha256(b"independent synthetic observation");
        effects.reconcile(
            &mut tree,
            &authority,
            &handle,
            Reconciliation::Indeterminate("fixture ambiguous write"),
            TimestampNs(60_000_000_000),
        )?;
        effects.reconcile(
            &mut tree,
            &authority,
            &handle,
            Reconciliation::Observed(proof),
            TimestampNs(61_000_000_000),
        )?;
        effects.reconcile(
            &mut tree,
            &authority,
            &handle,
            Reconciliation::Verified(proof),
            TimestampNs(62_000_000_000),
        )?;
    }
    let head = effects.durable_pin().ok_or("missing journal pin")?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        assert!(
            checkpoint_scope
                .match_recovered_journal(
                    &cx,
                    &CheckpointPolicy(true),
                    &effects,
                    &op,
                    head,
                    forward_preparation
                )
                .is_err()
        );
        Ok::<(), Box<dyn Error>>(())
    })?;
    drop(effects);
    let journal = FileEffectJournal::open(
        dir.join("journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        head,
    )?;
    let recovered = EffectCoordinator::recover(Box::new(journal), head)?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        assert_eq!(
            checkpoint_scope.match_recovered_journal(
                &cx,
                &CheckpointPolicy(true),
                &recovered,
                &op,
                head,
                forward_preparation
            )?,
            if verified { fss_core::EffectState::Verified } else if recorded_response {
                fss_core::EffectState::AdapterAccepted
            } else { fss_core::EffectState::Committed }
        );
        if recorded_response {
            assert_eq!(recovered.journal().operation(&op).and_then(|receipt| receipt.result_digest), acceptance_digest);
        }
        assert!(
            checkpoint_scope
                .match_recovered_journal(
                    &cx,
                    &CheckpointPolicy(false),
                    &recovered,
                    &op,
                    head,
                    forward_preparation
                )
                .is_err()
        );
        assert!(
            checkpoint_scope
                .match_recovered_journal(
                    &cx,
                    &CheckpointPolicy(true),
                    &recovered,
                    &op,
                    head,
                    ContentDigest::sha256(b"wrong preparation")
                )
                .is_err()
        );
        let wrong_head = fss_runtime::effect_journal::EffectJournalPin {
            sequence: head.sequence,
            root: ContentDigest::sha256(b"wrong head"),
        };
        assert!(
            checkpoint_scope
                .match_recovered_journal(
                    &cx,
                    &CheckpointPolicy(true),
                    &recovered,
                    &op,
                    wrong_head,
                    forward_preparation
                )
                .is_err()
        );
        let changed_conditions = Preconditions {
            peer_admission: ContentDigest::sha256(b"other admission"),
            ..conditions
        };
        let changed_plan = Plan::new(
            peer,
            &start,
            changed_conditions,
            &baseline,
            Framing::ContentLength,
        )?;
        let changed_scope = checkpoint::Scope::from_plan(
            &changed_plan,
            ContentDigest::sha256(b"fixture certificate"),
        )?;
        assert!(
            changed_scope
                .match_recovered_journal(
                    &cx,
                    &CheckpointPolicy(true),
                    &recovered,
                    &op,
                    head,
                    forward_preparation
                )
                .is_err()
        );
        if owned && match_request {
            assert!(
                checkpoint_scope
                    .match_recovered_journal(
                        &cx,
                        &CheckpointPolicy(true),
                        &recovered,
                        &restore_op,
                        head,
                        forward_preparation
                    )
                    .is_err()
            );
        }
        let retained = checkpoint::Sealed::from_bytes(sealed.bytes())?.open(&cx, &CheckpointPolicy(true), checkpoint_scope, &key)?;
        let peer2 = Ipv4Addr::new(192, 168, 42, 12);
        let after = serializer_snapshot(peer2, 2, br#"{"av":{"video":{"video1":{"avSerializer":{"type":"extendedFlv","parameters":{"streamName":"0123456789abcdef","withOpus":false},"destinations":["tcp://192.168.42.11:17777?retryInterval=1&connectTimeout=5"]}},"video2":{"avSerializer":{"destinations":["tcp://fixture:1"]}}}}}"#)?;
        let current = Preconditions { session_generation: 2, serializers: after.binding(|_, _| true)?, ..conditions };
        let context = checkpoint::RestoreContext { camera, certificate: ContentDigest::sha256(b"fixture certificate"), peer: peer2, forward: &start, original_peer: peer, original_generation: 1, original_framing: Framing::ContentLength, current, framing: Framing::ContentLength, original_owner: &recovered, original_operation: &op, journal_head: head, preparation: forward_preparation };
        let admitted = |p, g| p == peer2 && g == 2;
        if verified {
            let result = retained.prepare_verified_restore(&cx, &CheckpointPolicy(true), context, &after, admitted)?;
            assert_eq!(result.operation(), SerializerOperation::Restore);
            let before2 = serializer_snapshot(peer2, 2, br#"{"av":{"video":{"video1":{"avSerializer":null},"video2":{"avSerializer":{"destinations":["tcp://fixture:1"]}}}}}"#)?;
            let before_conditions = Preconditions { serializers: before2.binding(|_, _| true)?, ..current };
            let independent = Plan::new(peer2, &start, before_conditions, &before2, Framing::ContentLength)?.prepare_restore(&before2, &after, current, Framing::ContentLength, admitted)?;
            assert_eq!(result.request_digest(), independent.request_digest());
            assert_eq!(result.precondition_digest(), independent.precondition_digest());
            let changed = serializer_snapshot(peer2, 2, br#"{"av":{"video":{"video1":{"avSerializer":{}},"video2":{"avSerializer":{}}}}}"#)?;
            assert!(retained.prepare_verified_restore(&cx, &CheckpointPolicy(true), context, &changed, admitted).is_err());
            assert!(retained.prepare_verified_restore(&cx, &CheckpointPolicy(true), context, &after, |_, _| false).is_err());
            let wrong = checkpoint::RestoreContext { certificate: ContentDigest::sha256(b"wrong"), ..context };
            assert!(retained.prepare_verified_restore(&cx, &CheckpointPolicy(true), wrong, &after, admitted).is_err());
            let other_codec = StreamStart::new(VideoChannel::Video1, listener, VideoCodec::H265, AudioCodec::Aac, "0123456789abcdef")?;
            let wrong = checkpoint::RestoreContext { forward: &other_codec, ..context };
            assert!(retained.prepare_verified_restore(&cx, &CheckpointPolicy(true), wrong, &after, admitted).is_err());
            let wrong = checkpoint::RestoreContext { original_generation: 2, ..context };
            assert!(retained.prepare_verified_restore(&cx, &CheckpointPolicy(true), wrong, &after, admitted).is_err());
        } else {
            assert!(retained.prepare_verified_restore(&cx, &CheckpointPolicy(true), context, &after, admitted).is_err());
        }
        Ok::<(), Box<dyn Error>>(())
    })?;
    Ok(())
}
#[test]
fn av_trailer_mismatch_is_retirable_but_other_framing_refusals_are_not() {
    use fss_packet::extended_flv::stream::Error as FramingError;
    use fss_reference::unifi_direct::{http_stream::{media_av_archive, media_av_startup}, ingress, pipeline};

    let mismatch = pipeline::Error::Ingress(ingress::Error::Framing(FramingError::TrailerPolicyMismatch));
    assert!(media_av_archive::Step::MediaError(mismatch).has_retirable_tail());
    let mismatch = pipeline::Error::Ingress(ingress::Error::Framing(FramingError::TrailerPolicyMismatch));
    assert!(media_av_startup::Step::MediaError(mismatch).has_retirable_tail());
    let other = pipeline::Error::Ingress(ingress::Error::Framing(FramingError::BufferLimit));
    assert!(!media_av_archive::Step::MediaError(other).has_retirable_tail());
    let other = pipeline::Error::Ingress(ingress::Error::Framing(FramingError::BufferLimit));
    assert!(!media_av_startup::Step::MediaError(other).has_retirable_tail());
}
