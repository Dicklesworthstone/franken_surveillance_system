#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Synthetic journaled local serializer dispatch and reconciliation contracts.
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
        source: SourceKey {
            connection: 1,
            generation: 1,
        },
        camera_claim: camera,
        source_retention: retention,
        source_scope: ContentDigest::sha256(b"preflight source"),
        av_scope: ContentDigest::sha256(b"preflight video"),
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
fn synthetic_high_flv() -> std::io::Result<Vec<u8>> {
    const SOURCE: &[u8] = include_bytes!(
        "../../../experiments/unifi_tls_05_server_lab/tests/fixtures/synthetic_g4_resolution.264"
    );
    let nals: Vec<_> = fss_codec_h264::annex_b_nal_units(SOURCE).collect();
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
    let pictures: Vec<_> = nals.iter().copied().filter(|n| n[0] & 31 == 5).collect();
    if pictures.len() != 4 {
        return Err(std::io::Error::other("fixture IDR count"));
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
    let mut wire = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    wire.extend(flv_tag(9, 0, &avc)?);
    for (i, picture) in pictures.iter().enumerate() {
        let mut data = vec![0x17, 1, 0, 0, 0];
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
    }
    Ok(wire)
}
fn fixture_server(
    address: std::net::SocketAddr,
    match_request: bool,
    media_target: Option<SocketAddrV4>,
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
        if index == 4
            && let Some(target) = media_target
        {
            let mut media =
                std::net::TcpStream::connect_timeout(&target.into(), Duration::from_secs(5))?;
            if match_request {
                media.write_all(&synthetic_high_flv()?)?;
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
    exercise(false, false, false, false, false, false, false)
}
#[test]
fn partial_write_fences_and_leaves_effect_open() -> Test {
    exercise(true, false, false, false, false, false, false)
}
#[test]
fn unsuccessful_response_fences_and_leaves_effect_open() -> Test {
    exercise(false, true, false, false, false, false, false)
}
#[test]
fn owned_http_checks_policy_and_requires_private_readback() -> Test {
    exercise(false, false, true, false, false, false, false)
}
#[test]
fn owned_http_observes_requested_fields_without_settling() -> Test {
    exercise(false, false, true, true, false, false, false)
}
#[test]
fn owned_http_starts_native_media_listener() -> Test {
    exercise(false, false, true, true, true, false, false)
}
#[test]
fn owned_http_refuses_unmatched_readback_before_media_accept() -> Test {
    exercise(false, false, true, false, true, false, false)
}

#[test]
fn owned_http_media_publishes_and_reads_native_video() -> Test {
    exercise(false, false, true, true, true, true, false)
}

#[test]
fn owned_http_archive_starts_media_with_preflight() -> Test {
    exercise(false, false, true, true, true, false, true)
}

async fn archive_http_media<'scope, 'task>(
    connected: media::Connected,
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
            http_stream::media_archive::{Driver, Step},
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
    let mut driver = Driver::attach(connected, pending.storage, policy, camera)
        .map_err(|_| "HTTP media archive attachment refused")?;
    let cost = BudgetVector::ZERO;
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
        let event = timeout(
            cx.now(),
            Duration::from_secs(30),
            driver.step(
                task,
                cx,
                clock,
                if release.is_some() {
                    Duration::from_millis(50)
                } else {
                    Duration::from_secs(5)
                },
                ArchiveAdmission {
                    resource: "fixture:archive",
                    cost: &cost,
                },
                ArchiveAdmission {
                    resource: "fixture:archive",
                    cost: &cost,
                },
            ),
        )
        .await?;
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

fn exercise(
    partial: bool,
    bad_response: bool,
    owned: bool,
    match_request: bool,
    native_media: bool,
    archive_media: bool,
    combined_start: bool,
) -> Test {
    let dir = std::env::temp_dir().join(format!(
        "fss-http-serializer-{}-{}-{}-{}-{}-{}-{}-{}",
        std::process::id(),
        partial,
        bad_response,
        owned,
        match_request,
        native_media,
        archive_media,
        combined_start
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
    budget.network_bytes = 1_000_000;
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
    let runtime = if archive_media || combined_start {
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
                let output: Test = async {
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
                            fixture_server(address, match_request, native_media.then_some(listener))
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
                                let expected = if archive_media || combined_start {
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
                            let result = if combined_start {
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
                                let parts = driver
                                    .into_parts()
                                    .map_err(|_| "new driver unexpectedly running")?;
                                Ok(parts.connected)
                            } else {
                                media::start(
                                    &mut owner,
                                    native_listener.as_mut().ok_or("missing media listener")?,
                                    request,
                                    permit,
                                    |p, g| p == peer && g == 1,
                                )
                                .await
                            };
                            if !match_request {
                                let refusal = match result {
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
                            let connected = result.map_err(|_| "native media startup refused")?;
                            assert_eq!(
                                connected.comparison().change,
                                ReadbackChange::TargetTrackOnly
                            );
                            assert!(connected.comparison().requested_fields_match);
                            if archive_media {
                                archive_http_media(
                                    connected,
                                    task,
                                    cx,
                                    clock,
                                    &dir,
                                    conditions.camera,
                                )
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
                }
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
    assert_eq!(
        effects
            .journal()
            .operation(&op)
            .ok_or("missing journal")?
            .state,
        fss_core::EffectState::Committed
    );
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
            if verified { fss_core::EffectState::Verified } else { fss_core::EffectState::Committed }
        );
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
