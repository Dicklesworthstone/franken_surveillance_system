#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]
//! Synthetic two-camera fleet route over task-owned experimental TLS.
use asupersync::runtime::RuntimeBuilder;
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_object::{
    HostSpoolIo,
    effect_journal::{EffectJournalLimits, FileEffectJournal},
};
use fss_reference::unifi_direct::{
    Controller, Identity, camera_api, camera_http, controller_listener, discovery, handoff,
    listener,
    metered::{MeteredClock, MeteredIo},
    owner::PeerAdmission,
    setup,
    upgrade::ProtocolPolicy,
};
use fss_runtime::{
    authority::AuthorityCx,
    effect::{CommitApproval, CommittedEffect, EffectCoordinator, PreparedEffect},
    execution::{TaskCompletion, TaskSpec, run_owned_async},
    lease::LeaseRegistry,
};
use fss_unifi_scoped_tls_entropy_lab::{camera_setup, camera_tls_owned};
#[path = "support/stream.rs"]
mod stream_fixture;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    cell::RefCell,
    error::Error,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    sync::Arc,
    thread::JoinHandle,
    time::{Duration, Instant},
};
type Test = Result<(), Box<dyn Error>>;
async fn acquire<'scope, 'task>(
    task: &'scope fss_runtime::execution::TaskCx<'task>,
    cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
    resource: &'scope str,
) -> Result<fss_unifi_scoped_tls_entropy_lab::owned::offload::Lease<'scope, 'task>, Box<dyn Error>>
{
    let mut owner = fss_unifi_scoped_tls_entropy_lab::owned::offload::Acquisition::begin(
        task, cx, clock, resource, 128,
    )?;
    match asupersync::time::timeout(cx.now(), Duration::from_secs(5), owner.join()).await {
        Ok(result) => Ok(result?),
        Err(_) => {
            owner.abort();
            let _ = owner.join().await;
            Err("entropy worker deadline".into())
        }
    }
}
const MAC: [u8; 6] = [0, 0x11, 0x22, 0xaa, 0xbb, 0xcc];
const HEAD: &str = "GET / HTTP/1.1\r\nHost: camera.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nCamera-Mac: 001122aabbcc\r\nSec-WebSocket-Protocol: secure_transfer\r\n\r\n";
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ReleaseOnDrop(Arc<std::sync::atomic::AtomicBool>);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}

/// Fixture threads are joined even when the asynchronous test returns early.
struct Joined(Option<JoinHandle<io::Result<()>>>);
impl Joined {
    fn finish(mut self) -> Test {
        self.0
            .take()
            .ok_or("missing fixture thread")?
            .join()
            .map_err(|_| "fixture panic")??;
        Ok(())
    }
}
impl Drop for Joined {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            let _ = handle.join();
        }
    }
}

struct Approval;
impl fss_reference::unifi_direct::conversation::Approval for Approval {
    fn approve(&self, prepared: &PreparedEffect) -> Option<CommitApproval> {
        Some(CommitApproval {
            prepared_digest: prepared.digest(),
            current_precondition_digest: prepared.precondition_digest(),
        })
    }
}
struct SlowApproval;
static SLOW_APPROVAL: SlowApproval = SlowApproval;
impl fss_reference::unifi_direct::conversation::Approval for SlowApproval {
    fn approve(&self, prepared: &PreparedEffect) -> Option<CommitApproval> {
        std::thread::sleep(Duration::from_secs(4));
        Some(CommitApproval {
            prepared_digest: prepared.digest(),
            current_precondition_digest: prepared.precondition_digest(),
        })
    }
}
struct Handoff;
impl camera_api::HandoffAuthority for Handoff {
    fn permits(
        &self,
        plan: &handoff::Plan,
        current: handoff::Preconditions,
        permit: &CommittedEffect,
    ) -> bool {
        plan.check_current(current).is_ok() && permit.fence() == plan.fence()
    }
}

fn discovery_packet_for(peer: Ipv4Addr, mac: [u8; 6]) -> Vec<u8> {
    let mut address = Vec::from(mac);
    address.extend_from_slice(&peer.octets());
    let mut body = Vec::new();
    for (kind, value) in [
        (1, mac.as_slice()),
        (2, address.as_slice()),
        (3, b"UVC.fixture".as_slice()),
        (12, b"UVC G4 Instant".as_slice()),
    ] {
        body.push(kind);
        body.extend_from_slice(&(value.len() as u16).to_be_bytes());
        body.extend_from_slice(value);
    }
    let mut packet = vec![1, 0];
    packet.extend_from_slice(&(body.len() as u16).to_be_bytes());
    packet.extend_from_slice(&body);
    packet
}

fn request(socket: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        socket.read_exact(&mut byte)?;
        bytes.push(byte[0]);
        if bytes.len() > 8192 {
            return Err(io::Error::other("fixture header limit"));
        }
    }
    let text = std::str::from_utf8(&bytes).map_err(io::Error::other)?;
    let length = text
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .map_or(Ok(0), str::parse::<usize>)
        .map_err(io::Error::other)?;
    if length > 4096 {
        return Err(io::Error::other("fixture body limit"));
    }
    let start = bytes.len();
    bytes.resize(start + length, 0);
    socket.read_exact(&mut bytes[start..])?;
    Ok(bytes)
}

fn camera_fixture(
    listener: std::net::TcpListener,
    port: u16,
    peer: Ipv4Addr,
    config: Arc<ServerConfig>,
) -> io::Result<()> {
    camera_fixture_with_gate(listener, port, peer, config, None, None, false, false)
}

/// Reject login or close early before any camera-management effect is prepared.
fn camera_reject_login(
    listener: std::net::TcpListener,
    config: Arc<ServerConfig>,
    deny_credentials: bool,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    };
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    socket.set_write_timeout(Some(Duration::from_secs(10)))?;
    let tls = rustls::ServerConnection::new(config).map_err(io::Error::other)?;
    let mut socket = StreamOwned::new(tls, socket);
    if !request(&mut socket)?.starts_with(b"POST /api/1.1/login ") {
        return Err(io::Error::other("expected login"));
    }
    if !deny_credentials {
        socket.conn.send_close_notify();
        return socket.flush();
    }
    socket
        .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
    socket.flush()
}

fn camera_fixture_with_gate(
    listener: std::net::TcpListener,
    port: u16,
    peer: Ipv4Addr,
    config: Arc<ServerConfig>,
    gate: Option<Arc<std::sync::atomic::AtomicBool>>,
    login_seen: Option<Arc<std::sync::atomic::AtomicBool>>,
    changed_readback: bool,
    stop_before_handoff: bool,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let (socket, _) = loop {
        match listener.accept() {
            Ok(connection) => break connection,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "fixture accept timed out",
                ));
            }
            Err(error) => return Err(error),
        }
    };
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(Duration::from_secs(15)))?;
    socket.set_write_timeout(Some(Duration::from_secs(15)))?;
    let tls = rustls::ServerConnection::new(config).map_err(io::Error::other)?;
    let mut socket = StreamOwned::new(tls, socket);
    let routes = [
        "POST /api/1.1/login ",
        "GET /api/1.1/status ",
        "GET /api/1.1/settings ",
        "GET /api/1.1/settings ",
        "PUT /api/1.1/settings ",
        "GET /api/1.1/settings ",
    ];
    for (index, route) in routes.iter().enumerate() {
        let message = request(&mut socket)?;
        if !message.starts_with(route.as_bytes()) {
            return Err(io::Error::other("fixture route mismatch"));
        }
        if index > 0
            && !message
                .windows(b"Cookie: authId=fixture-cookie".len())
                .any(|w| w == b"Cookie: authId=fixture-cookie")
        {
            return Err(io::Error::other("fixture cookie missing"));
        }
        if index == 4
            && !message.ends_with(format!(r#"{{"controller":{{"addr":"{peer}"}}}}"#).as_bytes())
        {
            return Err(io::Error::other("fixture destination mismatch"));
        }
        if index == 0 {
            if let Some(gate) = &gate {
                if let Some(login_seen) = &login_seen {
                    login_seen.store(true, std::sync::atomic::Ordering::Release);
                }
                let deadline = Instant::now() + Duration::from_secs(10);
                while !gate.load(std::sync::atomic::Ordering::Acquire) {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "parallel route did not complete",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
        let body = match index {
            1 => format!(r#"{{"controller":{{"port":{port}}}}}"#),
            2 | 3 | 5 => {
                let controller = if index == 5 {
                    peer.to_string()
                } else {
                    "192.168.1.10".to_owned()
                };
                let (width, height) = if changed_readback && index == 5 { (80, 64) } else { (160, 128) };
                format!(
                    r#"{{"controller":{{"addr":"{controller}"}},"av":{{"video":{{"video1":{{"width":2688,"height":1512,"fps":25}},"video2":{{"width":{width},"height":{height},"fps":25}},"video3":{{"width":64,"height":64,"fps":15}}}}}}}}"#
                )
            }
            4 => r#"{"success":true}"#.to_owned(),
            _ => "{}".to_owned(),
        };
        let cookie = if index == 0 {
            "Set-Cookie: authId=fixture-cookie\r\n"
        } else {
            ""
        };
        write!(
            socket,
            "HTTP/1.1 200 OK\r\n{cookie}Content-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
            body.len()
        )?;
        if stop_before_handoff && index == 3 {
            socket.flush()?;
            let mut byte = [0_u8; 1];
            return match socket.read(&mut byte) {
                Ok(0) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
                Ok(_) => Err(io::Error::other("unexpected handoff after deadline")),
                Err(error) => Err(error),
            };
        }
    }
    Ok(())
}

fn camera_upgrade_peer(
    endpoint: SocketAddrV4,
    peer: Ipv4Addr,
    config: Arc<ClientConfig>,
    mac_hex: &'static str,
) -> io::Result<()> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.bind(&SocketAddr::V4(SocketAddrV4::new(peer, 0)).into())?;
    socket.connect_timeout(&SocketAddr::V4(endpoint).into(), Duration::from_secs(5))?;
    let raw: std::net::TcpStream = socket.into();
    raw.set_read_timeout(Some(Duration::from_secs(10)))?;
    raw.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut tls = StreamOwned::new(
        ClientConnection::new(
            config,
            ServerName::try_from("localhost").map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)?,
        raw,
    );
    tls.write_all(HEAD.replace("001122aabbcc", mac_hex).as_bytes())?;
    tls.flush()?;
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        tls.read_exact(&mut byte)?;
        response.push(byte[0]);
        if response.len() > 4096 {
            return Err(io::Error::other("upgrade response limit"));
        }
    }
    if !response.starts_with(b"HTTP/1.1 101 ") {
        return Err(io::Error::other("upgrade refused"));
    }
    Ok(())
}

fn profile_limits(full_resolution: bool) -> fss_reference::unifi_direct::camera_api::VideoProfileLimits {
    use fss_reference::unifi_direct::camera_api::VideoProfileLimits;
    VideoProfileLimits { max_width: if full_resolution { 2688 } else { 160 }, max_height: if full_resolution { 1512 } else { 128 }, min_fps: 1, max_fps: 30, max_pixels_per_second: 2688 * 1512 * 30 }
}

fn parallel_fleet_upgrade_scenario(
    peer: Ipv4Addr,
    cert: &[u8],
    key: &[u8],
    capacity: usize,
    full_resolution: bool,
    changed_readback: bool,
) -> Test {
    eprintln!("fleet_fixture scenario capacity={capacity} full_resolution={full_resolution} changed_readback={changed_readback}");
    use asupersync::{io::AsyncReadExt, time::timeout};
    use fss_container::{
        demux::{AvcMp4, DemuxLimits},
        flv_avc::SourceKey,
    };
    use fss_packet::extended_flv::{Limits as FlvLimits, stream::Framer};
    use fss_reference::unifi_direct::controller_acceptor::{
        Acceptor as FleetAcceptor, ConfigurationError, Event,
    };
    use fss_reference::unifi_direct::discovery::{
        fleet::{Enrollment, Fleet, Router},
        pump::{CameraWork, CameraWorkSet, Event as PumpEvent, Progress, Pump},
        scan::{Outcome as ScanOutcome, Scanner},
    };
    use fss_reference::unifi_direct::{
        AudioCodec, VideoChannel, VideoCodec, archive, conversation, evidence, intent, management,
        pipeline, receive, recording, recording_storage, retirement_source, source_coordinator,
        source_worker, supervisor, video_bootstrap, video_session, video_worker,
    };
    use fss_unifi_scoped_tls_entropy_lab::fleet_leased::{
        ActiveStreams, AutoRoutedFleetEvent, AutomaticEvent, AutomaticWork, FleetLeased, FleetResources,
        FleetStreamEvent, LeaseSupply, RearmRefusal, RetryCompletion, RetryCoordinator,
        RoutedStreamAdmission, RoutedStreamRefusal, RoutedTransport, StreamCompletionRefusal, TrackedStreamWork,
        RetryLoopError, RetrySelection, RetryingFleetEvent, StreamRefusal, Supervised, SupplyEvent,
    };
    use std::{
        cell::Cell,
        future::{Future, poll_fn},
        rc::Rc,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        task::{Context, Poll, Wake, Waker},
    };

    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    const MACS: [[u8; 6]; 3] = [
        MAC,
        [0, 0x11, 0x22, 0xaa, 0xbb, 0xdd],
        [0, 0x11, 0x22, 0xaa, 0xbb, 0xee],
    ];
    const PEERS: [Ipv4Addr; 3] = [
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::new(127, 0, 0, 2),
        Ipv4Addr::new(127, 0, 0, 3),
    ];
    struct PairPolicy {
        listen: Ipv4Addr,
        cameras: [ContentDigest; 3],
        admissions: [ContentDigest; 3],
        fences: [u64; 3],
        resources: [String; 3],
    }
    impl setup::Admission for PairPolicy {
        fn permits(
            &self,
            candidate: &discovery::CameraCandidate,
            camera: ContentDigest,
            admission: ContentDigest,
            generation: u64,
            fence: u64,
        ) -> bool {
            (0..3).any(|i| {
                *candidate.source().ip() == PEERS[i]
                    && candidate.mac() == Some(MACS[i])
                    && camera == self.cameras[i]
                    && admission == self.admissions[i]
                    && generation == 1
                    && fence == self.fences[i]
            })
        }
    }
    impl camera_http::Authority for PairPolicy {
        fn permits(&self, source: Ipv4Addr, generation: u64, _: camera_http::Operation) -> bool {
            PEERS.contains(&source) && generation == 1
        }
    }
    impl listener::Admission for PairPolicy {
        fn listener(&self, requested: SocketAddrV4, bound: Option<SocketAddrV4>) -> bool {
            *requested.ip() == self.listen
                && bound.is_none_or(|v| *v.ip() == self.listen && v.port() != 0)
        }
        fn peer(&self, bound: SocketAddrV4, source: SocketAddrV4) -> bool {
            *bound.ip() == self.listen && PEERS.contains(source.ip())
        }
        fn controller_camera(
            &self,
            bound: SocketAddrV4,
            listener_resource: &str,
            camera_resource: &str,
            source: Ipv4Addr,
        ) -> bool {
            *bound.ip() == self.listen
                && listener_resource == "fixture:parallel-controller"
                && (0..3).any(|i| source == PEERS[i] && camera_resource == self.resources[i])
        }
    }
    impl PeerAdmission for PairPolicy {
        fn permits(&self, mac: [u8; 6]) -> bool {
            MACS.contains(&mac)
        }
    }
    struct Guard<'a, 'scope, 'task> {
        leases: &'a RefCell<LeaseRegistry>,
        clock: MeteredClock<'scope, 'task>,
        mac: [u8; 6],
    }
    impl receive::ManagementAuthority for Guard<'_, '_, '_> {
        fn permits(
            &self,
            mac: [u8; 6],
            intent: management::Intent,
            permit: &CommittedEffect,
        ) -> bool {
            mac == self.mac
                && permit.fence() == intent.fence()
                && self.clock.now().ok().is_some_and(|now| {
                    self.leases
                        .borrow_mut()
                        .check_fence(&intent.resource(), intent.fence(), now)
                        .is_ok()
                })
        }
    }
    impl receive::StreamAuthority for Guard<'_, '_, '_> {
        fn permits(&self, mac: [u8; 6], intent: intent::Intent, permit: &CommittedEffect) -> bool {
            mac == self.mac
                && permit.fence() == intent.fence()
                && self.clock.now().ok().is_some_and(|now| {
                    self.leases
                        .borrow_mut()
                        .check_fence(&intent.resource(), intent.fence(), now)
                        .is_ok()
                })
        }
    }
    struct Wall;
    impl conversation::WallClock for Wall {
        fn observe(&self) -> Option<conversation::WallTime> {
            Some(conversation::WallTime {
                unix_ms: 1_700_000_000_000,
                timestamp: "2026-11-05T10:00:00.000Z".into(),
            })
        }
    }
    struct AutoMedia<'scope, 'task> {
        cx: &'scope asupersync::Cx,
        task: &'scope fss_runtime::execution::TaskCx<'task>,
        clock: MeteredClock<'scope, 'task>,
        effects: Option<EffectCoordinator>,
        leases: &'scope RefCell<LeaseRegistry>,
        policy: &'scope PairPolicy,
        resource: &'scope str,
        peer: Ipv4Addr,
        camera: ContentDigest,
        admission: ContentDigest,
        fence: u64,
        full_resolution: bool,
        candidate_hold: Arc<AtomicBool>,
        candidate_proceed: Arc<AtomicBool>,
    }
    fn auto_media_factory<'scope, 'task: 'scope, 'policy: 'scope>(
        mut state: AutoMedia<'scope, 'task>,
        made: Rc<Cell<usize>>,
        polled: Rc<Cell<usize>>,
        release: Rc<Cell<bool>>,
    ) -> impl FnMut(usize, Enrollment, Option<(VideoChannel, camera_api::VideoProfile)>,
        fss_reference::unifi_direct::controller_acceptor::Session<'scope, 'task, 'policy,
            RoutedTransport<'scope, 'task, 'policy>>) -> TrackedStreamWork<'scope, (Test, EffectCoordinator)> {
        move |index, enrollment, reported_video, mut session| {
            assert_eq!(index, 1);
            assert_eq!(enrollment.mac(), MACS[1]);
            assert_eq!(session.claimed_mac(), enrollment.mac());
            let (channel, profile) = reported_video.expect("setup-time profile must reach the stream factory");
            assert_eq!(channel, if state.full_resolution { VideoChannel::Video1 } else { VideoChannel::Video2 });
            assert_eq!(profile.width, camera_api::VideoMetric::Reported(if state.full_resolution { 2688 } else { 160 }));
            assert_eq!(profile.height, camera_api::VideoMetric::Reported(if state.full_resolution { 1512 } else { 128 }));
            assert_eq!(profile.fps, camera_api::VideoMetric::Reported(25));
            made.set(made.get() + 1);
            let polled = polled.clone();
            let release = release.clone();
            let effects = state.effects.take().expect("one effect owner per fixture stream");
            let candidate_hold = state.candidate_hold.clone();
            let candidate_proceed = state.candidate_proceed.clone();
            let (cx, task, clock, leases, policy, resource, peer, camera, admission, fence, full_resolution) =
                (state.cx, state.task, state.clock, state.leases, state.policy, state.resource,
                 state.peer, state.camera, state.admission, state.fence, state.full_resolution);
            TrackedStreamWork::with_owned_effects(effects, move |mut effects| async move {
                let _release_guard = ReleaseOnDrop(candidate_hold.clone());
                let _proceed_guard = ReleaseOnDrop(candidate_proceed.clone());
                let result: Test = async {
                poll_fn(|_| {
                    polled.set(polled.get() + 1);
                    if release.get() { Poll::Ready(()) } else { Poll::Pending }
                }).await;
                let guard = Guard { leases, clock, mac: MACS[1] };
                let mut owner = conversation::Owner { cx, task, clock, effects: &mut effects, leases, approval: &Approval, management_authority: &guard, stream_authority: &guard, wall: &Wall };
                let hello = OperationId::parse("operation:auto-media-hello")?;
                let agreement = OperationId::parse("operation:auto-media-agreement")?;
                let stream = OperationId::parse("operation:auto-media-stream")?;
                let management = management::Preconditions { camera, peer_admission: admission, session_generation: 1, previous_association: None, previous_clock: None, lease_fence: fence };
                let stream_conditions = intent::Preconditions { camera, peer_admission: admission, stream_generation: 1, previous_settings: None, lease_fence: fence };
                let request = listener::Start { bind: SocketAddrV4::new(peer, 0), resource, admission: policy, channel, video: VideoCodec::H264, audio: AudioCodec::Aac, stream_name: "0123456789abcdef", hello: &hello, agreement: &agreement, stream: &stream, time_sync: &[], management, stream_conditions, chunk_bytes: 4096, max_bytes: 1_000_000, bind_wait: Duration::from_secs(10), conversation_wait: Duration::from_secs(10), accept_wait: Duration::from_secs(10) };
                let framer = Framer::new(FlvLimits::default(), 1024 * 1024)?;
                let recorder = recording::Recorder::new(SourceKey { connection: 3, generation: 1 }, recording::Limits::default())?;
                let mut trace = listener::StartTrace::default();
                let started = listener::start_before_reply_retaining_listener(&mut owner, &mut session, &request, framer, recorder, &mut trace).await?;
                let initial_clocks = started.started.time_syncs_during_accept;
                let initial_observations = started.started.observations_during_accept.len();
                let refusal = match listener::ValidatedMediaSelection::new(started, 3, 4096, 12, Duration::from_secs(10)) {
                    Err(refusal) => refusal,
                    Ok(_) => return Err("automatic short source limit accepted".into()),
                };
                assert_eq!(refusal.startup.started.pipeline.source_key().connection, 3);
                assert_eq!(refusal.startup.started.time_syncs_during_accept, initial_clocks);
                assert_eq!(refusal.startup.started.observations_during_accept.len(), initial_observations);
                let mut selection = listener::ValidatedMediaSelection::new(refusal.startup, 3, 4096, 1_000_000, Duration::from_secs(10)).map_err(|_| "automatic candidate configuration refused")?;
                assert_eq!(selection.startup().time_syncs_during_accept, initial_clocks);
                assert_eq!(selection.startup().observations_during_accept.len(), initial_observations);
                let mut fresh = |index: usize| -> io::Result<_> {
                    let framer = Framer::new(FlvLimits::default(), 1024 * 1024).map_err(io::Error::other)?;
                    let recorder = recording::Recorder::new(SourceKey { connection: 3 + index as u64, generation: 1 }, recording::Limits::default()).map_err(io::Error::other)?;
                    Ok((framer, recorder))
                };
                let mut waiting = Box::pin(selection.select(&mut owner, &mut session, &request, &mut trace, None, &mut fresh));
                poll_fn(|context| match waiting.as_mut().poll(context) {
                    Poll::Pending => Poll::Ready(()),
                    Poll::Ready(_) => panic!("selection unexpectedly completed before peer released"),
                }).await;
                drop(waiting);
                candidate_proceed.store(true, Ordering::Release);
                selection.select(&mut owner, &mut session, &request, &mut trace, None, &mut fresh).await?;
                assert_eq!(selection.attempts(), 3);
                let mut pipeline = selection.take_ready().ok_or("automatic valid media missing")?;
                assert_eq!(pipeline.source_key().connection, 5);
                let (startup, candidates) = selection.into_parts();
                assert_eq!(startup.time_syncs_during_accept, initial_clocks);
                assert_eq!(startup.observations_during_accept.len(), initial_observations);
                let (_listener, malformed, additional) = candidates.into_parts();
                assert_eq!(malformed.ok_or("automatic malformed source missing")?.retire().ingress.framing.bytes(), b"X");
                let mut held = additional.into_iter().flatten();
                let partial = held.next().ok_or("automatic partial source missing")?;
                assert_eq!(partial.retire().ingress.framing.bytes(), b"F");
                assert!(held.next().is_none());
                candidate_hold.store(true, Ordering::Release);
                let mut frames = 0usize;
                loop {
                    match pipeline.step(task, cx, clock.now()?).await? {
                        pipeline::Step::Recording(recording::Push::Segment(segment)) => {
                            let mut movie = pipeline.initialization().ok_or("missing automatic init")?.bytes().to_vec();
                            movie.extend_from_slice(segment.fragment().bytes());
                            let demux = AvcMp4::parse(&movie, None, DemuxLimits::default())?;
                            let count = demux.samples().len().min(3);
                            if count == 0 { return Err("empty automatic fragment".into()); }
                            let annex = demux.annex_b(0, count)?;
                            let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                            let mut pictures = decoder.decode_annex_b(annex.bytes())?;
                            pictures.extend(decoder.finish()?);
                            if full_resolution { assert!(pictures.iter().all(|p| p.width() == 2688 && p.height() == 1512)); }
                            frames += pictures.len();
                        }
                        pipeline::Step::Recording(_) | pipeline::Step::Progress { .. } => (),
                        pipeline::Step::Eof => break,
                        pipeline::Step::LimitReached => return Err("automatic media limit".into()),
                    }
                }
                if frames == 0 { return Err("automatic stream decoded no frames".into()); }
                let _ = pipeline.retire();
                let _ = session.retire();
                Ok(())
                }.await;
                (result, effects)
            })
        }
    }
    struct FixtureAccess(ContentDigest);
    impl archive::RetainAuthority for FixtureAccess {
        fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool {
            retention == self.0
        }
    }
    impl archive::ReadAuthority for FixtureAccess {
        fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool {
            retention == self.0
        }
    }
    fn source_confirmed(completion: source_worker::Completion) -> Test {
        if completion.runtime.is_err() {
            return Err("source worker runtime failed".into());
        }
        match completion.outcome {
            source_worker::Outcome::Publication(source_worker::Publication::Published {
                ..
            }) => Ok(()),
            _ => Err("source publication requires reconciliation".into()),
        }
    }
    fn control_event(step: supervisor::Step) -> Result<bool, Box<dyn Error>> {
        match step {
            supervisor::Step::Idle
            | supervisor::Step::Observation(_)
            | supervisor::Step::Media(pipeline::Step::Progress { .. })
            | supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Buffered)) => {
                Ok(false)
            }
            supervisor::Step::Media(pipeline::Step::Eof) => Ok(true),
            other => Err(format!("media supervisor stopped: {other:?}").into()),
        }
    }

    let provider = Arc::new(rustls_pure::provider());
    let server = Arc::new(
        ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
            )?,
    );
    let mut scoped_provider = rustls_pure::provider();
    scoped_provider.secure_random = &FORBIDDEN_RANDOM;
    scoped_provider.kx_groups = if capacity == 2 {
        vec![&FORBIDDEN_P256]
    } else {
        vec![&FORBIDDEN_KX]
    };
    let scoped_camera_provider = Arc::new(scoped_provider.clone());
    let mut scoped_server = ServerConfig::builder_with_provider(Arc::new(scoped_provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
        )?;
    scoped_server.send_tls13_tickets = 0;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(std::fs::read(
        "tests/fixtures/ca.der",
    )?))?;
    let client = Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let path = std::fs::canonicalize(std::env::temp_dir())?.join(format!(
        "fss-parallel-fleet-{}-{capacity}",
        std::process::id()
    ));
    std::fs::create_dir(&path)?;
    let temp = Temp(path);
    let store = FileEffectJournal::create(
        temp.0.join("journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut effects = EffectCoordinator::with_journal(Box::new(store))?;
    let third_store = FileEffectJournal::create(
        temp.0.join("journal-third"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut third_effects = EffectCoordinator::with_journal(Box::new(third_store))?;
    let stream_store = FileEffectJournal::create(
        temp.0.join("journal-concurrent-stream"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut concurrent_effects = EffectCoordinator::with_journal(Box::new(stream_store))?;
    let auto_store = FileEffectJournal::create(
        temp.0.join("journal-auto-stream"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let auto_effects = EffectCoordinator::with_journal(Box::new(auto_store))?;
    let upgrade_store = FileEffectJournal::create(
        temp.0.join("journal-scoped-upgrade"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut upgrade_effects = EffectCoordinator::with_journal(Box::new(upgrade_store))?;
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 4_000_000;
    budget.bytes = 128 * 1024 * 1024;
    budget.storage_operations = 10_000;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:parallel-fleet".into(),
            operation_id: OperationId::parse("operation:parallel-fleet-owner")?,
            principal: "principal:fixture".into(),
            capabilities: [
                RuntimeGrant::AdapterNet,
                RuntimeGrant::AdapterAuth,
                RuntimeGrant::ObserveStatus,
                RuntimeGrant::CameraManagementPrepare,
                RuntimeGrant::CameraManagementCommit,
                RuntimeGrant::CameraSettingPrepare,
                RuntimeGrant::CameraSettingCommit,
                RuntimeGrant::ReadMedia,
                RuntimeGrant::ObjectStage,
                RuntimeGrant::ObjectPublish,
            ]
            .iter()
            .map(|grant| grant.as_str().into())
            .collect(),
            deadline: Some(TimestampNs(600_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"parallel fleet fixture"),
            generation: 1,
        },
        RegionId::new("region:parallel-fleet")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let cameras = [
        ContentDigest::sha256(b"parallel camera 1"),
        ContentDigest::sha256(b"parallel camera 2"),
        ContentDigest::sha256(b"new owner camera"),
    ];
    let admissions = [
        ContentDigest::sha256(b"parallel admission 1"),
        ContentDigest::sha256(b"parallel admission 2"),
        ContentDigest::sha256(b"new owner admission"),
    ];
    let certificates = [
        ContentDigest::sha256(b"parallel cert 1"),
        ContentDigest::sha256(b"parallel cert 2"),
        ContentDigest::sha256(cert),
    ];
    let handles = [
        ContentDigest::sha256(b"parallel secret 1"),
        ContentDigest::sha256(b"parallel secret 2"),
        ContentDigest::sha256(b"new owner credential handle"),
    ];
    let operations = [
        OperationId::parse("operation:parallel-setup-1")?,
        OperationId::parse("operation:parallel-setup-2")?,
        OperationId::parse("operation:parallel-setup-3")?,
    ];
    let resources = cameras.map(|v| format!("camera:{}", v.to_text()));
    let mut leases = LeaseRegistry::new();
    let fences = [
        leases
            .acquire(
                &resources[0],
                authority.region().as_str(),
                None,
                TimestampNs(2),
            )?
            .fence,
        leases
            .acquire(
                &resources[1],
                authority.region().as_str(),
                None,
                TimestampNs(2),
            )?
            .fence,
        leases
            .acquire(
                &resources[2],
                authority.region().as_str(),
                None,
                TimestampNs(2),
            )?
            .fence,
    ];
    let leases = RefCell::new(leases);
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("runtime context")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:parallel-fleet")?,
                started_at: TimestampNs(3),
            },
            &cx,
            async |task, cx| {
                let output: Test = async {
                    let first = std::net::UdpSocket::bind((PEERS[0], 0)).map_err(|e| io::Error::new(e.kind(), format!("initial UDP peer 0: {e}")))?;
                    let port = first.local_addr()?.port();
                    let second = std::net::UdpSocket::bind((PEERS[1], port)).map_err(|e| io::Error::new(e.kind(), format!("initial UDP peer 1: {e}")))?;
                    let third = std::net::UdpSocket::bind((PEERS[2], port)).map_err(|e| io::Error::new(e.kind(), format!("initial UDP peer 2: {e}")))?;
                    let mut senders = Vec::new();
                    for (i, socket) in [first, second, third].into_iter().enumerate() {
                        socket.set_read_timeout(Some(Duration::from_secs(10)))?;
                        senders.push(Joined(Some(std::thread::spawn(
                            move || -> io::Result<()> {
                                let mut input = [0u8; 64];
                                let (_, source) = socket.recv_from(&mut input)?;
                                socket.send_to(&discovery_packet_for(PEERS[i], MACS[i]), source)?;
                                Ok(())
                            },
                        ))));
                    }
                    let clock = MeteredClock::new(task, cx, TimestampNs(4))?;
                    let config = discovery::Config::new_many(
                        PEERS[0],
                        8,
                        &[
                            SocketAddrV4::new(PEERS[0], port),
                            SocketAddrV4::new(PEERS[1], port),
                            SocketAddrV4::new(PEERS[2], port),
                        ],
                        "fixture:parallel-discovery",
                        Duration::from_millis(300),
                        8,
                    )?;
                    let report = discovery::discover(task, cx, clock.now()?, &config).await?;
                    for sender in senders {
                        sender.finish()?;
                    }
                    let inventory = [
                        Enrollment::new(
                            MACS[0],
                            cameras[0],
                            admissions[0],
                            certificates[0],
                            handles[0],
                            1,
                        )?,
                        Enrollment::new(
                            MACS[1],
                            cameras[1],
                            admissions[1],
                            certificates[1],
                            handles[1],
                            1,
                        )?,
                    ];
                    let fleet = Fleet::new(&report, &inventory)?;
                    let other_fleet = Fleet::new(&report, &inventory)?;
                    assert_eq!(fleet.unknown_claims().len(), 1);
                    let policy = PairPolicy {
                        listen: peer,
                        cameras,
                        admissions,
                        fences,
                        resources: resources.clone(),
                    };
                    let mut listener = controller_listener::Listener::bind(
                        task,
                        cx,
                        clock,
                        &policy,
                        SocketAddrV4::new(peer, 0),
                        "fixture:parallel-controller",
                        Duration::from_secs(5),
                    )
                    .await?;
                    let endpoint = listener.local_addr();
                    // Exercise the reusable setup-to-scoped-TLS bridge with one
                    // deliberately truncated first connection and a fresh lease.
                    {
                        let camera_listener = std::net::TcpListener::bind((PEERS[0], 0))?;
                        let SocketAddr::V4(camera_address) = camera_listener.local_addr()? else { return Err("IPv4 required".into()); };
                        let camera_server = server.clone();
                        let camera_client = client.clone();
                        let fixture = Joined(Some(std::thread::spawn(move || {
                            camera_fixture(camera_listener, endpoint.port(), peer, camera_server)?;
                            let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
                            socket.bind(&SocketAddr::V4(SocketAddrV4::new(PEERS[0], 0)).into())?;
                            socket.connect_timeout(&SocketAddr::V4(endpoint).into(), Duration::from_secs(5))?;
                            drop(socket);
                            camera_upgrade_peer(endpoint, PEERS[0], camera_client, "001122aabbcc")
                        })));
                        let mut inbound_leases = [Some(acquire(task, cx, clock, &resources[0]).await?), Some(acquire(task, cx, clock, &resources[0]).await?)];
                        let camera_lease = acquire(task, cx, clock, &resources[0]).await?;
                        let tls = camera_tls_owned::connect_with_lease(cx, task, clock, camera_address, cert, &resources[0], Duration::from_secs(5), scoped_camera_provider.clone(), camera_lease).await?;
                        let plaintext = MeteredIo::with_clock(tls, clock, &resources[0], 4096)?;
                        let mut http = camera_http::Owner::new(plaintext, task, cx, clock, &policy, PEERS[0], 1, &resources[0])?;
                        let mut upgrade_owner = setup::Owner { cx, task, clock, effects: &mut upgrade_effects, leases: &leases, approval: &Approval, admission: &policy, handoff_authority: &Handoff };
                        let operation = OperationId::parse("operation:scoped-setup-upgrade")?;
                        let cfg = setup::Config { report: &report, index: 0, camera: cameras[0], peer_admission: admissions[0], generation: 1, fence: fences[0], destination: peer, operation: &operation, credential: br#"{"username":"fixture","password":"synthetic"}"#, wait: Duration::from_secs(10) };
                        let tls_config = Arc::new(scoped_server.clone());
                        let mut trace = setup::AcceptTrace::default();
                        let invalid_controller = Controller::new(Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?, 1)?;
                        assert!(matches!(fss_unifi_scoped_tls_entropy_lab::setup_upgrade::setup_and_upgrade(
                            cx, &mut upgrade_owner, &mut listener, endpoint.port(), &mut http, &cfg, handoff::Framing::ContentLength,
                            0, Duration::from_secs(10), Duration::from_secs(20), &mut trace, tls_config.clone(),
                            &mut inbound_leases, ProtocolPolicy::RequireOffer, &policy, invalid_controller,
                        ).await, Err(fss_unifi_scoped_tls_entropy_lab::setup_upgrade::Error::Configuration)));
                        assert!(trace.outcome().is_none() && inbound_leases.iter().all(Option::is_some));
                        let wrong_lease = acquire(task, cx, clock, &resources[1]).await?;
                        let original = inbound_leases[1].replace(wrong_lease).ok_or("missing fixture lease")?;
                        let controller = Controller::new(Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?, 1)?;
                        assert!(matches!(fss_unifi_scoped_tls_entropy_lab::setup_upgrade::setup_and_upgrade(
                            cx, &mut upgrade_owner, &mut listener, endpoint.port(), &mut http, &cfg, handoff::Framing::ContentLength,
                            4096, Duration::from_secs(10), Duration::from_secs(20), &mut trace, tls_config.clone(),
                            &mut inbound_leases, ProtocolPolicy::RequireOffer, &policy, controller,
                        ).await, Err(fss_unifi_scoped_tls_entropy_lab::setup_upgrade::Error::Configuration)));
                        drop(inbound_leases[1].replace(original));
                        assert!(trace.outcome().is_none() && inbound_leases.iter().all(Option::is_some));
                        let mut tickets = scoped_server.clone();
                        tickets.send_tls13_tickets = 1;
                        let controller = Controller::new(Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?, 1)?;
                        assert!(matches!(fss_unifi_scoped_tls_entropy_lab::setup_upgrade::setup_and_upgrade(
                            cx, &mut upgrade_owner, &mut listener, endpoint.port(), &mut http, &cfg, handoff::Framing::ContentLength,
                            4096, Duration::from_secs(10), Duration::from_secs(20), &mut trace, Arc::new(tickets),
                            &mut inbound_leases, ProtocolPolicy::RequireOffer, &policy, controller,
                        ).await, Err(fss_unifi_scoped_tls_entropy_lab::setup_upgrade::Error::Configuration)));
                        assert!(trace.outcome().is_none() && inbound_leases.iter().all(Option::is_some));
                        let controller = Controller::new(Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?, 1)?;
                        let session = fss_unifi_scoped_tls_entropy_lab::setup_upgrade::setup_and_upgrade(
                            cx, &mut upgrade_owner, &mut listener, endpoint.port(), &mut http, &cfg, handoff::Framing::ContentLength,
                            4096, Duration::from_secs(10), Duration::from_secs(20), &mut trace, tls_config,
                            &mut inbound_leases, ProtocolPolicy::RequireOffer, &policy, controller,
                        ).await?;
                        assert_eq!(session.claimed_mac(), MACS[0]);
                        assert!(matches!(trace.outcome(), Some(setup::Outcome::Observed { readback: handoff::Readback::Requested, .. })));
                        assert!(inbound_leases.iter().all(Option::is_none));
                        let _ = session.retire();
                        drop(http);
                        fixture.finish()?;
                    }
                    for i in 0..2 {
                        let camera_listener = std::net::TcpListener::bind((PEERS[i], 0))?;
                        let SocketAddr::V4(address) = camera_listener.local_addr()? else {
                            return Err("IPv4 required".into());
                        };
                        let camera_server = server.clone();
                        let fixture = Joined(Some(std::thread::spawn(move || {
                            camera_fixture(camera_listener, endpoint.port(), peer, camera_server)
                        })));
                        let lease = acquire(task, cx, clock, &resources[i]).await?;
                        let tls = camera_tls_owned::connect_with_lease(
                            cx,
                            task,
                            clock,
                            address,
                            cert,
                            &resources[i],
                            Duration::from_secs(5),
                            scoped_camera_provider.clone(),
                            lease,
                        )
                        .await?;
                        let io = MeteredIo::with_clock(tls, clock, &resources[i], 4096)?;
                        let mut http = camera_http::Owner::new(
                            io,
                            task,
                            cx,
                            clock,
                            &policy,
                            PEERS[i],
                            1,
                            &resources[i],
                        )?;
                        let mut owner = setup::Owner {
                            cx,
                            task,
                            clock,
                            effects: &mut effects,
                            leases: &leases,
                            approval: &Approval,
                            admission: &policy,
                            handoff_authority: &Handoff,
                        };
                        let mut trace = setup::Trace::default();
                        trace.require_reported_video(profile_limits(full_resolution))?;
                        assert!(fleet.reported_video(i).is_none());
                        let outcome = fleet
                            .setup_one(
                                i,
                                &mut owner,
                                &listener,
                                endpoint.port(),
                                &mut http,
                                certificates[i],
                                handles[i],
                                br#"{"username":"fixture","password":"synthetic"}"#,
                                fences[i],
                                peer,
                                &operations[i],
                                handoff::Framing::ContentLength,
                                Duration::from_secs(10),
                                &mut trace,
                            )
                            .await?;
                        assert!(matches!(outcome, setup::Outcome::Observed { .. }));
                        assert_eq!(fleet.reported_video(i), trace.preflight_video().and_then(|v| v.selected));
                        drop(http);
                        fixture.finish()?;
                    }
                    let fleet_resources = FleetResources::new(&resources[..1])?;
                    let other_resources = FleetResources::new(&["fixture:wrong".to_owned()])?;
                    let empty_resources = FleetResources::new(&[])?;
                    let router = Router::new(&fleet, &listener, 2, 4096, Duration::from_secs(10))?;
                    let identity =
                        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?;
                    let other_transport =
                        FleetLeased::new(scoped_server.clone(), task, cx, clock, &other_resources)?;
                    if !matches!(other_transport.synchronize_fleet(&fleet), Err(error) if error.kind() == io::ErrorKind::InvalidInput)
                        || other_resources.len() != 1 {
                        return Err("mismatched resource prefix changed inventory".into());
                    }
                    let empty_transport = FleetLeased::new(scoped_server.clone(), task, cx, clock, &empty_resources)?;
                    let mut empty_supply = LeaseSupply::new(empty_transport.clone(), 2, 128)?;
                    let empty_count = Arc::new(WakeCount(AtomicUsize::new(0)));
                    let empty_waker = Waker::from(empty_count.clone());
                    let mut empty_context = Context::from_waker(&empty_waker);
                    assert!(empty_supply.poll_next(&mut empty_context).is_pending());
                    assert_eq!(empty_transport.synchronize_fleet(&fleet)?, 2);
                    assert!(empty_count.0.load(Ordering::Relaxed) > 0);
                    assert!(matches!(timeout(cx.now(), Duration::from_secs(5), empty_supply.next()).await?, Some(SupplyEvent::Started(_))));
                    empty_supply.request_stop();
                    assert!(matches!(timeout(cx.now(), Duration::from_secs(5), empty_supply.next()).await?, Some(SupplyEvent::Drained(_))));
                    assert!(matches!(empty_supply.next().await, Some(SupplyEvent::Stopped)));
                    drop(empty_supply);
                    drop(empty_transport);
                    let transport = FleetLeased::new(scoped_server.clone(), task, cx, clock, &fleet_resources)?;
                    if !matches!(
                        FleetLeased::new(scoped_server, task, cx, clock, &fleet_resources),
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists
                    ) {
                        return Err("resource owner was bound to two transports".into());
                    }
                    let unrelated = acquire(task, cx, clock, "fixture:unrelated").await?;
                    if transport.install(unrelated).is_ok() {
                        return Err("unrelated lease was accepted".into());
                    }
                    // Stop immediately after admitting a worker. Even if the
                    // blocking operation has already finished, its owner must
                    // be joined before the supervisor can report Stopped.
                    let mut stopping = LeaseSupply::new(transport.clone(), 2, 128)?;
                    if !matches!(
                        timeout(cx.now(), Duration::from_secs(5), stopping.next()).await?,
                        Some(SupplyEvent::Started(_))
                    ) {
                        return Err("shutdown fixture did not admit a worker".into());
                    }
                    stopping.request_stop();
                    if !matches!(
                        timeout(cx.now(), Duration::from_secs(5), stopping.next()).await?,
                        Some(SupplyEvent::Drained(_))
                    ) || !matches!(
                        timeout(cx.now(), Duration::from_secs(5), stopping.next()).await?,
                        Some(SupplyEvent::Stopped)
                    ) {
                        return Err("shutdown reported before worker drain".into());
                    }
                    drop(stopping);
                    let mut supply = LeaseSupply::new(transport.clone(), 2, 128)?;
                    if LeaseSupply::new(transport.clone(), 2, 128).is_ok() {
                        return Err("second supply owner was accepted".into());
                    }
                    let mut installed = [false; 2];
                    while !installed[0] {
                        match timeout(cx.now(), Duration::from_secs(5), supply.next()).await? {
                            Some(SupplyEvent::Started(_)) => (),
                            Some(SupplyEvent::Installed(index)) => installed[index] = true,
                            _ => return Err("initial lease supply failed".into()),
                        }
                    }
                    let duplicate = acquire(task, cx, clock, &resources[0]).await?;
                    if transport.install(duplicate).is_ok() {
                        return Err("existing lease was replaced".into());
                    }
                    let retained = poll_fn(|context| {
                        let mut wait = std::pin::pin!(supply.next());
                        Poll::Ready(wait.as_mut().poll(context).is_pending())
                    })
                    .await;
                    assert!(
                        retained,
                        "full supply should wait without discarding ownership"
                    );
                    let refused = match FleetAcceptor::new(
                        router,
                        cx,
                        &policy,
                        transport,
                        identity,
                        Default::default(),
                        ProtocolPolicy::RequireOffer,
                        4096,
                        Duration::from_secs(10),
                        0,
                    ) {
                        Err(refusal) => refusal,
                        Ok(_) => return Err("zero handshake capacity was accepted".into()),
                    };
                    assert!(matches!(refused.reason, ConfigurationError::Invalid));
                    let mut acceptor = FleetAcceptor::new(
                        refused.router,
                        cx,
                        &policy,
                        refused.transport,
                        refused.identity,
                        Default::default(),
                        ProtocolPolicy::RequireOffer,
                        4096,
                        Duration::from_secs(30),
                        capacity,
                    )
                    .map_err(|error| format!("acceptor configuration: {error:?}"))?;
                    let socket = asupersync::net::TcpSocket::new_v4()?;
                    socket.bind(SocketAddr::V4(SocketAddrV4::new(PEERS[0], 0)))?;
                    let mut stalled = socket.connect(SocketAddr::V4(endpoint)).await?;
                    poll_fn(|context| match acceptor.poll_next(context) {
                        Poll::Pending if acceptor.handshake_len() == 1 => Poll::Ready(()),
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(_) => panic!("first handshake unexpectedly completed"),
                    })
                    .await;
                    // Discover both synthetic cameras while the first TLS
                    // handshake remains owned and unable to finish.
                    let first_scan = std::net::UdpSocket::bind((PEERS[0], port)).map_err(|e| io::Error::new(e.kind(), format!("rescan UDP peer 0: {e}")))?;
                    let second_scan = std::net::UdpSocket::bind((PEERS[1], port)).map_err(|e| io::Error::new(e.kind(), format!("rescan UDP peer 1: {e}")))?;
                    let third_scan = std::net::UdpSocket::bind((PEERS[2], port)).map_err(|e| io::Error::new(e.kind(), format!("rescan UDP peer 2: {e}")))?;
                    let mut scan_senders = Vec::new();
                    for (i, socket) in [first_scan, second_scan, third_scan].into_iter().enumerate() {
                        socket.set_read_timeout(Some(Duration::from_secs(10)))?;
                        scan_senders.push(Joined(Some(std::thread::spawn(
                            move || -> io::Result<()> {
                                let mut input = [0u8; 64];
                                let (_, source) = socket.recv_from(&mut input)?;
                                socket.send_to(&discovery_packet_for(PEERS[i], MACS[i]), source)?;
                                Ok(())
                            },
                        ))));
                    }
                    let scanner = Scanner::new(
                        cx,
                        task,
                        clock,
                        &fleet,
                        config.clone(),
                        Duration::from_secs(5),
                    )?;
                    let mut pump = Pump::new(&scanner, &mut acceptor)?;
                    assert_eq!(fleet_resources.len(), 1);
                    let touched_fleet = Rc::new(Cell::new(false));
                    let factory_flag = touched_fleet.clone();
                    let mut other_auto = AutomaticWork::<()>::new(&other_fleet, 1)
                        .map_err(|_| "automatic work capacity refused")?;
                    let mut other_factory = move |_: usize, _: Enrollment| -> io::Result<CameraWork<'_, ()>> {
                        factory_flag.set(true);
                        Err(io::ErrorKind::PermissionDenied.into())
                    };
                    if !matches!(supply.next_with_automatic_setup(&mut pump, &mut other_auto, &mut other_factory).await,
                        Err(error) if error.kind() == io::ErrorKind::InvalidInput) {
                        return Err("unrelated fleet called automatic factory".into());
                    }
                    let wrong_fleet_touched = Rc::new(Cell::new(false));
                    let wrong_fleet_flag = wrong_fleet_touched.clone();
                    let mut wrong_fleet_streams = ActiveStreams::new(&other_fleet, 1).map_err(|_| "stream capacity refused")?;
                    assert!(wrong_fleet_streams.insert(0, Box::pin(poll_fn(move |_| {
                        wrong_fleet_flag.set(true); Poll::Ready(())
                    }))).is_ok());
                    assert!(matches!(supply.next_with_setup_and_streams(&mut pump, &mut other_auto, &mut wrong_fleet_streams, &mut other_factory).await,
                        Err(error) if error.kind() == io::ErrorKind::InvalidInput));
                    assert!(!wrong_fleet_touched.get());
                    assert_eq!(wrong_fleet_streams.into_pending().ok().ok_or("unexpected completion fence")?.len(), 1);
                    assert!(!touched_fleet.get());
                    assert!(other_auto.into_pending().is_empty());
                    let mut wrong_supply = LeaseSupply::new(other_transport, 1, 128)?;
                    let touched = Rc::new(Cell::new(false));
                    let mut wrong_auto = AutomaticWork::<()>::new(&fleet, 1)
                        .map_err(|_| "automatic work capacity refused")?;
                    let factory_touched = touched.clone();
                    let mut wrong_factory = move |_: usize, _: Enrollment| -> io::Result<CameraWork<'_, ()>> {
                        factory_touched.set(true);
                        Err(io::ErrorKind::PermissionDenied.into())
                    };
                    if !matches!(wrong_supply.next_with_automatic_setup(&mut pump, &mut wrong_auto, &mut wrong_factory).await,
                        Err(error) if error.kind() == io::ErrorKind::InvalidInput) {
                        return Err("unrelated supply called automatic factory".into());
                    }
                    let stream_touched = Rc::new(Cell::new(false));
                    let stream_flag = stream_touched.clone();
                    let mut wrong_streams = ActiveStreams::new(&fleet, 1).map_err(|_| "stream capacity refused")?;
                    assert!(wrong_streams.insert(0, Box::pin(poll_fn(move |_| {
                        stream_flag.set(true); Poll::Ready(())
                    }))).is_ok());
                    assert!(matches!(wrong_supply.next_with_setup_and_streams(&mut pump, &mut wrong_auto, &mut wrong_streams, &mut wrong_factory).await,
                        Err(error) if error.kind() == io::ErrorKind::InvalidInput));
                    assert!(!stream_touched.get() && !touched.get());
                    assert_eq!(wrong_streams.into_pending().ok().ok_or("unexpected completion fence")?.len(), 1);
                    assert!(!touched.get());
                    wrong_auto.request_stop();
                    assert!(wrong_auto.into_pending().is_empty());
                    let flag = touched.clone();
                    let mut wrong_work = CameraWorkSet::new(1).map_err(|_| "camera work capacity refused")?;
                    assert!(wrong_work.insert(0, Box::pin(poll_fn(move |_| {
                        flag.set(true);
                        Poll::Ready(())
                    }))).is_ok());
                    if !matches!(wrong_supply.next_with_camera_work(&mut pump, &mut wrong_work).await,
                        Err(error) if error.kind() == io::ErrorKind::InvalidInput) {
                        return Err("unrelated supply polled camera work".into());
                    }
                    assert!(!touched.get());
                    drop(wrong_work.into_pending());
                    if !matches!(
                        wrong_supply.next_with_pump(&mut pump).await,
                        Err(error) if error.kind() == io::ErrorKind::InvalidInput
                    ) {
                        return Err("unrelated supply was paired with pump".into());
                    }
                    wrong_supply.request_stop();
                    assert!(matches!(
                        wrong_supply.next().await,
                        Some(SupplyEvent::Stopped)
                    ));
                    let mut scanned = false;
                    let mut first_replenished = false;
                    let mut second_installed = false;
                    while !scanned || !first_replenished || !second_installed {
                        match timeout(
                            cx.now(),
                            Duration::from_secs(5),
                            supply.next_with_pump(&mut pump),
                        )
                        .await??
                        {
                            Progress::Event(PumpEvent::Discovery(Ok(ScanOutcome::Updated(
                                snapshot,
                            )))) => {
                                assert_eq!(snapshot.report().cameras.len(), 3);
                                scanned = true;
                            }
                            Progress::Work(Some(SupplyEvent::Started(0))) => (),
                            Progress::Work(Some(SupplyEvent::Installed(0))) => {
                                first_replenished = true
                            }
                            Progress::Work(Some(SupplyEvent::Started(1))) => (),
                            Progress::Work(Some(SupplyEvent::Installed(1))) => second_installed = true,
                            _ => {
                                return Err(
                                    "shared pump did not scan and replenish during stalled TLS"
                                        .into(),
                                );
                            }
                        }
                    }
                    for sender in scan_senders {
                        sender.finish()?;
                    }
                    assert_eq!(pump.driver().handshake_len(), 1);
                    pump.request_scan_stop();
                    assert!(pump.scan_drained());
                    let parked = poll_fn(|context| {
                        let mut wait = std::pin::pin!(supply.next_with_pump(&mut pump));
                        Poll::Ready(wait.as_mut().poll(context).is_pending())
                    })
                    .await;
                    assert!(
                        parked,
                        "dropping a wait must preserve the stalled handshake"
                    );
                    assert_eq!(pump.driver().handshake_len(), 1);
                    assert_eq!(fleet_resources.len(), 2);
                    let counter = Arc::new(WakeCount(AtomicUsize::new(0)));
                    let waker = Waker::from(counter.clone());
                    let mut wake_context = Context::from_waker(&waker);
                    let watched_calls = Rc::new(Cell::new(0usize));
                    let factory_calls = watched_calls.clone();
                    let mut watching_auto = AutomaticWork::<()>::new(&fleet, 1)
                        .map_err(|_| "automatic work capacity refused")?;
                    let mut watching_factory = move |_: usize, _: Enrollment| -> io::Result<CameraWork<'_, ()>> {
                        factory_calls.set(factory_calls.get() + 1);
                        Ok(Box::pin(poll_fn(|_| Poll::Pending)))
                    };
                    {
                        let mut waiting = std::pin::pin!(supply.next_with_automatic_setup(
                            &mut pump, &mut watching_auto, &mut watching_factory,
                        ));
                        assert!(waiting.as_mut().poll(&mut wake_context).is_pending());
                        let new_entry = Enrollment::new(
                            MACS[2],
                            cameras[2],
                            admissions[2],
                            certificates[2],
                            handles[2],
                            1,
                        )?;
                        assert_eq!(fleet.add_enrollment(new_entry)?, 2);
                        assert!(matches!(fleet.state(2), Some(discovery::fleet::State::Ready { .. })));
                        assert!(fleet.unknown_claims().is_empty());
                        assert!(counter.0.load(Ordering::Relaxed) > 0, "fleet append did not wake the parked loop");
                        assert!(matches!(timeout(cx.now(), Duration::from_secs(5), waiting.as_mut()).await??,
                            AutomaticEvent::Progress(Supervised::Fleet(Progress::Work(Some(SupplyEvent::Started(2)))))));
                    }
                    assert!(matches!(supply.next_with_automatic_setup(&mut pump, &mut watching_auto, &mut watching_factory).await?,
                        AutomaticEvent::Started { index: 2 }));
                    assert_eq!(watched_calls.get(), 1);
                    watching_auto.request_stop();
                    let retained = watching_auto.into_pending();
                    assert_eq!(retained.len(), 1);
                    drop(retained);
                    assert_eq!(fleet_resources.len(), 3);
                    assert!(matches!(timeout(cx.now(), Duration::from_secs(5), supply.next_with_pump(&mut pump)).await??,
                        Progress::Work(Some(SupplyEvent::Installed(2)))));
                    assert_eq!(pump.driver().handshake_len(), 1);

                    let polls = Rc::new(Cell::new(0usize));
                    let work_polls = polls.clone();
                    let mut pending_work = CameraWorkSet::new(1).map_err(|_| "camera work capacity refused")?;
                    assert!(pending_work.insert(2, Box::pin(poll_fn(move |_| {
                        work_polls.set(work_polls.get() + 1);
                        Poll::<()>::Pending
                    }))).is_ok());
                    let parked = poll_fn(|context| {
                        let mut wait = std::pin::pin!(supply.next_with_camera_work(&mut pump, &mut pending_work));
                        Poll::Ready(wait.as_mut().poll(context).is_pending())
                    }).await;
                    assert!(parked && polls.get() > 0 && pending_work.len() == 1);
                    assert_eq!(pump.driver().handshake_len(), 1);
                    let retained = pending_work.into_pending();
                    assert_eq!(retained.len(), 1);
                    drop(retained);

                    let stopped_calls = Rc::new(Cell::new(0usize));
                    let stopped_count = stopped_calls.clone();
                    let mut stopped_auto = AutomaticWork::<()>::new(&fleet, 1)
                        .map_err(|_| "automatic work capacity refused")?;
                    stopped_auto.request_stop();
                    let mut stopped_factory = move |_: usize, _: Enrollment| -> io::Result<CameraWork<'_, ()>> {
                        stopped_count.set(stopped_count.get() + 1);
                        Err(io::ErrorKind::PermissionDenied.into())
                    };
                    let stopped = poll_fn(|context| {
                        let mut wait = std::pin::pin!(supply.next_with_automatic_setup(
                            &mut pump, &mut stopped_auto, &mut stopped_factory,
                        ));
                        Poll::Ready(wait.as_mut().poll(context).is_pending())
                    }).await;
                    assert!(stopped && stopped_calls.get() == 0);
                    assert!(stopped_auto.into_pending().is_empty());

                    let held_calls = Rc::new(Cell::new(0usize));
                    let held_count = held_calls.clone();
                    let mut held_auto = AutomaticWork::<()>::new(&fleet, 1)
                        .map_err(|_| "automatic work capacity refused")?;
                    let mut held_factory = move |_: usize, _: Enrollment| -> io::Result<CameraWork<'_, ()>> {
                        held_count.set(held_count.get() + 1);
                        Ok(Box::pin(poll_fn(|_| Poll::Pending)))
                    };
                    let mut test_streams = ActiveStreams::new(&fleet, 1).map_err(|_| "stream capacity refused")?;
                    let invalid = test_streams.insert(999, Box::pin(async { 1usize }));
                    assert!(matches!(invalid, Err((StreamRefusal::UnknownEnrollment, _))));
                    let ready = Rc::new(Cell::new(false));
                    let stream_ready = ready.clone();
                    assert!(test_streams.insert(2, Box::pin(poll_fn(move |_| {
                        if stream_ready.get() { Poll::Ready(42usize) } else { Poll::Pending }
                    }))).is_ok());
                    assert!(matches!(test_streams.insert(2, Box::pin(async { 8usize })),
                        Err((StreamRefusal::Work(_), _))));
                    let parked = poll_fn(|context| {
                        let mut wait = std::pin::pin!(supply.next_with_setup_and_streams(
                            &mut pump, &mut held_auto, &mut test_streams, &mut held_factory,
                        ));
                        Poll::Ready(wait.as_mut().poll(context).is_pending())
                    }).await;
                    assert!(parked && held_calls.get() == 0 && test_streams.len() == 1);
                    ready.set(true);
                    assert!(matches!(supply.next_with_setup_and_streams(&mut pump, &mut held_auto, &mut test_streams, &mut held_factory).await?,
                        FleetStreamEvent::Stream { index: 2, output: 42 }));
                    assert!(matches!(supply.next_with_setup_and_streams(&mut pump, &mut held_auto, &mut test_streams, &mut held_factory).await?,
                        FleetStreamEvent::Automatic(AutomaticEvent::Started { index: 2 })));
                    assert_eq!(held_auto.rearm(2), Err(RearmRefusal::InFlight));
                    assert_eq!(held_auto.rearm(999), Err(RearmRefusal::UnknownEnrollment));
                    let conflict_polled = Rc::new(Cell::new(false));
                    let conflict_flag = conflict_polled.clone();
                    assert!(test_streams.insert(2, Box::pin(poll_fn(move |_| {
                        conflict_flag.set(true); Poll::Ready(0usize)
                    }))).is_ok());
                    assert!(matches!(supply.next_with_setup_and_streams(&mut pump, &mut held_auto, &mut test_streams, &mut held_factory).await,
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists));
                    assert!(!conflict_polled.get() && held_auto.pending_len() == 1 && test_streams.len() == 1);
                    assert_eq!(test_streams.into_pending().ok().ok_or("unexpected completion fence")?.len(), 1);
                    let mut test_streams = ActiveStreams::new(&fleet, 1).map_err(|_| "stream capacity refused")?;
                    let stream_polls = Rc::new(Cell::new(0));
                    let observed_stream_polls = stream_polls.clone();
                    assert!(test_streams.insert(0, Box::pin(poll_fn(move |_| { observed_stream_polls.set(observed_stream_polls.get()+1); Poll::<usize>::Pending }))).is_ok());
                    held_auto.request_stop();
                    let waiting = poll_fn(|context| {
                        let mut wait = std::pin::pin!(supply.next_with_setup_and_streams(
                            &mut pump, &mut held_auto, &mut test_streams, &mut held_factory,
                        ));
                        Poll::Ready(wait.as_mut().poll(context).is_pending())
                    }).await;
                    assert!(waiting && held_calls.get() == 1 && held_auto.pending_len() == 1 && stream_polls.get() > 0 && test_streams.len() == 1);
                    assert_eq!(test_streams.into_pending().ok().ok_or("unexpected completion fence")?.len(), 1);
                    let retained = held_auto.into_pending();
                    assert_eq!(retained.len(), 1);
                    drop(retained);

                    // Once an automatic future completes, its in-flight mark
                    // is cleared and the same camera may start stream work.
                    let mut completed_auto = AutomaticWork::<()>::new(&fleet, 1)
                        .map_err(|_| "automatic capacity refused")?;
                    let mut completed_streams = ActiveStreams::new(&fleet, 1)
                        .map_err(|_| "stream capacity refused")?;
                    let mut complete_factory = |_: usize, _: Enrollment| -> io::Result<CameraWork<'_, ()>> {
                        Ok(Box::pin(async {}))
                    };
                    assert!(matches!(supply.next_with_setup_and_streams(&mut pump, &mut completed_auto, &mut completed_streams, &mut complete_factory).await?,
                        FleetStreamEvent::Automatic(AutomaticEvent::Started { index: 2 })));
                    assert!(matches!(supply.next_with_setup_and_streams(&mut pump, &mut completed_auto, &mut completed_streams, &mut complete_factory).await?,
                        FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Camera { index: 2, output: () }))));
                    assert_eq!(completed_auto.rearm(2), Ok(()));
                    assert_eq!(completed_auto.rearm(2), Err(RearmRefusal::NotAttempted));
                    assert!(completed_streams.insert(2, Box::pin(async { 5usize })).is_ok());
                    assert!(matches!(supply.next_with_setup_and_streams(&mut pump, &mut completed_auto, &mut completed_streams, &mut complete_factory).await?,
                        FleetStreamEvent::Stream { index: 2, output: 5 }));
                    assert!(matches!(supply.next_with_setup_and_streams(&mut pump, &mut completed_auto, &mut completed_streams, &mut complete_factory).await?,
                        FleetStreamEvent::Automatic(AutomaticEvent::Started { index: 2 })));
                    assert!(matches!(supply.next_with_setup_and_streams(&mut pump, &mut completed_auto, &mut completed_streams, &mut complete_factory).await?,
                        FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Camera { index: 2, output: () }))));
                    assert!(completed_auto.into_pending().is_empty() && completed_streams.is_empty());

                    // A failed factory is reported once and must not be retried
                    // merely because the fleet entry remains ready.
                    let attempts = Rc::new(Cell::new(0usize));
                    let count_attempt = attempts.clone();
                    let mut failed_auto = AutomaticWork::<()>::new(&fleet, 1)
                        .map_err(|_| "automatic work capacity refused")?;
                    let mut refuse_factory = move |_: usize, _: Enrollment| -> io::Result<CameraWork<'_, ()>> {
                        count_attempt.set(count_attempt.get() + 1);
                        Err(io::ErrorKind::PermissionDenied.into())
                    };
                    assert!(matches!(
                        supply.next_with_automatic_setup(&mut pump, &mut failed_auto, &mut refuse_factory).await?,
                        AutomaticEvent::FactoryFailed { index: 2, kind: io::ErrorKind::PermissionDenied }
                    ));
                    let parked = poll_fn(|context| {
                        let mut wait = std::pin::pin!(supply.next_with_automatic_setup(
                            &mut pump, &mut failed_auto, &mut refuse_factory,
                        ));
                        Poll::Ready(wait.as_mut().poll(context).is_pending())
                    }).await;
                    assert!(parked && attempts.get() == 1);
                    assert_eq!(failed_auto.rearm(0), Err(RearmRefusal::NotAttempted));
                    assert_eq!(failed_auto.rearm(2), Ok(()));
                    assert!(matches!(
                        supply.next_with_automatic_setup(&mut pump, &mut failed_auto, &mut refuse_factory).await?,
                        AutomaticEvent::FactoryFailed { index: 2, kind: io::ErrorKind::PermissionDenied }
                    ));
                    assert_eq!(attempts.get(), 2);
                    failed_auto.request_stop();
                    assert_eq!(failed_auto.rearm(2), Err(RearmRefusal::Stopped));
                    assert!(failed_auto.into_pending().is_empty());

                    // A real synthetic HTTPS login failure is known to precede
                    // setup effects. Schedule its exact operation, run the
                    // timer alongside an owned stream, then observe selection.
                    let reject_socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
                    reject_socket.bind(&SocketAddr::V4(SocketAddrV4::new(PEERS[2], 0)).into())?;
                    let SocketAddr::V4(reject_address) = reject_socket.local_addr()?.as_socket().ok_or("IPv4 required")? else { return Err("IPv4 required".into()); };
                    let reject_server = server.clone();
                    let preflight_progress = Arc::new(camera_setup::PreflightRetryTrace::default());
                    let observed_progress = preflight_progress.clone();
                    let reject_peer = Joined(Some(std::thread::spawn(move || {
                        let deadline = Instant::now() + Duration::from_secs(10);
                        while observed_progress.retries() == 0 {
                            if Instant::now() >= deadline { return Err(io::Error::new(io::ErrorKind::TimedOut, "preflight retry not observed")); }
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        reject_socket.listen(1)?;
                        camera_reject_login(reject_socket.into(), reject_server, changed_readback)
                    })));
                    let mut retry_owner = setup::Owner {
                        cx, task, clock, effects: &mut effects, leases: &leases,
                        approval: &Approval, admission: &policy, handoff_authority: &Handoff,
                    };
                    let mut retry_trace = setup::Trace::default();
                    let mut retry_acquisitions = [
                        fss_unifi_scoped_tls_entropy_lab::owned::offload::Acquisition::begin(task, cx, clock, &resources[2], 128)?,
                        fss_unifi_scoped_tls_entropy_lab::owned::offload::Acquisition::begin(task, cx, clock, &resources[2], 128)?,
                    ];
                    let preflight_policy = camera_setup::PreflightRetryPolicy::new(2, Duration::from_millis(500))?;
                    assert!(camera_setup::PreflightRetryPolicy::new(0, Duration::from_millis(500)).is_err());
                    assert!(camera_setup::PreflightRetryPolicy::new(2, Duration::ZERO).is_err());
                    let retry_operation = OperationId::parse("operation:synthetic-pre-effect-failure")?;
                    let completion_operation = retry_operation.clone();
                    let retry_future: CameraWork<'_, RetryCompletion<Result<setup::Outcome, camera_setup::Error>>> = Box::pin(async {
                        let output = camera_setup::run_with_preflight_retries(
                            &fleet, 2, &mut retry_owner, &listener, &policy, reject_address, cert,
                            handles[2], br#"{"username":"fixture","password":"synthetic"}"#,
                            &resources[2], &mut retry_acquisitions, scoped_camera_provider.clone(), fences[2],
                            peer, &retry_operation, handoff::Framing::ContentLength, Duration::from_secs(10), &mut retry_trace, &preflight_progress, preflight_policy,
                        ).await;
                        RetryCompletion { operation: completion_operation, output }
                    });
                    struct DenyLogin;
                    impl camera_http::Authority for DenyLogin {
                        fn permits(&self, _: Ipv4Addr, _: u64, _: camera_http::Operation) -> bool { false }
                    }
                    struct DenyAdmission;
                    impl setup::Admission for DenyAdmission {
                        fn permits(&self, _: &discovery::CameraCandidate, _: ContentDigest, _: ContentDigest, _: u64, _: u64) -> bool { false }
                    }
                    let deny_login = DenyLogin;
                    let deny_admission = DenyAdmission;
                    let third_owner = Rc::new(RefCell::new(setup::Owner {
                        cx, task, clock, effects: &mut third_effects, leases: &leases,
                        approval: &Approval, admission: &policy, handoff_authority: &Handoff,
                    }));
                    let mut third_acquisition = fss_unifi_scoped_tls_entropy_lab::owned::offload::Acquisition::begin(
                        task, cx, clock, &resources[2], 128,
                    )?;
                    let mut third_trace = setup::Trace::default();
                    third_trace.require_reported_video(profile_limits(full_resolution))?;
                    let mut retry_offered = Some(retry_future);
                    let mut retry_factory = |_: usize, _: Enrollment| retry_offered.take().ok_or_else(|| io::ErrorKind::AlreadyExists.into());
                    let retry_policy = discovery::retry::Policy::new(Duration::from_millis(500), Duration::from_millis(500), 2)?;
                    let queue = discovery::retry::Queue::new(&fleet, task, cx, clock, retry_policy)?;
                    let mut retry_queue = RetryCoordinator::new(queue).map_err(|_| "retry queue was not empty")?;
                    let mut retry_auto = AutomaticWork::new(&fleet, 1).map_err(|_| "automatic retry capacity")?;
                    let mut retry_streams = ActiveStreams::new(&fleet, 2).map_err(|_| "retry stream capacity")?;
                    let retry_stream_polls = Rc::new(Cell::new(0usize));
                    let stream_counter = retry_stream_polls.clone();
                    assert!(retry_streams.insert(0, Box::pin(poll_fn(move |_| { stream_counter.set(stream_counter.get()+1); Poll::<Test>::Pending }))).is_ok());
                    let other_queue = discovery::retry::Queue::new(&other_fleet, task, cx, clock, retry_policy)?;
                    let mut wrong_retry_queue = RetryCoordinator::new(other_queue).map_err(|_| "wrong queue not empty")?;
                    assert!(matches!(supply.next_with_retries_and_streams(&mut pump, &mut retry_auto, &mut retry_streams, &mut wrong_retry_queue, &mut retry_factory).await,
                        Err(RetryLoopError::Binding)));
                    assert_eq!(retry_stream_polls.get(), 0);
                    assert!(matches!(supply.next_with_retries_and_streams(&mut pump, &mut retry_auto, &mut retry_streams, &mut retry_queue, &mut retry_factory).await.map_err(|e| format!("retry admission: {e:?}"))?,
                        RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Started { index: 2 }), retry: None }));
                    let saw_preflight_wait = timeout(cx.now(), Duration::from_secs(5), poll_fn(|context| {
                        let mut wait = std::pin::pin!(supply.next_with_retries_and_streams(&mut pump, &mut retry_auto, &mut retry_streams, &mut retry_queue, &mut retry_factory));
                        match wait.as_mut().poll(context) {
                            Poll::Pending if preflight_progress.retries() == 1 => Poll::Ready(true),
                            Poll::Pending => Poll::Pending,
                            Poll::Ready(_) => Poll::Ready(false),
                        }
                    })).await?;
                    assert!(saw_preflight_wait && preflight_progress.attempts() == 1 && retry_auto.pending_len() == 1);
                    loop {
                        match timeout(cx.now(), Duration::from_secs(15), supply.next_with_retries_and_streams(&mut pump, &mut retry_auto, &mut retry_streams, &mut retry_queue, &mut retry_factory)).await?.map_err(|e| format!("retry setup: {e:?}"))? {
                            RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Camera { index: 2, output })), retry: Some(disposition) } => {
                                assert!(matches!(output.output, Err(camera_setup::Error::Setup(_))));
                                if changed_readback {
                                    assert!(matches!(output.output, Err(camera_setup::Error::Setup(discovery::fleet::Error::Setup(setup::Error::Camera(camera_http::Error::Camera(camera_api::Error::HttpStatus)))))));
                                    assert_eq!(disposition, discovery::pump::RetryDisposition::NotEligible);
                                    assert!(retry_queue.is_empty());
                                    retry_queue.schedule_explicit_for(2, &retry_operation)?;
                                } else {
                                    assert!(matches!(output.output, Err(camera_setup::Error::Setup(discovery::fleet::Error::Setup(setup::Error::Camera(camera_http::Error::Io(io::ErrorKind::UnexpectedEof)))))));
                                    assert_eq!(disposition, discovery::pump::RetryDisposition::Scheduled);
                                }
                                break;
                            }
                            RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Work(Some(SupplyEvent::Started(_)) | Some(SupplyEvent::Installed(_)))))), .. } => (),
                            _ => return Err("unexpected pre-effect setup retry event".into()),
                        }
                    }
                    assert_eq!(retry_queue.len(), 1);
                    assert!(retry_stream_polls.get() > 0);
                    assert!(matches!(fleet.state(2), Some(discovery::fleet::State::Finished { .. })));
                    assert_eq!(retry_auto.rearm(2), Err(RearmRefusal::NotReady));
                    let parked = poll_fn(|context| {
                        let mut wait = std::pin::pin!(supply.next_with_retries_and_streams(&mut pump, &mut retry_auto, &mut retry_streams, &mut retry_queue, &mut retry_factory));
                        Poll::Ready(wait.as_mut().poll(context).is_pending())
                    }).await;
                    assert!(parked && retry_queue.len() == 1 && retry_streams.len() == 1);
                    loop {
                        match timeout(cx.now(), Duration::from_secs(5), supply.next_with_retries_and_streams(&mut pump, &mut retry_auto, &mut retry_streams, &mut retry_queue, &mut retry_factory)).await?.map_err(|e| format!("retry timer: {e:?}"))? {
                            RetryingFleetEvent::Retry { event: discovery::retry::Event::Rearmed { index: 2, state: discovery::fleet::State::Ready { .. } }, selection: RetrySelection::Released } => break,
                            RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Work(Some(SupplyEvent::Started(_)) | Some(SupplyEvent::Installed(_)))))), .. } => (),
                            _ => return Err("unexpected retry timer event".into()),
                        }
                    }
                    assert!(retry_queue.is_empty());
                    drop(retry_factory);
                    drop(retry_offered);
                    reject_peer.finish()?;
                    let enrolled = fleet.enrollment(2).ok_or("missing enrollment")?;
                    let mut setup_queue = fss_unifi_scoped_tls_entropy_lab::prepared_setup::Queue::new(&fleet, 2, 4)?;
                    {
                        use fss_unifi_scoped_tls_entropy_lab::prepared_setup::{PreparedSetup, Queue, Refusal};
                        let mut bounded = Queue::new(&fleet, 1, 1)?;
                        let polls = Rc::new(Cell::new(0));
                        let touched = polls.clone();
                        let operation = OperationId::parse("operation:unpolled-queue-check")?;
                        let first: CameraWork<'_, Result<setup::Outcome, camera_setup::Error>> = Box::pin(async move {
                            touched.set(touched.get() + 1);
                            Err(camera_setup::Error::Binding)
                        });
                        bounded.enqueue(PreparedSetup::new(2, enrolled, operation.clone(), first))
                            .map_err(|(reason, _)| format!("bounded queue admission: {reason:?}"))?;
                        let rejected: CameraWork<'_, Result<setup::Outcome, camera_setup::Error>> = Box::pin(async { panic!("refused future polled") });
                        let (reason, rejected) = bounded.enqueue(PreparedSetup::new(
                            2, enrolled, OperationId::parse("operation:unpolled-queue-overflow")?, rejected,
                        )).err().ok_or("queue capacity was exceeded")?;
                        assert_eq!(reason, Refusal::Capacity);
                        drop(rejected.into_parts());
                        assert!(matches!(bounded.take(2, fleet.enrollment(0).ok_or("missing other enrollment")?), Err(error) if error.kind() == io::ErrorKind::PermissionDenied));
                        let retained = bounded.into_pending();
                        assert_eq!(retained.len(), 1);
                        assert_eq!(retained[0].operation(), &operation);
                        assert_eq!(polls.get(), 0);
                        drop(retained);
                        let mut eager = Queue::new(&fleet, 2, 2)?;
                        let first_id = OperationId::parse("operation:queue-first")?;
                        let second_id = OperationId::parse("operation:queue-second")?;
                        for (operation, value) in [(first_id.clone(), 1), (second_id.clone(), 2)] {
                            let counter = polls.clone();
                            let future: CameraWork<'_, usize> = Box::pin(async move {
                                counter.set(counter.get() + 1);
                                value
                            });
                            eager.enqueue(PreparedSetup::new(2, enrolled, operation, future))
                                .map_err(|(reason, _)| format!("preloaded queue admission: {reason:?}"))?;
                        }
                        assert_eq!(polls.get(), 0);
                        let first = eager.take(2, enrolled)?.await;
                        assert_eq!((first.operation, first.output), (first_id, 1));
                        let second = eager.take(2, enrolled)?.await;
                        assert_eq!((second.operation, second.output), (second_id, 2));
                        assert_eq!(polls.get(), 2);
                        assert!(eager.into_pending().is_empty());
                    }

                    // Construct the next camera attempt before any deadline
                    // occurs. It remains unpolled in the queue until the
                    // retry coordinator makes this enrollment ready again.
                    let third_listener = std::net::TcpListener::bind((PEERS[2], 0))?;
                    let SocketAddr::V4(third_address) = third_listener.local_addr()? else {
                        return Err("IPv4 required".into());
                    };
                    let operation_work = operations[2].clone();
                    let owner_work = third_owner.clone();
                    let provider_work = scoped_camera_provider.clone();
                    let (fleet_work, listener_work, policy_work, resource_work) = (&fleet, &listener, &policy, &resources[2]);
                    let (acquisition_work, trace_work) = (&mut third_acquisition, &mut third_trace);
                    let fresh_polled = Rc::new(Cell::new(false));
                    let fresh_polled_work = fresh_polled.clone();
                    let mut fresh_future: Option<CameraWork<'_, Result<setup::Outcome, camera_setup::Error>>> = Some(Box::pin(async move {
                        fresh_polled_work.set(true);
                        let mut owner = owner_work.borrow_mut();
                        camera_setup::run_with_acquisition(
                            fleet_work, 2, &mut owner, listener_work, policy_work, third_address, cert,
                            handles[2], br#"{"username":"fixture","password":"synthetic"}"#,
                            resource_work, acquisition_work, provider_work, fences[2],
                            peer, &operation_work, handoff::Framing::ContentLength, Duration::from_secs(10), trace_work,
                        ).await
                    }));

                    // A witnessed deadline after preparation must retain its
                    // evidence before the existing scheduler admits a retry.
                    if capacity == 2 && !full_resolution && !changed_readback {
                        let timeout_listener = std::net::TcpListener::bind((PEERS[2], 0))?;
                        let SocketAddr::V4(timeout_address) = timeout_listener.local_addr()? else {
                            return Err("IPv4 required".into());
                        };
                        let timeout_server = server.clone();
                        let timeout_port = endpoint.port();
                        let timeout_peer = Joined(Some(std::thread::spawn(move || {
                            camera_fixture_with_gate(timeout_listener, timeout_port, peer, timeout_server, None, None, false, true)
                        })));
                        third_owner.borrow_mut().approval = &SLOW_APPROVAL;
                        let timeout_operation = OperationId::parse("operation:synthetic-deadline-recovery")?;
                        let deadline_trace = Rc::new(RefCell::new(setup::Trace::default()));
                        let preflight_trace = Rc::new(camera_setup::PreflightRetryTrace::default());
                        let preflight_policy = camera_setup::PreflightRetryPolicy::new(1, Duration::from_millis(10))?;
                        let acquisitions = Rc::new(RefCell::new([fss_unifi_scoped_tls_entropy_lab::owned::offload::Acquisition::begin(task, cx, clock, &resources[2], 128)?]));
                        let spool = Rc::new(RefCell::new(fss_object::StagingSpool::open(
                            temp.0.join("deadline-evidence"), fss_object::SpoolLimits::new(4, 4096, 1024, 4),
                        )?));
                        let recovery = Rc::new(RefCell::new(None));
                        let (owner_work, trace_work, acquisitions_work, spool_work, recovery_work, preflight_work) =
                            (third_owner.clone(), deadline_trace.clone(), acquisitions.clone(), spool.clone(), recovery.clone(), preflight_trace.clone());
                        let operation_work = timeout_operation.clone();
                        let provider_work = scoped_camera_provider.clone();
                        let (fleet_work, listener_work, policy_work, resource_work) = (&fleet, &listener, &policy, &resources[2]);
                        let future: CameraWork<'_, Result<setup::Outcome, camera_setup::Error>> = Box::pin(async move {
                            let mut owner = owner_work.borrow_mut();
                            let mut trace = trace_work.borrow_mut();
                            let mut acquisitions = acquisitions_work.borrow_mut();
                            let mut spool = spool_work.borrow_mut();
                            let output = camera_setup::run_with_preflight_retries_and_deadline_recovery(
                                fleet_work, 2, &mut owner, listener_work, policy_work, timeout_address, cert,
                                handles[2], br#"{"username":"fixture","password":"synthetic"}"#,
                                resource_work, &mut *acquisitions, provider_work, fences[2],
                                peer, &operation_work, handoff::Framing::ContentLength, Duration::from_secs(3),
                                &mut trace, &preflight_work, preflight_policy, &mut spool, resource_work,
                            ).await;
                            *recovery_work.borrow_mut() = output.deadline_recovery;
                            output.outcome
                        });
                        setup_queue.enqueue(fss_unifi_scoped_tls_entropy_lab::prepared_setup::PreparedSetup::new(
                            2, enrolled, timeout_operation.clone(), future,
                        )).map_err(|(reason, _)| format!("deadline queue admission: {reason:?}"))?;
                        let duplicate: CameraWork<'_, Result<setup::Outcome, camera_setup::Error>> = Box::pin(async { panic!("duplicate future polled") });
                        let (reason, duplicate) = setup_queue.enqueue(fss_unifi_scoped_tls_entropy_lab::prepared_setup::PreparedSetup::new(
                            2, enrolled, timeout_operation.clone(), duplicate,
                        )).err().ok_or("duplicate operation accepted")?;
                        assert_eq!(reason, fss_unifi_scoped_tls_entropy_lab::prepared_setup::Refusal::DuplicateOperation);
                        drop(duplicate.into_parts());
                        assert_eq!(setup_queue.len(), 1);
                        assert!(matches!(setup_queue.take(2, fleet.enrollment(0).ok_or("missing other enrollment")?), Err(error) if error.kind() == io::ErrorKind::PermissionDenied));
                        assert_eq!(setup_queue.len(), 1);
                        setup_queue.enqueue(fss_unifi_scoped_tls_entropy_lab::prepared_setup::PreparedSetup::new(
                            2, enrolled, operations[2].clone(), fresh_future.take().ok_or("missing prebuilt setup")?,
                        )).map_err(|(reason, _)| format!("prebuilt setup admission: {reason:?}"))?;
                        assert_eq!(setup_queue.len(), 2);
                        assert!(!fresh_polled.get());
                        let mut factory = |index: usize, enrollment: Enrollment| setup_queue.take(index, enrollment);
                        assert!(matches!(supply.next_with_retries_and_streams(&mut pump, &mut retry_auto, &mut retry_streams, &mut retry_queue, &mut factory).await.map_err(|e| format!("deadline admission: {e:?}"))?,
                            RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Started { index: 2 }), .. }));
                        loop {
                            match timeout(cx.now(), Duration::from_secs(15), supply.next_with_retries_and_streams(&mut pump, &mut retry_auto, &mut retry_streams, &mut retry_queue, &mut factory)).await?.map_err(|e| format!("deadline setup: {e:?}"))? {
                                RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Camera { index: 2, output })), retry: Some(discovery::pump::RetryDisposition::Scheduled) } => {
                                    assert!(matches!(output.output, Err(camera_setup::Error::Setup(discovery::fleet::Error::Setup(setup::Error::Deadline)))));
                                    break;
                                }
                                RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Work(Some(SupplyEvent::Started(_)) | Some(SupplyEvent::Installed(_)))))), .. } => (),
                                _ => return Err("unexpected deadline setup event".into()),
                            }
                        };
                        loop {
                            match timeout(cx.now(), Duration::from_secs(5), supply.next_with_retries_and_streams(&mut pump, &mut retry_auto, &mut retry_streams, &mut retry_queue, &mut factory)).await?.map_err(|e| format!("deadline timer: {e:?}"))? {
                                RetryingFleetEvent::Retry { event: discovery::retry::Event::Rearmed { index: 2, state: discovery::fleet::State::Ready { .. } }, selection: RetrySelection::Released } => break,
                                RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Work(Some(SupplyEvent::Started(_)) | Some(SupplyEvent::Installed(_)))))), .. } => (),
                                _ => return Err("unexpected deadline retry event".into()),
                            }
                        }
                        drop(factory);
                        assert_eq!(setup_queue.len(), 1);
                        assert!(!fresh_polled.get());
                        let reused: CameraWork<'_, Result<setup::Outcome, camera_setup::Error>> = Box::pin(async { panic!("used operation future polled") });
                        let (reason, reused) = setup_queue.enqueue(fss_unifi_scoped_tls_entropy_lab::prepared_setup::PreparedSetup::new(
                            2, enrolled, timeout_operation.clone(), reused,
                        )).err().ok_or("consumed operation accepted again")?;
                        assert_eq!(reason, fss_unifi_scoped_tls_entropy_lab::prepared_setup::Refusal::DuplicateOperation);
                        drop(reused.into_parts());
                        let evidence = recovery.borrow_mut().take().ok_or("deadline recovery skipped")??;
                        assert_eq!(spool.borrow().state(evidence), Some(fss_object::SpoolObjectState::Verified));
                        assert!(deadline_trace.borrow().preparation_cancelled());
                        assert_eq!(third_owner.borrow().effects.journal().operation(&timeout_operation).ok_or("lost preparation")?.state, fss_core::EffectState::Cancelled);
                        third_owner.borrow_mut().approval = &Approval;
                        timeout_peer.finish()?;
                    }

                    // Carry the newly discovered and owner-enrolled camera
                    // through the actual synthetic HTTPS setup owner while the
                    // existing camera handshake remains stalled and owned.
                    let third_server = server.clone();
                    let gate = Arc::new(AtomicBool::new(false));
                    let login_seen = Arc::new(AtomicBool::new(false));
                    let third_gate = (capacity == 2).then(|| gate.clone());
                    let third_seen = (capacity == 2).then(|| login_seen.clone());
                    let third_fixture = Joined(Some(std::thread::spawn(move || {
                        camera_fixture_with_gate(third_listener, endpoint.port(), peer, third_server, third_gate, third_seen, changed_readback, false)
                    })));
                    // Refuse a pin or credential-handle mismatch before any
                    // connection or credential-bearing HTTP operation.
                    let probe = std::net::TcpListener::bind((PEERS[2], 0))?;
                    probe.set_nonblocking(true)?;
                    let SocketAddr::V4(probe_address) = probe.local_addr()? else {
                        return Err("IPv4 required".into());
                    };
                    let other_probe = std::net::TcpListener::bind((PEERS[1], probe_address.port())).map_err(|e| io::Error::new(e.kind(), format!("secondary TCP probe: {e}")))?;
                    other_probe.set_nonblocking(true)?;
                    let wrong_certificate = std::fs::read("tests/fixtures/ca.der")?;
                    for failure in 0..6 {
                        let lease = acquire(task, cx, clock, &resources[2]).await?;
                        let mut trace = setup::Trace::default();
                        let candidate_cert: &[u8] = if failure == 0 { &wrong_certificate } else { cert };
                        let handle = if failure == 1 { handles[0] } else { handles[2] };
                        let candidate_address = if failure == 2 { SocketAddrV4::new(PEERS[1], probe_address.port()) } else { probe_address };
                        let resource = if failure == 3 { &resources[1] } else { &resources[2] };
                        let http_auth: &dyn camera_http::Authority = if failure == 4 { &deny_login } else { &policy };
                        let mut owner = third_owner.borrow_mut();
                        owner.admission = if failure == 5 { &deny_admission } else { &policy };
                        let result = camera_setup::run(
                            &fleet, 2, &mut owner, &listener, http_auth, candidate_address,
                            candidate_cert, handle, br#"{"username":"fixture","password":"synthetic"}"#,
                            resource, lease, scoped_camera_provider.clone(), fences[2], peer,
                            &operations[2], handoff::Framing::ContentLength, Duration::from_secs(5), &mut trace,
                        ).await;
                        if failure < 4 {
                            assert!(matches!(result, Err(camera_setup::Error::Binding)));
                        } else {
                            assert!(matches!(result, Err(camera_setup::Error::Authority)));
                        }
                        assert!(trace.operation().is_none());
                        assert!(matches!(probe.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
                        assert!(matches!(other_probe.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
                    }
                    third_owner.borrow_mut().admission = &policy;
                    let mut denied_acquisitions = [
                        fss_unifi_scoped_tls_entropy_lab::owned::offload::Acquisition::begin(task, cx, clock, &resources[2], 128)?,
                        fss_unifi_scoped_tls_entropy_lab::owned::offload::Acquisition::begin(task, cx, clock, &resources[2], 128)?,
                    ];
                    let denied_progress = camera_setup::PreflightRetryTrace::default();
                    let mut denied_trace = setup::Trace::default();
                    let denied_operation = OperationId::parse("operation:denied-preflight-retry")?;
                    assert!(matches!(camera_setup::run_with_preflight_retries(
                        &fleet, 2, &mut third_owner.borrow_mut(), &listener, &deny_login, probe_address, cert, handles[2],
                        br#"{"username":"fixture","password":"synthetic"}"#, &resources[2], &mut denied_acquisitions,
                        scoped_camera_provider.clone(), fences[2], peer, &denied_operation, handoff::Framing::ContentLength,
                        Duration::from_secs(5), &mut denied_trace, &denied_progress, preflight_policy,
                    ).await, Err(camera_setup::Error::Authority)));
                    assert_eq!(denied_progress.attempts(), 1);
                    assert_eq!(denied_progress.retries(), 0);
                    assert!(denied_trace.operation().is_none());
                    assert!(denied_acquisitions[0].is_drained() && !denied_acquisitions[1].is_drained());
                    denied_acquisitions[1].abort();
                    assert!(timeout(cx.now(), Duration::from_secs(5), denied_acquisitions[1].join()).await?.is_err());
                    assert!(matches!(probe.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
                    // Wrong acquisition binding must not consume the retained owner
                    // or open a socket; it can still be cancelled and drained.
                    let mut wrong_acquisition = fss_unifi_scoped_tls_entropy_lab::owned::offload::Acquisition::begin(
                        task, cx, clock, &resources[1], 128,
                    )?;
                    let mut refused_trace = setup::Trace::default();
                    assert!(matches!(camera_setup::run_with_acquisition(
                        &fleet, 2, &mut third_owner.borrow_mut(), &listener, &policy, probe_address, cert,
                        handles[2], br#"{"username":"fixture","password":"synthetic"}"#,
                        &resources[2], &mut wrong_acquisition, scoped_camera_provider.clone(), fences[2],
                        peer, &operations[2], handoff::Framing::ContentLength, Duration::from_secs(5), &mut refused_trace,
                    ).await, Err(camera_setup::Error::Binding)));
                    assert!(!wrong_acquisition.is_drained());
                    wrong_acquisition.abort();
                    assert!(timeout(cx.now(), Duration::from_secs(5), wrong_acquisition.join()).await?.is_err());
                    assert!(wrong_acquisition.is_drained());
                    assert!(refused_trace.operation().is_none());
                    assert!(matches!(probe.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
                    if let Some(future) = fresh_future.take() {
                        setup_queue.enqueue(fss_unifi_scoped_tls_entropy_lab::prepared_setup::PreparedSetup::new(
                            2, enrolled, operations[2].clone(), future,
                        )).map_err(|(reason, _)| format!("fresh queue admission: {reason:?}"))?;
                    }
                    drop(fresh_future);
                    let factory_calls = Rc::new(Cell::new(0usize));
                    let setup_calls = factory_calls.clone();
                    let mut setup_factory = |index: usize, enrollment: Enrollment| {
                        setup_calls.set(setup_calls.get() + 1);
                        if index != 2 || enrollment.camera() != cameras[2] {
                            return Err(io::ErrorKind::InvalidInput.into());
                        }
                        setup_queue.take(index, enrollment)
                    };
                    assert!(matches!(
                        supply.next_with_retries_and_streams(&mut pump, &mut retry_auto, &mut retry_streams, &mut retry_queue, &mut setup_factory).await.map_err(|e| format!("retry success admission: {e:?}"))?,
                        RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Started { index: 2 }), .. }
                    ));
                    assert_eq!(retry_auto.pending_len(), 1);
                    assert_eq!(factory_calls.get(), 1);
                    if capacity == 2 {
                        let parked = poll_fn(|context| {
                            let mut wait = std::pin::pin!(supply.next_with_retries_and_streams(
                                &mut pump, &mut retry_auto, &mut retry_streams, &mut retry_queue, &mut setup_factory,
                            ));
                            Poll::Ready(wait.as_mut().poll(context).is_pending())
                        }).await;
                        assert!(parked && retry_auto.pending_len() == 1 && factory_calls.get() == 1);
                    }
                    let mut parallel_peer = if capacity == 2 {
                        let client = client.clone();
                        let login_seen = login_seen.clone();
                        Some(Joined(Some(std::thread::spawn(move || {
                            let deadline = Instant::now() + Duration::from_secs(10);
                            while !login_seen.load(Ordering::Acquire) {
                                if Instant::now() >= deadline {
                                    return Err(io::Error::new(io::ErrorKind::TimedOut, "setup login did not begin"));
                                }
                                std::thread::sleep(Duration::from_millis(10));
                            }
                            stream_fixture::camera(endpoint, PEERS[1], client, "001122aabbdd",
                                Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(true)), full_resolution)
                        }))))
                    } else { None };
                    let mut parallel_finished = false;
                    let mut second_replenished = false;
                    let mut concurrent_effects_slot = Some(&mut concurrent_effects);
                    let outcome = loop {
                        match timeout(cx.now(), Duration::from_secs(15), supply.next_with_retries_and_streams(&mut pump, &mut retry_auto, &mut retry_streams, &mut retry_queue, &mut setup_factory)).await?.map_err(|e| format!("retry success setup: {e:?}"))? {
                            RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Camera { index: 2, output })), retry: Some(discovery::pump::RetryDisposition::NotEligible) } => break output.output?,
                            RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Event(PumpEvent::Route(Event::Session { index: 1, session }))))), .. } => {
                                assert!(!parallel_finished);
                                assert!(login_seen.load(Ordering::Acquire));
                                assert_eq!(session.claimed_mac(), MACS[1]);
                                let session = match retry_streams.admit_routed_session(&retry_auto, 999, session, |_, _| -> TrackedStreamWork<'_, Test> { panic!("invalid enrollment reached factory") }) {
                                    Err(RoutedStreamAdmission::Session { reason: RoutedStreamRefusal::UnknownEnrollment, session }) => session,
                                    _ => return Err("unknown enrollment did not retain session".into()),
                                };
                                let session = match retry_streams.admit_routed_session(&retry_auto, 2, session, |_, _| -> TrackedStreamWork<'_, Test> { panic!("mismatched claim reached factory") }) {
                                    Err(RoutedStreamAdmission::Session { reason: RoutedStreamRefusal::ClaimMismatch, session }) => session,
                                    _ => return Err("mismatched enrollment did not retain session".into()),
                                };
                                let mut stopped_auto: AutomaticWork<'_, '_, '_, RetryCompletion<Test>> = AutomaticWork::new(&fleet, 1).map_err(|_| "stopped work capacity")?;
                                stopped_auto.request_stop();
                                let session = match retry_streams.admit_routed_session(&stopped_auto, 1, session, |_, _| -> TrackedStreamWork<'_, Test> { panic!("stopped admission reached factory") }) {
                                    Err(RoutedStreamAdmission::Session { reason: RoutedStreamRefusal::Stopped, session }) => session,
                                    _ => return Err("shutdown did not retain session".into()),
                                };
                                let mut full_streams = ActiveStreams::new(&fleet, 1).map_err(|_| "full stream capacity")?;
                                assert!(full_streams.insert(0, Box::pin(std::future::pending::<Test>())).is_ok());
                                let session = match full_streams.admit_routed_session(&retry_auto, 1, session, |_, _| -> TrackedStreamWork<'_, Test> { panic!("full stream set reached factory") }) {
                                    Err(RoutedStreamAdmission::Session { reason: RoutedStreamRefusal::Capacity, session }) => session,
                                    _ => return Err("capacity refusal did not retain session".into()),
                                };
                                drop(full_streams.into_pending().ok().ok_or("unexpected completion fence")?);
                                let stream_effects = concurrent_effects_slot.take().ok_or("stream effect owner missing")?;
                                let stream_effect_binding = stream_effects.binding();
                                let stream_leases = &leases;
                                let stream_policy = &policy;
                                let stream_resource = &resources[1];
                                let management = management::Preconditions { camera: cameras[1], peer_admission: admissions[1], session_generation: 1, previous_association: None, previous_clock: None, lease_fence: fences[1] };
                                let stream_conditions = intent::Preconditions { camera: cameras[1], peer_admission: admissions[1], stream_generation: 1, previous_settings: None, lease_fence: fences[1] };
                                let result = retry_streams.admit_routed_session(&retry_auto, 1, session, |enrollment, session| {
                                  assert_eq!(enrollment.mac(), MACS[1]);
                                  let work: CameraWork<'_, Test> = Box::pin(async move {
                                    let mut session = session;
                                    let guard = Guard { leases: stream_leases, clock, mac: MACS[1] };
                                    let mut conversation = conversation::Owner { cx, task, clock, effects: stream_effects, leases: stream_leases, approval: &Approval, management_authority: &guard, stream_authority: &guard, wall: &Wall };
                                    let hello = OperationId::parse("operation:concurrent-media-hello")?;
                                    let agreement = OperationId::parse("operation:concurrent-media-agreement")?;
                                    let stream = OperationId::parse("operation:concurrent-media-start")?;
                                    let request = listener::Start { bind: SocketAddrV4::new(peer, 0), resource: stream_resource, admission: stream_policy, channel: if full_resolution { VideoChannel::Video1 } else { VideoChannel::Video2 }, video: VideoCodec::H264, audio: AudioCodec::Aac, stream_name: "0123456789abcdef", hello: &hello, agreement: &agreement, stream: &stream, time_sync: &[], management, stream_conditions, chunk_bytes: 4096, max_bytes: 1_000_000, bind_wait: Duration::from_secs(10), conversation_wait: Duration::from_secs(10), accept_wait: Duration::from_secs(10) };
                                    let framer = Framer::new(FlvLimits::default(), 1024 * 1024)?;
                                    let recorder = recording::Recorder::new(SourceKey { connection: 2, generation: 1 }, recording::Limits::default())?;
                                    let mut trace = listener::StartTrace::default();
                                    let mut pipeline = listener::start_tracked(&mut conversation, &mut session, &request, framer, recorder, &mut trace).await?.pipeline;
                                    let mut frames = 0usize;
                                    loop {
                                        match pipeline.step(task, cx, clock.now()?).await? {
                                            pipeline::Step::Recording(recording::Push::Segment(segment)) => {
                                                let mut movie = pipeline.initialization().ok_or("missing concurrent init")?.bytes().to_vec();
                                                movie.extend_from_slice(segment.fragment().bytes());
                                                let demux = AvcMp4::parse(&movie, None, DemuxLimits::default())?;
                                                let count = demux.samples().len().min(3);
                                                if count == 0 { return Err("empty concurrent fragment".into()); }
                                                let annex = demux.annex_b(0, count)?;
                                                let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                                                let mut pictures = decoder.decode_annex_b(annex.bytes())?;
                                                pictures.extend(decoder.finish()?);
                                                if full_resolution { assert!(pictures.iter().all(|p| p.width() == 2688 && p.height() == 1512)); }
                                                frames += pictures.len();
                                            }
                                            pipeline::Step::Recording(_) | pipeline::Step::Progress { .. } => (),
                                            pipeline::Step::Eof => break,
                                            pipeline::Step::LimitReached => return Err("concurrent media limit".into()),
                                        }
                                    }
                                    assert!(frames > 0);
                                    let _ = pipeline.retire();
                                    let _ = session.retire();
                                    Ok(())
                                  });
                                  TrackedStreamWork { work, effects: stream_effect_binding }
                                });
                                if result.is_err() { return Err("concurrent stream refused".into()); }
                            }
                            RetryingFleetEvent::Fleet { event: FleetStreamEvent::Stream { index: 1, output }, .. } => {
                                output?;
                                assert!(login_seen.load(Ordering::Acquire));
                                assert_eq!(retry_auto.pending_len(), 1);
                                gate.store(true, Ordering::Release);
                                parallel_peer.take().ok_or("parallel peer missing")?.finish()?;
                                parallel_finished = true;
                            }
                            RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Work(Some(SupplyEvent::Started(1)))))), .. } => (),
                            RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Work(Some(SupplyEvent::Installed(1)))))), .. } => second_replenished = true,
                            _ => return Err("unexpected event while driving third setup".into()),
                        }
                    };
                    assert!(fresh_polled.get());
                    assert_eq!(parallel_finished, capacity == 2);
                    assert!(matches!(&outcome, setup::Outcome::Observed { readback: handoff::Readback::Requested, .. }));
                    let selected = outcome.select_reported_video(profile_limits(full_resolution))?.ok_or("setup had no profile observation")?;
                    let selected_channel = selected.selected.ok_or("no reported profile fits")?.0;
                    assert_eq!(selected_channel, if full_resolution { VideoChannel::Video1 } else { VideoChannel::Video2 });
                    assert_eq!(retry_auto.pending_len(), 0);
                    assert!(matches!(fleet.state(2), Some(discovery::fleet::State::Finished { .. })));
                    assert_eq!(retry_auto.rearm(2), Err(RearmRefusal::NotReady));
                    assert!(retry_queue.is_empty());
                    retry_auto.request_stop();
                    assert!(retry_auto.into_pending().is_empty());
                    let _unresolved_retry_owner = match retry_streams.into_pending() {
                        Err(owner) if parallel_finished => {
                            assert_eq!(owner.len(), 1);
                            assert_eq!(owner.pending_completion(1).map(|v| v.generation()), Some(1));
                            Some(owner)
                        }
                        Ok(pending) if !parallel_finished => { assert_eq!(pending.len(), 1); drop(pending); None }
                        _ => return Err("unexpected stream completion disposition".into()),
                    };
                    drop(setup_factory);
                    assert!(setup_queue.is_empty());
                    assert!(setup_queue.into_pending().is_empty());
                    let preflight = third_trace.preflight_video().and_then(|selection| selection.selected);
                    if changed_readback {
                        assert_ne!(preflight, selected.selected);
                        assert!(!third_trace.reported_video_matches(&outcome));
                        assert!(!fleet.route_ready(2));
                        assert!(fleet.reported_video(2).is_none());
                    } else {
                        assert_eq!(preflight, selected.selected);
                        assert!(third_trace.reported_video_matches(&outcome));
                        assert!(fleet.route_ready(2));
                        assert_eq!(fleet.reported_video(2), selected.selected);
                    }
                    assert!(retry_acquisitions.iter().all(|a| a.is_drained()));
                    assert_eq!(preflight_progress.attempts(), 2);
                    assert_eq!(preflight_progress.retries(), 1);
                    assert!(retry_trace.operation().is_none());
                    drop(retry_owner);
                    assert!(third_acquisition.is_drained());
                    assert_eq!(third_trace.operation(), Some(&operations[2]));
                    drop(third_owner);
                    third_fixture.finish()?;
                    assert_eq!(pump.driver().handshake_len(), 1);
                    if parallel_finished {
                        while !second_replenished {
                            match timeout(cx.now(), Duration::from_secs(5), supply.next_with_pump(&mut pump)).await?? {
                                Progress::Work(Some(SupplyEvent::Started(1))) => (),
                                Progress::Work(Some(SupplyEvent::Installed(1))) => second_replenished = true,
                                _ => return Err("parallel camera lease did not replenish".into()),
                            }
                        }
                    }
                    if capacity == 1 {
                        let socket = asupersync::net::TcpSocket::new_v4()?;
                        socket.bind(SocketAddr::V4(SocketAddrV4::new(PEERS[1], 0)))?;
                        let mut refused = socket.connect(SocketAddr::V4(endpoint)).await?;
                        assert!(matches!(
                            pump.next().await,
                            PumpEvent::Route(Event::HandshakeCapacity { index: 1 })
                        ));
                        let mut byte = [0u8; 1];
                        assert!(matches!(
                            timeout(cx.now(), Duration::from_secs(5), refused.read(&mut byte))
                                .await?,
                            Ok(0)
                        ));
                    } else {
                        let stream_seen = Arc::new(AtomicBool::new(false));
                        let stream_release = Arc::new(AtomicBool::new(false));
                        let controller_release = Arc::new(AtomicBool::new(false));
                        let third_seen = stream_seen.clone();
                        let third_release = stream_release.clone();
                        let third_controller_release = controller_release.clone();
                        let third_client = client.clone();
                        let third_route = Joined(Some(std::thread::spawn(move || {
                            stream_fixture::camera_with_hold(endpoint, PEERS[2], third_client, "001122aabbee", third_seen, third_release, full_resolution, Some(third_controller_release))
                        })));
                        let concurrent_seen = stream_seen.clone();
                        let concurrent_client = client.clone();
                        let concurrent = Joined(Some(std::thread::spawn(move || {
                            let deadline = Instant::now() + Duration::from_secs(10);
                            while !concurrent_seen.load(Ordering::Acquire) {
                                if Instant::now() >= deadline { return Err(io::Error::new(io::ErrorKind::TimedOut, "stream did not start")); }
                                std::thread::sleep(Duration::from_millis(5));
                            }
                            camera_upgrade_peer(endpoint, PEERS[1], concurrent_client, "001122aabbdd")
                        })));
                        let mut third_session = match timeout(cx.now(), Duration::from_secs(5), pump.next()).await? {
                            PumpEvent::Route(Event::Session { index: 2, session }) => session,
                            _ => return Err("newly set up camera failed to route".into()),
                        };
                        assert_eq!(third_session.claimed_mac(), MACS[2]);
                        let management = management::Preconditions { camera: cameras[2], peer_admission: admissions[2], session_generation: 1, previous_association: None, previous_clock: None, lease_fence: fences[2] };
                        let stream_conditions = intent::Preconditions { camera: cameras[2], peer_admission: admissions[2], stream_generation: 1, previous_settings: None, lease_fence: fences[2] };
                        let guard = Guard { leases: &leases, clock, mac: MACS[2] };
                        let mut conversation = conversation::Owner { cx, task, clock, effects: &mut effects, leases: &leases, approval: &Approval, management_authority: &guard, stream_authority: &guard, wall: &Wall };
                        let hello = OperationId::parse("operation:parallel-stream-hello")?;
                        let agreement = OperationId::parse("operation:parallel-stream-agreement")?;
                        let stream = OperationId::parse("operation:parallel-stream-start")?;
                        let request = listener::Start { bind: SocketAddrV4::new(peer, 0), resource: &resources[2], admission: &policy, channel: selected_channel, video: VideoCodec::H264, audio: AudioCodec::Aac, stream_name: "0123456789abcdef", hello: &hello, agreement: &agreement, stream: &stream, time_sync: &[], management, stream_conditions, chunk_bytes: 4096, max_bytes: 1_000_000, bind_wait: Duration::from_secs(10), conversation_wait: Duration::from_secs(10), accept_wait: Duration::from_secs(10) };
                        let framer = Framer::new(FlvLimits::default(), 1024 * 1024)?;
                        let recorder = recording::Recorder::new(SourceKey { connection: 1, generation: 1 }, recording::Limits::default())?;
                        let mut trace = listener::StartTrace::default();
                        let trace_ref = &mut trace;
                        let archive_base = temp.0.clone();
                        let archive_resource = &resources[2];
                        let release_guard = ReleaseOnDrop(controller_release);
                        let mut active_streams = ActiveStreams::new(&fleet, 2).map_err(|_| "stream capacity refused")?;
                        let stream_work: CameraWork<'_, Test> = Box::pin(async move {
                        let _release_guard = release_guard;
                        let started = listener::start_tracked(&mut conversation, &mut third_session, &request, framer, recorder, trace_ref).await?;
                        let supervisor = supervisor::Supervisor::new(third_session, started.pipeline, management);
                        let retention = ContentDigest::sha256(b"scoped fleet fixture retention");
                        let source = SourceKey { connection: 1, generation: 1 };
                        let access = Arc::new(FixtureAccess(retention));
                        let replay_authority = fss_core::region::ContextAuthority::new_root(RootAuthoritySpec {
                            trace_id: "trace:scoped-fleet-replay".into(),
                            operation_id: OperationId::parse("operation:scoped-fleet-replay")?,
                            principal: "principal:fixture".into(), capabilities: vec!["ADP-REPLAY-001".into()],
                            deadline: None, priority: 1, budgets: budget,
                            privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
                            anchor_universe: ContentDigest::sha256(b"scoped fleet replay"), generation: 1,
                        })?;
                        let source_replay = fss_reference::ReplayCx::from_context_authority(&replay_authority, archive_base.clone())?;
                        let video_replay = fss_reference::ReplayCx::from_context_authority(&replay_authority, archive_base.clone())?;
                        let storage_root = archive_base.join("scoped-fleet-storage");
                        let created = recording_storage::create(task, cx, clock, recording_storage::Configuration {
                            root: &storage_root, site_lineage: "site:scoped-fleet", source,
                            camera_claim: cameras[2], source_retention: retention,
                            source_scope: ContentDigest::sha256(b"scoped fixture source"),
                            av_scope: ContentDigest::sha256(b"scoped fixture video"),
                            source_deployment_limits: fss_reference::DeploymentLimits::standard(),
                            av_deployment_limits: fss_reference::DeploymentLimits::standard(),
                            source_history_limits: EffectJournalLimits::default(),
                            av_history_limits: EffectJournalLimits::default(),
                            limits: archive::Limits::default(), max_source_bytes: 1024 * 1024,
                            work_limit: 4_000_000_000,
                        }, source_replay, video_replay, access.clone())?;
                        let mut bootstrap = video_bootstrap::Bootstrap::begin(
                            supervisor, created.coordinator.into_worker(), created.av, source, cameras[2],
                            video_bootstrap::Policy { inband: false, retention,
                                media_limits: fss_container::Mp4Limits::default(), evidence_limits: evidence::Limits::default() },
                        ).map_err(|_| "scoped video bootstrap refused")?;
                        let admission = source_coordinator::ArchiveAdmission { resource: archive_resource, cost: &BudgetVector::ZERO };
                        let mut step_number = 0usize;
                        let mut source_count = 0usize;
                        let mut pins = Vec::new();
                        loop {
                            if step_number >= 512 { return Err("scoped bootstrap step limit".into()); }
                            let op = OperationId::parse(format!("operation:scoped-archive-{step_number}"))?;
                            step_number += 1;
                            match bootstrap.step(&mut conversation, &op, Duration::from_millis(100), task, cx, clock, admission).await {
                                video_bootstrap::Step::SourceOffered(_) | video_bootstrap::Step::Configured | video_bootstrap::Step::SourceStarted => (),
                                video_bootstrap::Step::SourceArchive { control, completion } => {
                                    if let Some(control) = control { if control_event(control)? { return Err("media ended during bootstrap".into()); } }
                                    if let Some(completion) = completion { source_confirmed(completion)?; source_count += 1; }
                                }
                                video_bootstrap::Step::Supervisor(control) => if control_event(control)? { return Err("media ended during bootstrap".into()); },
                                video_bootstrap::Step::Ready => break,
                                _ => return Err("scoped bootstrap requires reconciliation".into()),
                            }
                        }
                        let mut recording = bootstrap.into_session().map_err(|_| "scoped video session handoff")?;
                        loop {
                            if step_number >= 512 { return Err("scoped recording step limit".into()); }
                            let op = OperationId::parse(format!("operation:scoped-archive-{step_number}"))?;
                            step_number += 1;
                            match recording.step(&mut conversation, &op, Duration::from_millis(100), task, cx, clock, admission, admission).await {
                                video_session::Step::SourceOffered(_) | video_session::Step::VideoOffered | video_session::Step::SourceStarted | video_session::Step::VideoStarted => (),
                                video_session::Step::SourceArchive { control, completion } => {
                                    if let Some(control) = control { if control_event(control)? { return Err("media ended during source archive".into()); } }
                                    if let Some(completion) = completion { source_confirmed(completion)?; source_count += 1; }
                                }
                                video_session::Step::VideoArchive { control, completion } => {
                                    if let Some(control) = control { if control_event(control)? { return Err("media ended during video archive".into()); } }
                                    if let Some(completion) = completion {
                                        if completion.runtime.is_err() { return Err("video archive worker failed".into()); }
                                        let published = match completion.outcome {
                                            video_worker::Outcome::Publication(video_worker::Publication::Published(value)) => value,
                                            _ => return Err("video archive requires reconciliation".into()),
                                        };
                                        if pins.len() == 16 || pins.contains(&published.pin) { return Err("invalid video history".into()); }
                                        pins.push(published.pin);
                                    }
                                }
                                video_session::Step::Supervisor(control) => if control_event(control)? { break; },
                                _ => return Err("scoped recording requires reconciliation".into()),
                            }
                        }
                        if pins.is_empty() || source_count == 0 { return Err("missing video or source publication".into()); }
                        let parts = recording.into_parts().map_err(|_| "scoped session not drained")?;
                        let retirement = parts.prepare_retirement().map_err(|_| "scoped retirement refused")?;
                        if retirement.time_sync.is_some() || retirement.controller.prepared.is_some()
                            || retirement.controller.agreement_id.is_some() || retirement.controller.hello_request_id.is_some()
                            || retirement.controller.time_sync_request_id.is_some() || retirement.controller.stream_request.is_some()
                            || retirement.controller.motion_request.is_some() || retirement.controller.event_reply.is_some()
                            || retirement.controller.rejected_message.is_some() { return Err("controller retirement requires reconciliation".into()); }
                        let mut tail = retirement.tail;
                        loop {
                            if step_number >= 512 { return Err("scoped tail step limit".into()); }
                            step_number += 1;
                            match tail.step(task, cx, clock, admission).await {
                                retirement_source::DriverStep::Offered { .. } | retirement_source::DriverStep::Started => (),
                                retirement_source::DriverStep::Completed(completion) => { source_confirmed(completion)?; source_count += 1; },
                                retirement_source::DriverStep::Finished => break,
                                _ => return Err("scoped tail requires reconciliation".into()),
                            }
                        }
                        let tail_parts = tail.into_parts().map_err(|_| "scoped tail worker not drained")?;
                        let mut video = retirement.video.retire().map_err(|_| "scoped video worker not retired")?;
                        let mut source_retired = tail_parts.worker.retire().map_err(|_| "scoped source worker not retired")?;
                        if video.fenced || video.report.is_some() || source_retired.fenced || source_retired.pending.is_some() { return Err("scoped archive requires reconciliation".into()); }
                        let video_page = video.parts.journal.confirmed_page(video.parts.journal.anchor(), 0, 128, &video.parts.replay)?;
                        let source_page = source_retired.parts.journal.confirmed_page(source_retired.parts.journal.anchor(), 0, 128, &source_retired.parts.replay)?;
                        if video_page.has_more || video_page.pending.is_some() || !pins.iter().copied().eq(video_page.entries.iter().map(|entry| entry.pin))
                            || source_page.has_more || source_page.pending.is_some() || source_page.entries.len() != source_count { return Err("scoped archive history mismatch".into()); }
                        let expected = stream_fixture::media_fixture(full_resolution)?;
                        let mut ranges = Vec::new();
                        for entry in &source_page.entries {
                            let recovered = archive::read_unknown_time_source(&mut source_retired.parts.deployment, entry.pin, access.as_ref(), archive::Limits::default(), &mut fss_geometry::WorkBudget::new(4_000_000_000), &source_retired.parts.replay)?;
                            let end = recovered.offset().checked_add(u64::try_from(recovered.bytes().len())?).ok_or("source overflow")?;
                            if recovered.key() != source || recovered.camera_claim() != cameras[2] || expected.get(usize::try_from(recovered.offset())?..usize::try_from(end)?) != Some(recovered.bytes()) { return Err("source readback mismatch".into()); }
                            ranges.push((recovered.offset(), end));
                        }
                        let mut frames = 0usize;
                        for pin in &pins {
                            let clip = archive::read_unknown_time_video_clip(&mut video.parts.deployment, *pin, access.as_ref(), archive::Limits::default(), &mut fss_geometry::WorkBudget::new(4_000_000_000), &video.parts.replay)?;
                            if clip.claimed_source() != source || clip.samples() == 0 { return Err("video readback binding".into()); }
                            for record in clip.source_records() {
                                let end = record.offset.checked_add(u64::try_from(record.length)?).ok_or("video source overflow")?;
                                let bytes = archive::read_unknown_time_object(&mut video.parts.deployment, *pin, record.digest, access.as_ref(), archive::Limits::default(), &mut fss_geometry::WorkBudget::new(4_000_000_000), &video.parts.replay)?;
                                if bytes.len() != record.length || expected.get(usize::try_from(record.offset)?..usize::try_from(end)?) != Some(bytes.as_slice()) { return Err("video source readback mismatch".into()); }
                                ranges.push((record.offset, end));
                            }
                            if frames == 0 {
                                let demux = AvcMp4::parse(clip.bytes(), None, DemuxLimits::default())?;
                                let annex = demux.annex_b(0, 1)?;
                                let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                                let mut pictures = decoder.decode_annex_b(annex.bytes())?;
                                pictures.extend(decoder.finish()?);
                                if full_resolution { assert!(pictures.iter().all(|picture| picture.width() == 2688 && picture.height() == 1512)); }
                                frames += pictures.len();
                            }
                        }
                        assert!(frames > 0);
                        ranges.sort_unstable();
                        let mut covered = 0u64;
                        for (start, end) in ranges { if start != covered || end <= start { return Err("source coverage gap or overlap".into()); } covered = end; }
                        if covered != u64::try_from(expected.len())? { return Err("source coverage incomplete".into()); }
                        Ok(())
                        });
                        assert!(active_streams.insert(2, stream_work).is_ok());
                        let mut stream_auto = AutomaticWork::<()>::new(&fleet, 1).map_err(|_| "automatic capacity refused")?;
                        stream_auto.request_stop();
                        let mut no_setup = |_: usize, _: Enrollment| -> io::Result<CameraWork<'_, ()>> { Err(io::ErrorKind::PermissionDenied.into()) };
                        let mut parallel_done = false;
                        let mut concurrent = Some(concurrent);
                        let mut refreshed = [false; 3];
                        let mut renewed_stall = false;
                        loop {
                            match timeout(cx.now(), Duration::from_secs(60), supply.next_with_setup_and_streams(&mut pump, &mut stream_auto, &mut active_streams, &mut no_setup)).await?? {
                                FleetStreamEvent::Stream { index: 2, output } => { output?; assert!(parallel_done); break; }
                                FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Event(PumpEvent::Route(Event::Session { index: 1, session }))))) => {
                                    assert!(stream_seen.load(Ordering::Acquire));
                                    stream_release.store(true, Ordering::Release);
                                    concurrent.take().ok_or("parallel stream peer missing")?.finish()?;
                                    drop(session);
                                    parallel_done = true;
                                }
                                FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Work(Some(SupplyEvent::Started(_)))))) => (),
                                FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Work(Some(SupplyEvent::Installed(i)))))) => refreshed[i] = true,
                                // An unmatched accept may expire while the already
                                // connected stream is being archived. Only tolerate
                                // this after the concurrent route has succeeded.
                                FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Event(PumpEvent::Route(Event::RouteRefused {
                                    index: None, reason: discovery::fleet::RouteError::Listener(listener::Error::Deadline),
                                }))))) if parallel_done => (),
                                FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Event(PumpEvent::Route(Event::HandshakeFailed {
                                    index: 0, reason: fss_reference::unifi_direct::controller_upgrade::Error::Deadline,
                                }))))) if !renewed_stall => {
                                    let mut byte = [0_u8; 1];
                                    assert!(matches!(timeout(cx.now(), Duration::from_secs(5), stalled.read(&mut byte)).await?, Ok(0)));
                                    let socket = asupersync::net::TcpSocket::new_v4()?;
                                    socket.bind(SocketAddr::V4(SocketAddrV4::new(PEERS[0], 0)))?;
                                    stalled = socket.connect(SocketAddr::V4(endpoint)).await?;
                                    renewed_stall = true;
                                }
                                FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Event(PumpEvent::Route(Event::RouteRefused { reason, .. }))))) => return Err(format!("archive stream route refused: {reason:?}").into()),
                                FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Event(PumpEvent::Route(Event::HandshakeFailed { index, reason }))))) => return Err(format!("archive stream handshake failed: index={index} reason={reason:?}").into()),
                                _ => return Err("unexpected fleet event while streaming".into()),
                            }
                        }
                        assert!(active_streams.is_empty());
                        assert!(stream_auto.into_pending().is_empty());
                        drop(active_streams);
                        assert!(trace.attempted());
                        third_route.finish()?;
                        while !refreshed[1] || !refreshed[2] {
                            match timeout(cx.now(), Duration::from_secs(5), supply.next_with_pump(&mut pump)).await?? {
                                Progress::Work(Some(SupplyEvent::Started(_))) => (),
                                Progress::Work(Some(SupplyEvent::Installed(i))) => refreshed[i] = true,
                                _ => return Err("camera lease did not replenish".into()),
                            }
                        }
                        let tls_client = client.clone();
                        let auto_stream_seen = Arc::new(AtomicBool::new(false));
                        let auto_peer_seen = auto_stream_seen.clone();
                        let candidate_hold = Arc::new(AtomicBool::new(false));
                        let candidate_proceed = Arc::new(AtomicBool::new(false));
                        let peer_hold = candidate_hold.clone();
                        let peer_proceed = candidate_proceed.clone();
                        let other = Joined(Some(std::thread::spawn(move || {
                            stream_fixture::camera_with_candidates(endpoint, PEERS[1], tls_client, "001122aabbdd", auto_peer_seen, Arc::new(AtomicBool::new(true)), full_resolution, peer_hold, peer_proceed)
                        })));
                        let auto_policy = discovery::retry::Policy::new(Duration::from_millis(50), Duration::from_millis(100), 1)?;
                        let queue = discovery::retry::Queue::new(&fleet, task, cx, clock, auto_policy)?;
                        let mut auto_retries = RetryCoordinator::new(queue).map_err(|_| "auto stream retry queue")?;
                        let mut auto_setup = AutomaticWork::new(&fleet, 1).map_err(|_| "auto stream setup capacity")?;
                        let mut auto_streams = ActiveStreams::new(&fleet, 1).map_err(|_| "auto stream capacity")?;
                        let mut no_setup = |_: usize, _: Enrollment| -> io::Result<CameraWork<'_, RetryCompletion<Test>>> { Err(io::ErrorKind::PermissionDenied.into()) };
                        let made = Rc::new(Cell::new(0usize));
                        let polled = Rc::new(Cell::new(0usize));
                        let release = Rc::new(Cell::new(false));
                        let media = AutoMedia { cx, task, clock, effects: Some(auto_effects), leases: &leases,
                            policy: &policy, resource: &resources[1], peer, camera: cameras[1],
                            admission: admissions[1], fence: fences[1], full_resolution, candidate_hold, candidate_proceed };
                        let mut make_stream = auto_media_factory(media, made.clone(), polled.clone(), release.clone());
                        let mut auto_lease_installed = false;
                        loop {
                            match timeout(cx.now(), Duration::from_secs(5), supply.next_with_automatic_streams(&mut pump, &mut auto_setup, &mut auto_streams, &mut auto_retries, &mut no_setup, &mut make_stream)).await?.map_err(|e| format!("automatic stream admission: {e:?}"))? {
                                AutoRoutedFleetEvent::StreamStarted { index: 1 } => break,
                                AutoRoutedFleetEvent::Progress(RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Work(Some(SupplyEvent::Started(_)))))), .. }) => (),
                                AutoRoutedFleetEvent::Progress(RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Work(Some(SupplyEvent::Installed(i)))))), .. }) => { if i == 1 { auto_lease_installed = true; } },
                                _ => return Err("automatic stream was not admitted".into()),
                            }
                        }
                        assert_eq!(made.get(), 1);
                        assert_eq!(polled.get(), 0);
                        assert_eq!(auto_streams.len(), 1);
                        let mut auto_streams = match auto_streams.into_pending() {
                            Err(owner) => owner,
                            Ok(_) => return Err("running automatic stream owner was discarded".into()),
                        };
                        let mut park_polls = 0;
                        loop {
                            park_polls += 1;
                            if park_polls > 16 { return Err("automatic stream did not reach parked state".into()); }
                            let one_poll = poll_fn(|context| {
                                let mut wait = std::pin::pin!(supply.next_with_automatic_streams(&mut pump, &mut auto_setup, &mut auto_streams, &mut auto_retries, &mut no_setup, &mut make_stream));
                                Poll::Ready(wait.as_mut().poll(context))
                            }).await;
                            match one_poll {
                                Poll::Pending if polled.get() > 0 => break,
                                Poll::Pending => (),
                                Poll::Ready(Ok(AutoRoutedFleetEvent::Progress(RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Work(Some(SupplyEvent::Started(_)))))), .. }))) => (),
                                Poll::Ready(Ok(AutoRoutedFleetEvent::Progress(RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Work(Some(SupplyEvent::Installed(i)))))), .. }))) => { if i == 1 { auto_lease_installed = true; } },
                                _ => return Err("automatic stream did not park safely".into()),
                            }
                        }
                        assert_eq!(auto_streams.len(), 1);
                        let before_resume = polled.get();
                        release.set(true);
                        let (completion, returned_effects) = loop {
                            match timeout(cx.now(), Duration::from_secs(30), supply.next_with_automatic_streams(&mut pump, &mut auto_setup, &mut auto_streams, &mut auto_retries, &mut no_setup, &mut make_stream)).await?.map_err(|e| format!("automatic stream completion: {e:?}"))? {
                                AutoRoutedFleetEvent::StreamFinished { index: 1, output: (result, returned_effects), completion } => { result?; break (completion, returned_effects); }
                                AutoRoutedFleetEvent::Progress(RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Work(Some(SupplyEvent::Started(_)))))), .. }) => (),
                                AutoRoutedFleetEvent::Progress(RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Work(Some(SupplyEvent::Installed(i)))))), .. }) => { if i == 1 { auto_lease_installed = true; } },
                                _ => return Err("automatic stream did not finish".into()),
                            }
                        };
                        assert!(polled.get() > before_resume);
                        assert!(auto_streams.is_empty());
                        assert!(auto_retries.is_empty());
                        assert_eq!(completion.index(), 1);
                        assert_eq!(completion.generation(), 1);
                        let mut auto_streams = match auto_streams.into_pending() {
                            Err(owner) => owner,
                            Ok(_) => return Err("unresolved automatic stream owner was discarded".into()),
                        };
                        assert_eq!(auto_streams.pending_completion(1).map(|v| v.generation()), Some(1));
                        let rejected_polled = Rc::new(Cell::new(false));
                        let rejected_flag = rejected_polled.clone();
                        let rejected = auto_streams.insert(1, Box::pin(poll_fn(move |_| {
                            rejected_flag.set(true);
                            Poll::Ready((Ok(()), EffectCoordinator::new()))
                        })));
                        assert!(matches!(rejected, Err((StreamRefusal::PreviousUnresolved, _))));
                        assert!(!rejected_polled.get());
                        let mut unrelated_streams = ActiveStreams::<(Test, EffectCoordinator)>::new(&fleet, 1).map_err(|_| "unrelated stream capacity")?;
                        assert_eq!(unrelated_streams.release_after_reconciliation(&completion, &EffectCoordinator::new()), Err(StreamCompletionRefusal::WrongOwner));
                        assert_eq!(auto_streams.release_after_reconciliation(&completion, &EffectCoordinator::new()), Err(StreamCompletionRefusal::WrongCoordinator));
                        assert_eq!(auto_streams.release_after_reconciliation(&completion, &returned_effects), Err(StreamCompletionRefusal::UnsettledEffects));
                        other.finish()?;
                        assert!(auto_stream_seen.load(Ordering::Acquire));
                        while !auto_lease_installed {
                            match timeout(cx.now(), Duration::from_secs(5), supply.next_with_pump(&mut pump)).await?? {
                                Progress::Work(Some(SupplyEvent::Started(_))) => (),
                                Progress::Work(Some(SupplyEvent::Installed(i))) => { if i == 1 { auto_lease_installed = true; } },
                                _ => return Err("automatic stream lease was not replenished".into()),
                            }
                        }
                        let tls_client = client.clone();
                        let unresolved_peer = Joined(Some(std::thread::spawn(move || {
                            camera_upgrade_peer(endpoint, PEERS[1], tls_client, "001122aabbdd")
                        })));
                        let mut after_unresolved_installed = false;
                        let mut refreshed_stall = false;
                        loop {
                            match timeout(cx.now(), Duration::from_secs(5), supply.next_with_automatic_streams(&mut pump, &mut auto_setup, &mut auto_streams, &mut auto_retries, &mut no_setup, &mut make_stream)).await?.map_err(|e| format!("unresolved stream admission: {e:?}"))? {
                                AutoRoutedFleetEvent::StreamRefused { index: 1, refusal: RoutedStreamAdmission::Session { reason: RoutedStreamRefusal::PreviousUnresolved, session } } => { drop(session); break; }
                                AutoRoutedFleetEvent::Progress(RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Work(Some(SupplyEvent::Started(_)))))), .. }) => (),
                                AutoRoutedFleetEvent::Progress(RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Work(Some(SupplyEvent::Installed(i)))))), .. }) => { if i == 1 { after_unresolved_installed = true; } },
                                // The intentionally silent camera-0 handshake has a
                                // real 30-second deadline. A slow full-resolution
                                // archive can outlive it; verify closure and renew
                                // that test fixture without relaxing the deadline.
                                AutoRoutedFleetEvent::Progress(RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Event(PumpEvent::Route(Event::HandshakeFailed {
                                    index: 0, reason: fss_reference::unifi_direct::controller_upgrade::Error::Deadline,
                                }))))), .. }) if !refreshed_stall => {
                                    let mut byte = [0_u8; 1];
                                    assert!(matches!(timeout(cx.now(), Duration::from_secs(5), stalled.read(&mut byte)).await?, Ok(0)));
                                    let socket = asupersync::net::TcpSocket::new_v4()?;
                                    socket.bind(SocketAddr::V4(SocketAddrV4::new(PEERS[0], 0)))?;
                                    stalled = socket.connect(SocketAddr::V4(endpoint)).await?;
                                    refreshed_stall = true;
                                }
                                AutoRoutedFleetEvent::Progress(RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Event(PumpEvent::Route(Event::RouteRefused { index, reason }))))), .. }) => return Err(format!("unresolved stream route refused: index={index:?} reason={reason:?}").into()),
                                AutoRoutedFleetEvent::Progress(RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Event(PumpEvent::Route(Event::HandshakeFailed { index, reason }))))), .. }) => return Err(format!("unresolved stream handshake failed: index={index} reason={reason:?}").into()),
                                _ => return Err("unresolved stream was not fenced".into()),
                            }
                        }
                        unresolved_peer.finish()?;
                        assert_eq!(made.get(), 1);
                        assert_eq!(auto_streams.pending_completion(1).map(|v| v.generation()), Some(1));
                        while !after_unresolved_installed {
                            match timeout(cx.now(), Duration::from_secs(5), supply.next_with_pump(&mut pump)).await?? {
                                Progress::Work(Some(SupplyEvent::Started(_))) => (),
                                Progress::Work(Some(SupplyEvent::Installed(i))) => { if i == 1 { after_unresolved_installed = true; } },
                                _ => return Err("unresolved stream lease was not replenished".into()),
                            }
                        }
                        auto_setup.request_stop();
                        let tls_client = client.clone();
                        let stopping_peer = Joined(Some(std::thread::spawn(move || {
                            camera_upgrade_peer(endpoint, PEERS[1], tls_client, "001122aabbdd")
                        })));
                        loop {
                            match timeout(cx.now(), Duration::from_secs(5), supply.next_with_automatic_streams(&mut pump, &mut auto_setup, &mut auto_streams, &mut auto_retries, &mut no_setup, &mut make_stream)).await?.map_err(|e| format!("stopped automatic stream: {e:?}"))? {
                                AutoRoutedFleetEvent::StreamRefused { index: 1, refusal: RoutedStreamAdmission::Session { reason: RoutedStreamRefusal::Stopped, session } } => { drop(session); break; }
                                AutoRoutedFleetEvent::Progress(RetryingFleetEvent::Fleet { event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(Supervised::Fleet(Progress::Work(Some(SupplyEvent::Started(_) | SupplyEvent::Installed(_)))))), .. }) => (),
                                _ => return Err("shutdown did not retain routed session".into()),
                            }
                        }
                        stopping_peer.finish()?;
                        assert_eq!(made.get(), 1);
                        assert!(auto_setup.into_pending().is_empty());
                        drop(make_stream);
                        // The preceding session consumed camera 1's only lease. Connect
                        // again before polling the supply, and poll the handshake twice:
                        // an empty slot must keep the route instead of refusing it.
                        let tls_client = client.clone();
                        let replacement = Joined(Some(std::thread::spawn(move || {
                            camera_upgrade_peer(endpoint, PEERS[1], tls_client, "001122aabbdd")
                        })));
                        timeout(
                            cx.now(),
                            Duration::from_secs(5),
                            poll_fn(|context| match pump.poll_next(context) {
                                Poll::Pending if pump.driver().handshake_len() == 2 => {
                                    Poll::Ready(Ok(()))
                                }
                                Poll::Pending => Poll::Pending,
                                Poll::Ready(_) => {
                                    Poll::Ready(Err("replacement route refused before lease wait"))
                                }
                            }),
                        )
                        .await??;
                        let parked = poll_fn(|context| match pump.poll_next(context) {
                            Poll::Pending => Poll::Ready(true),
                            Poll::Ready(_) => Poll::Ready(false),
                        })
                        .await;
                        if !parked || pump.driver().handshake_len() != 2 {
                            return Err("empty lease slot refused the waiting handshake".into());
                        }
                        let mut installed = false;
                        let session = loop {
                            match timeout(
                                cx.now(),
                                Duration::from_secs(5),
                                supply.next_with_pump(&mut pump),
                            )
                            .await??
                            {
                                Progress::Work(Some(SupplyEvent::Started(1))) => (),
                                Progress::Work(Some(SupplyEvent::Installed(1))) => installed = true,
                                Progress::Event(PumpEvent::Route(Event::Session {
                                    index: 1,
                                    session,
                                })) => break session,
                                _ => {
                                    return Err(
                                        "waiting handshake did not resume after replenishment"
                                            .into(),
                                    );
                                }
                            }
                        };
                        assert!(
                            installed,
                            "waiting connection resumed without an installed lease"
                        );
                        assert_eq!(session.claimed_mac(), MACS[1]);
                        replacement.finish()?;
                        drop(session);
                    }
                    supply.request_stop();
                    loop {
                        match timeout(
                            cx.now(),
                            Duration::from_secs(5),
                            supply.next_with_pump(&mut pump),
                        )
                        .await??
                        {
                            Progress::Work(Some(SupplyEvent::Drained(_))) => (),
                            Progress::Work(Some(SupplyEvent::Stopped)) => break,
                            _ => return Err("supply did not drain".into()),
                        }
                    }
                    assert!(supply.next().await.is_none());
                    drop(supply);
                    // Shutdown while a different camera is waiting for an
                    // unavailable lease must close that actual routed socket.
                    let mut waiting = if capacity == 2 {
                        let socket = asupersync::net::TcpSocket::new_v4()?;
                        socket.bind(SocketAddr::V4(SocketAddrV4::new(PEERS[1], 0)))?;
                        let waiting = socket.connect(SocketAddr::V4(endpoint)).await?;
                        timeout(
                            cx.now(),
                            Duration::from_secs(5),
                            poll_fn(|context| match pump.poll_next(context) {
                                Poll::Pending if pump.driver().handshake_len() == 2 => {
                                    Poll::Ready(Ok(()))
                                }
                                Poll::Pending => Poll::Pending,
                                Poll::Ready(_) => {
                                    Poll::Ready(Err("shutdown waiting route refused"))
                                }
                            }),
                        )
                        .await??;
                        let parked = poll_fn(|context| match pump.poll_next(context) {
                            Poll::Pending => Poll::Ready(true),
                            Poll::Ready(_) => Poll::Ready(false),
                        })
                        .await;
                        assert!(parked, "empty lease handshake did not remain owned");
                        Some(waiting)
                    } else {
                        None
                    };
                    drop(pump);
                    drop(acceptor);
                    let mut byte = [0u8; 1];
                    if let Some(waiting) = waiting.as_mut() {
                        assert!(matches!(
                            timeout(cx.now(), Duration::from_secs(5), waiting.read(&mut byte))
                                .await?,
                            Ok(0)
                        ));
                    }
                    assert!(matches!(
                        timeout(cx.now(), Duration::from_secs(5), stalled.read(&mut byte)).await?,
                        Ok(0)
                    ));
                    Ok(())
                }
                .await;
                TaskCompletion {
                    outcome: if output.is_ok() {
                        TaskOutcome::Indeterminate("fixture handoffs require reconciliation".into())
                    } else {
                        TaskOutcome::Failed("parallel fleet fixture failed".into())
                    },
                    output,
                    completed_at: TimestampNs(599_000_000_000),
                }
            },
        )
        .await?;
        run.receipt?;
        run.output
    })
}

#[test]
fn task_owned_fleet_routes_two_synthetic_cameras() -> Test {
    // This integration fixture builds a single very large async state machine.
    // Keep its stack budget explicit; this is not a production stack proof.
    std::thread::Builder::new()
        .name("scoped-fleet-fixture".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(|| run_fleet_scenarios().map_err(|error| error.to_string()))?
        .join()
        .map_err(|_| "scoped fleet fixture thread panicked")?
        .map_err(Into::into)
}

#[test]
fn deadline_recovery_schedules_over_synthetic_tls() -> Test {
    std::thread::Builder::new()
        .name("scoped-deadline-fixture".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let (peer, cert, key) = fleet_fixture_inputs().map_err(|error| error.to_string())?;
            parallel_fleet_upgrade_scenario(peer, &cert, &key, 2, false, false)
                .map_err(|error| error.to_string())
        })?
        .join()
        .map_err(|_| "deadline fixture thread panicked")?
        .map_err(Into::into)
}

fn fleet_fixture_inputs() -> Result<(Ipv4Addr, Vec<u8>, Vec<u8>), Box<dyn Error>> {
    // Setup intentionally refuses loopback controller destinations. Select an
    // address assigned to this worker; the synthetic cameras are loopback-only.
    let interfaces = std::process::Command::new("ip")
        .args(["-o", "-4", "addr", "show", "scope", "global"])
        .output()?;
    if !interfaces.status.success() {
        return Err("cannot inspect local interfaces".into());
    }
    let text = std::str::from_utf8(&interfaces.stdout)?;
    let peer = text
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            let index = fields.iter().position(|value| *value == "inet")?;
            fields
                .get(index + 1)?
                .split('/')
                .next()?
                .parse::<Ipv4Addr>()
                .ok()
        })
        .find(|ip| ip.is_private() && !ip.is_unspecified() && *ip != Ipv4Addr::new(192, 168, 1, 10))
        .ok_or("no local private interface for the fixture")?;
    let cert = std::fs::read("tests/fixtures/cert.der")?;
    let key = std::fs::read("tests/fixtures/key.der")?;
    Ok((peer, cert, key))
}

fn run_fleet_scenarios() -> Test {
    let (peer, cert, key) = fleet_fixture_inputs()?;
    parallel_fleet_upgrade_scenario(peer, &cert, &key, 2, false, false)?;
    parallel_fleet_upgrade_scenario(peer, &cert, &key, 2, true, false)?;
    parallel_fleet_upgrade_scenario(peer, &cert, &key, 1, false, false)?;
    parallel_fleet_upgrade_scenario(peer, &cert, &key, 1, false, true)
}

#[derive(Debug)]
struct ForbiddenRandom;
impl rustls::crypto::SecureRandom for ForbiddenRandom {
    fn fill(&self, _: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        panic!("ambient server randomness used")
    }
}
#[derive(Debug)]
struct ForbiddenKx;
impl rustls::crypto::SupportedKxGroup for ForbiddenKx {
    fn start(&self) -> Result<Box<dyn rustls::crypto::ActiveKeyExchange>, rustls::Error> {
        panic!("ambient server kx used")
    }
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}
static FORBIDDEN_RANDOM: ForbiddenRandom = ForbiddenRandom;
static FORBIDDEN_KX: ForbiddenKx = ForbiddenKx;
#[derive(Debug)]
struct ForbiddenP256;
impl rustls::crypto::SupportedKxGroup for ForbiddenP256 {
    fn start(&self) -> Result<Box<dyn rustls::crypto::ActiveKeyExchange>, rustls::Error> {
        panic!("ambient P-256 key exchange used")
    }
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp256r1
    }
}
static FORBIDDEN_P256: ForbiddenP256 = ForbiddenP256;
