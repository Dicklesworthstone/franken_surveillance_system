#![forbid(unsafe_code)]
#![cfg(unix)]
//! Synthetic private-interface exercise of setup through TLS and WebSocket.

use asupersync::runtime::RuntimeBuilder;
use fss_container::{
    demux::{AvcMp4, DemuxLimits},
    flv_avc::SourceKey,
};
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_object::{
    HostSpoolIo,
    effect_journal::{EffectJournalLimits, FileEffectJournal},
};
use fss_packet::extended_flv::{Limits as FlvLimits, stream::Framer};
use fss_reference::unifi_direct::{
    AudioCodec, Controller, Identity, VideoChannel, VideoCodec, camera_api, camera_http,
    controller_listener, controller_upgrade, conversation, discovery, handoff, intent, listener, management,
    metered::{MeteredClock, MeteredIo},
    owner::PeerAdmission,
    archive, evidence, pipeline, recording, recording_storage, retirement_source, setup, source_worker, supervisor,
    video_bootstrap, video_session, video_worker,
    upgrade::ProtocolPolicy,
};
use fss_runtime::{
    authority::AuthorityCx,
    effect::{CommitApproval, CommittedEffect, EffectCoordinator, PreparedEffect},
    execution::{TaskCompletion, TaskSpec, run_owned_async},
    lease::LeaseRegistry,
};
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
use unifi_tls_05_server_lab::{camera_tls, setup_upgrade};

type Test = Result<(), Box<dyn Error>>;
const MAC: [u8; 6] = [0, 0x11, 0x22, 0xaa, 0xbb, 0xcc];
const HEAD: &str = "GET / HTTP/1.1\r\nHost: camera.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nCamera-Mac: 001122aabbcc\r\nSec-WebSocket-Protocol: secure_transfer\r\n\r\n";
const HELLO: &[u8] = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_hello","messageId":7,"payload":{}}"#;

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
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

struct Admission {
    peer: Ipv4Addr,
    listen: Ipv4Addr,
    camera: ContentDigest,
    admission: ContentDigest,
    fence: u64,
    allow_other_source: bool,
}
impl setup::Admission for Admission {
    fn permits(
        &self,
        candidate: &discovery::CameraCandidate,
        camera: ContentDigest,
        peer_admission: ContentDigest,
        generation: u64,
        fence: u64,
    ) -> bool {
        *candidate.source().ip() == self.peer
            && candidate.mac() == Some(MAC)
            && camera == self.camera
            && peer_admission == self.admission
            && generation == 1
            && fence == self.fence
    }
}
impl camera_http::Authority for Admission {
    fn permits(&self, peer: Ipv4Addr, generation: u64, _: camera_http::Operation) -> bool {
        peer == self.peer && generation == 1
    }
}
impl listener::Admission for Admission {
    fn listener(&self, requested: SocketAddrV4, bound: Option<SocketAddrV4>) -> bool {
        *requested.ip() == self.listen
            && bound.is_none_or(|v| *v.ip() == self.listen && v.port() != 0)
    }
    fn peer(&self, bound: SocketAddrV4, source: SocketAddrV4) -> bool {
        *bound.ip() == self.listen
            && (*source.ip() == self.peer
                || (self.allow_other_source && *source.ip() == Ipv4Addr::new(127, 0, 0, 2)))
    }
}
impl PeerAdmission for Admission {
    fn permits(&self, claim: [u8; 6]) -> bool {
        claim == MAC
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

struct Guard<'a, 'scope, 'task> {
    leases: &'a RefCell<LeaseRegistry>,
    clock: MeteredClock<'scope, 'task>,
}
impl fss_reference::unifi_direct::receive::ManagementAuthority for Guard<'_, '_, '_> {
    fn permits(&self, mac: [u8; 6], intent: management::Intent, permit: &CommittedEffect) -> bool {
        let Ok(now) = self.clock.now() else {
            return false;
        };
        mac == MAC
            && permit.fence() == intent.fence()
            && self
                .leases
                .borrow_mut()
                .check_fence(&intent.resource(), intent.fence(), now)
                .is_ok()
    }
}
impl fss_reference::unifi_direct::receive::StreamAuthority for Guard<'_, '_, '_> {
    fn permits(&self, mac: [u8; 6], intent: intent::Intent, permit: &CommittedEffect) -> bool {
        let Ok(now) = self.clock.now() else {
            return false;
        };
        mac == MAC
            && permit.fence() == intent.fence()
            && self
                .leases
                .borrow_mut()
                .check_fence(&intent.resource(), intent.fence(), now)
                .is_ok()
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

fn discovery_packet(peer: Ipv4Addr) -> Vec<u8> {
    discovery_packet_for(peer, MAC)
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
        let body = match index {
            1 => format!(r#"{{"controller":{{"port":{port}}}}}"#),
            2 | 3 | 5 => r#"{"controller":{"addr":"192.168.1.10"}}"#.to_owned(),
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
    }
    Ok(())
}

fn frame(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 126);
    let mask = [1, 2, 3, 4];
    let mut bytes = vec![0x82, 0x80 | payload.len() as u8];
    bytes.extend_from_slice(&mask);
    bytes.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    bytes
}

fn receive_binary(socket: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut head = [0; 2];
    socket.read_exact(&mut head)?;
    if head[0] != 0x82 || head[1] & 0x80 != 0 {
        return Err(io::Error::other("invalid server frame"));
    }
    let len = match head[1] {
        n @ 0..=125 => usize::from(n),
        126 => {
            let mut n = [0; 2];
            socket.read_exact(&mut n)?;
            usize::from(u16::from_be_bytes(n))
        }
        _ => return Err(io::Error::other("frame too large")),
    };
    if len > 4096 {
        return Err(io::Error::other("frame bound"));
    }
    let mut payload = vec![0; len];
    socket.read_exact(&mut payload)?;
    Ok(payload)
}

fn message_id(message: &str) -> io::Result<u64> {
    let value = message
        .split_once("\"messageId\":")
        .map(|(_, suffix)| {
            suffix
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .unwrap_or("")
        })
        .ok_or_else(|| io::Error::other("missing request id"))?;
    value.parse().map_err(io::Error::other)
}

fn flv_tag(timestamp: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut tag = vec![
        9,
        (n >> 16) as u8,
        (n >> 8) as u8,
        n as u8,
        (timestamp >> 16) as u8,
        (timestamp >> 8) as u8,
        timestamp as u8,
        (timestamp >> 24) as u8,
        0,
        0,
        0,
    ];
    tag.extend_from_slice(payload);
    tag.extend_from_slice(&(11_u32 + n as u32).to_be_bytes());
    tag
}

fn media_fixture() -> TestMedia {
    media_fixture_from(
        include_bytes!("../../../crates/fss-packet/tests/fixtures/avc/baseline.264"),
        3,
    )
}

fn media_fixture_from(source: &[u8], cycle: usize) -> TestMedia {
    media_fixture_from_frames(source, cycle, 7)
}

fn media_fixture_from_frames(source: &[u8], cycle: usize, frames: usize) -> TestMedia {
    let nals: Vec<_> = fss_codec_h264::annex_b_nal_units(source).collect();
    let sps = nals
        .iter()
        .copied()
        .find(|n| n[0] & 31 == 7)
        .ok_or("missing SPS")?;
    let pps = nals
        .iter()
        .copied()
        .find(|n| n[0] & 31 == 8)
        .ok_or("missing PPS")?;
    let pictures: Vec<_> = nals
        .into_iter()
        .filter(|n| matches!(n[0] & 31, 1 | 5))
        .collect();
    if pictures.len() != 4 || pictures[0][0] & 31 != 5 || !(1..=pictures.len()).contains(&cycle) {
        return Err("unexpected fixture pictures".into());
    }
    let mut config = vec![0x17, 0, 0, 0, 0, 1, sps[1], sps[2], sps[3], 0xff, 0xe1];
    config.extend_from_slice(&u16::try_from(sps.len())?.to_be_bytes());
    config.extend_from_slice(sps);
    config.push(1);
    config.extend_from_slice(&u16::try_from(pps.len())?.to_be_bytes());
    config.extend_from_slice(pps);
    let mut wire = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    wire.extend(flv_tag(0, &config));
    for index in 0..frames {
        let nal = pictures[index % cycle];
        let mut payload = vec![0x17, 1, 0, 0, 0];
        payload.extend_from_slice(&u32::try_from(nal.len())?.to_be_bytes());
        payload.extend_from_slice(nal);
        wire.extend(flv_tag(index as u32 * 40, &payload));
    }
    Ok(wire)
}
type TestMedia = Result<Vec<u8>, Box<dyn Error>>;

fn scenario(
    peer: Ipv4Addr,
    cert: &[u8],
    key: &[u8],
    send_tls: bool,
    drop_initial: bool,
    wrong_retry: bool,
) -> Test {
    let provider = Arc::new(rustls_pure::provider());
    let server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
        )?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert.to_vec()))?;
    let client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let path = std::fs::canonicalize(std::env::temp_dir())?.join(format!(
        "fss-setup-upgrade-{}-{send_tls}",
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
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 2_000_000;
    budget.bytes = 2_000_000;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:setup-upgrade".into(),
            operation_id: OperationId::parse("operation:setup-upgrade")?,
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
            ]
            .iter()
            .map(|v| v.as_str().into())
            .collect(),
            deadline: Some(TimestampNs(600_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"setup upgrade fixture"),
            generation: 1,
        },
        RegionId::new("region:setup-upgrade")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let camera = ContentDigest::sha256(b"fixture camera");
    let admission_digest = ContentDigest::sha256(b"fixture admission");
    let resource = format!("camera:{}", camera.to_text());
    let mut leases = LeaseRegistry::new();
    let fence = leases
        .acquire(&resource, "region:setup-upgrade", None, TimestampNs(2))?
        .fence;
    let leases = RefCell::new(leases);
    let operation = OperationId::parse("operation:setup-upgrade-handoff")?;
    let hello = OperationId::parse("operation:setup-upgrade-hello")?;
    let agreement = OperationId::parse("operation:setup-upgrade-agreement")?;
    let stream = OperationId::parse("operation:setup-upgrade-stream")?;
    let wire = media_fixture()?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("runtime context")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:setup-upgrade")?,
                started_at: TimestampNs(3),
            },
            &cx,
            async |task, cx| {
                let output: Test = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(4))?;
                    let policy = Admission {
                        peer: Ipv4Addr::LOCALHOST,
                        listen: peer,
                        camera,
                        admission: admission_digest,
                        fence,
                        allow_other_source: wrong_retry,
                    };
                    let udp = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
                    udp.set_read_timeout(Some(Duration::from_secs(15)))?;
                    let target = match udp.local_addr()? {
                        SocketAddr::V4(v) => v,
                        _ => return Err("IPv4 required".into()),
                    };
                    let discovery_peer = Joined(Some(std::thread::spawn(move || {
                        let mut input = [0_u8; 64];
                        let (_, source) = udp.recv_from(&mut input)?;
                        udp.send_to(&discovery_packet(Ipv4Addr::LOCALHOST), source)?;
                        Ok(())
                    })));
                    let discovery_cfg = discovery::Config::new(
                        Ipv4Addr::LOCALHOST,
                        8,
                        target,
                        "fixture:discovery",
                        Duration::from_millis(150),
                        8,
                    )?;
                    let report =
                        discovery::discover(task, cx, clock.now()?, &discovery_cfg).await?;
                    discovery_peer.finish()?;
                    if report.cameras.len() != 1 {
                        return Err("fixture discovery count".into());
                    }
                    let mut listener = controller_listener::Listener::bind(
                        task,
                        cx,
                        clock,
                        &policy,
                        SocketAddrV4::new(peer, 0),
                        &resource,
                        Duration::from_secs(5),
                    )
                    .await
                    .map_err(|e| format!("listener: {e:?}"))?;
                    let listener_address = listener.local_addr();
                    if send_tls {
                        let bad_listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
                        bad_listener.set_nonblocking(true)?;
                        let SocketAddr::V4(bad_address) = bad_listener.local_addr()? else { return Err("IPv4 required".into()) };
                        let bad_config = Arc::new(server.clone());
                        let bad_peer = Joined(Some(std::thread::spawn(move || -> io::Result<()> {
                            let limit = Instant::now() + Duration::from_secs(10);
                            let (raw, _) = loop {
                                match bad_listener.accept() {
                                    Ok(peer) => break peer,
                                    Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < limit => std::thread::sleep(Duration::from_millis(10)),
                                    Err(e) => return Err(e),
                                }
                            };
                            raw.set_nonblocking(false)?;
                            raw.set_read_timeout(Some(Duration::from_secs(5)))?;
                            raw.set_write_timeout(Some(Duration::from_secs(5)))?;
                            let mut tls = StreamOwned::new(rustls::ServerConnection::new(bad_config).map_err(io::Error::other)?, raw);
                            match tls.read(&mut [0u8; 1]) {
                                Err(_) | Ok(0) => Ok(()),
                                Ok(_) => Err(io::Error::other("mismatched pin received application data")),
                            }
                        })));
                        let mut wrong_pin = cert.to_vec();
                        *wrong_pin.last_mut().ok_or("empty certificate")? ^= 1;
                        let denied = camera_tls::connect(cx, task, clock, bad_address, &wrong_pin, &resource, Duration::from_secs(5)).await;
                        if !matches!(denied, Err(camera_tls::Error::Handshake)) {
                            return Err("mismatched camera certificate was not rejected".into());
                        }
                        bad_peer.finish()?;
                    }
                    let camera_listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
                    let camera_address = camera_listener.local_addr()?;
                    let camera_tls_config = Arc::new(server.clone());
                    let camera_peer = Joined(Some(std::thread::spawn(move || {
                        camera_fixture(camera_listener, listener_address.port(), peer, camera_tls_config)
                    })));
                    let controller_peer =
                        Joined(Some(std::thread::spawn(move || -> io::Result<()> {
                            if drop_initial {
                                let first = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
                                first.bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).into())?;
                                first.connect_timeout(&SocketAddr::V4(listener_address).into(), Duration::from_secs(10))?;
                                drop(first);
                            }
                            let socket =
                                Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
                            let source=if wrong_retry {Ipv4Addr::new(127,0,0,2)} else {Ipv4Addr::LOCALHOST};
                            socket.bind(&SocketAddr::V4(SocketAddrV4::new(source, 0)).into())?;
                            socket.connect_timeout(
                                &SocketAddr::V4(listener_address).into(),
                                Duration::from_secs(10),
                            )?;
                            let raw: std::net::TcpStream = socket.into();
                            if wrong_retry {return Ok(());}
                            raw.set_read_timeout(Some(Duration::from_secs(15)))?;
                            raw.set_write_timeout(Some(Duration::from_secs(15)))?;
                            if !send_tls {
                                return Ok(());
                            }
                            let connection = ClientConnection::new(
                                Arc::new(client),
                                ServerName::try_from("localhost").map_err(io::Error::other)?,
                            )
                            .map_err(io::Error::other)?;
                            let mut tls = StreamOwned::new(connection, raw);
                            let mut handshake = HEAD.as_bytes().to_vec();
                            handshake.extend(frame(HELLO));
                            tls.write_all(&handshake)?;
                            tls.flush()?;
                            let mut response = Vec::new();
                            let mut byte = [0_u8; 1];
                            while !response.ends_with(b"\r\n\r\n") {
                                tls.read_exact(&mut byte)?;
                                response.push(byte[0]);
                                if response.len() > 4096 {
                                    return Err(io::Error::other("upgrade limit"));
                                }
                            }
                            if !response.starts_with(b"HTTP/1.1 101 ") {
                                return Err(io::Error::other("upgrade refused"));
                            }
                            if !receive_binary(&mut tls)?.windows(b"ubnt_avclient_hello".len()).any(|w| w == b"ubnt_avclient_hello") {
                                return Err(io::Error::other("missing hello reply"));
                            }
                            let agreement_request = receive_binary(&mut tls)?;
                            if !agreement_request.windows(b"ubnt_avclient_paramAgreement".len()).any(|w| w == b"ubnt_avclient_paramAgreement") {
                                return Err(io::Error::other("missing agreement"));
                            }
                            let agreement_id = message_id(std::str::from_utf8(&agreement_request).map_err(io::Error::other)?)?;
                            let reply = format!(r#"{{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_paramAgreement","messageId":8,"inResponseTo":{agreement_id}}}"#);
                            tls.write_all(&frame(reply.as_bytes()))?;
                            tls.flush()?;
                            let stream_request = receive_binary(&mut tls)?;
                            let message = std::str::from_utf8(&stream_request).map_err(io::Error::other)?;
                            let destination: SocketAddr = message.split_once("tcp://")
                                .and_then(|(_, suffix)| suffix.split_once('?'))
                                .map(|(address, _)| address)
                                .ok_or_else(|| io::Error::other("missing media destination"))?
                                .parse().map_err(io::Error::other)?;
                            if !matches!(destination, SocketAddr::V4(address) if *address.ip() == peer && address.port() != 0) {
                                return Err(io::Error::other("unexpected media destination"));
                            }
                            let stream_id = message_id(message)?;
                            let reply = format!(r#"{{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ChangeVideoSettings","messageId":9,"inResponseTo":{stream_id}}}"#);
                            tls.write_all(&frame(reply.as_bytes()))?;
                            tls.flush()?;
                            let media = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
                            media.bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).into())?;
                            media.connect_timeout(&destination.into(), Duration::from_secs(5))?;
                            let mut media: std::net::TcpStream = media.into();
                            media.write_all(&wire)?;
                            Ok(())
                        })));
                    let SocketAddr::V4(camera_address) = camera_address else { return Err("IPv4 required".into()) };
                    let tls = camera_tls::connect(cx, task, clock, camera_address, cert, &resource, Duration::from_secs(5)).await?;
                    let io = MeteredIo::with_clock(tls, clock, &resource, 4096)?;
                    let mut http = camera_http::Owner::new(
                        io,
                        task,
                        cx,
                        clock,
                        &policy,
                        Ipv4Addr::LOCALHOST,
                        1,
                        &resource,
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
                    let cfg = setup::Config {
                        report: &report,
                        index: 0,
                        camera,
                        peer_admission: admission_digest,
                        generation: 1,
                        fence,
                        destination: peer,
                        operation: &operation,
                        credential: br#"{"username":"fixture","password":"synthetic"}"#,
                        wait: Duration::from_secs(10),
                    };
                    let mut trace = setup::AcceptTrace::default();
                    let preflight_controller = Controller::new(
                        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
                        1,
                    )?;
                    let invalid = setup_upgrade::setup_and_upgrade(
                        cx,
                        &mut owner,
                        &mut listener,
                        listener_address.port(),
                        &mut http,
                        &cfg,
                        handoff::Framing::ContentLength,
                        4096,
                        Duration::from_secs(5),
                        Duration::ZERO,
                        &mut trace,
                        Arc::new(server.clone()),
                        ProtocolPolicy::RequireOffer,
                        &policy,
                        preflight_controller,
                    )
                    .await;
                    assert!(matches!(invalid, Err(setup_upgrade::Error::Configuration)));
                    assert!(trace.outcome().is_none() && !trace.accept_started());
                    assert_eq!(http.phase(), camera_api::Phase::Login);
                    let preflight_controller = Controller::new(
                        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?, 1,
                    )?;
                    let invalid_retry = setup_upgrade::setup_and_upgrade_with_retries(
                        cx, &mut owner, &mut listener, listener_address.port(), &mut http, &cfg,
                        handoff::Framing::ContentLength, 4096, Duration::from_secs(5),
                        Duration::from_secs(10), 0, &mut trace, Arc::new(server.clone()),
                        ProtocolPolicy::RequireOffer, &policy, preflight_controller,
                    ).await;
                    assert!(matches!(invalid_retry, Err(setup_upgrade::Error::Configuration)));
                    assert!(trace.outcome().is_none() && !trace.accept_started());
                    assert_eq!(http.phase(), camera_api::Phase::Login);
                    let controller = Controller::new(
                        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
                        1,
                    )?;
                    let result = if drop_initial { setup_upgrade::setup_and_upgrade_with_retries(
                        cx, &mut owner, &mut listener, listener_address.port(), &mut http, &cfg,
                        handoff::Framing::ContentLength, 4096, Duration::from_secs(5),
                        Duration::from_secs(10), 2, &mut trace, Arc::new(server),
                        ProtocolPolicy::RequireOffer, &policy, controller,
                    ).await } else { setup_upgrade::setup_and_upgrade(
                        cx,
                        &mut owner,
                        &mut listener,
                        listener_address.port(),
                        &mut http,
                        &cfg,
                        handoff::Framing::ContentLength,
                        4096,
                        Duration::from_secs(5),
                        Duration::from_secs(10),
                        &mut trace,
                        Arc::new(server),
                        ProtocolPolicy::RequireOffer,
                        &policy,
                        controller,
                    )
                    .await };
                    match result {
                        Err(setup_upgrade::Error::RetryPeerMismatch) if wrong_retry => (),
                        Ok(mut session) if send_tls => {
                            let management = management::Preconditions {
                                camera, peer_admission: admission_digest, session_generation: 1,
                                previous_association: None, previous_clock: None, lease_fence: fence,
                            };
                            let stream_conditions = intent::Preconditions {
                                camera, peer_admission: admission_digest, stream_generation: 1,
                                previous_settings: None, lease_fence: fence,
                            };
                            let guard = Guard { leases: &leases, clock };
                            let mut conversation = conversation::Owner {
                                cx, task, clock, effects: &mut *owner.effects, leases: &leases,
                                approval: &Approval, management_authority: &guard,
                                stream_authority: &guard, wall: &Wall,
                            };
                            let request = listener::Start {
                                bind: SocketAddrV4::new(peer, 0), resource: &resource,
                                admission: &policy, channel: VideoChannel::Video2,
                                video: VideoCodec::H264, audio: AudioCodec::Aac,
                                stream_name: "0123456789abcdef", hello: &hello,
                                agreement: &agreement, stream: &stream, time_sync: &[],
                                management, stream_conditions, chunk_bytes: 4096,
                                max_bytes: 1_000_000, bind_wait: Duration::from_secs(5),
                                conversation_wait: Duration::from_secs(5),
                                accept_wait: Duration::from_secs(5),
                            };
                            let framer = Framer::new(FlvLimits::default(), 1024 * 1024)?;
                            let recorder = recording::Recorder::new(
                                SourceKey { connection: 1, generation: 1 }, recording::Limits::default(),
                            )?;
                            let mut start_trace = listener::StartTrace::default();
                            let started = listener::start_tracked(
                                &mut conversation, &mut session, &request, framer, recorder, &mut start_trace,
                            ).await?;
                            let mut pipeline = started.pipeline;
                            let mut segments = 0;
                            let mut decoded_frames = 0;
                            loop {
                                match pipeline.step(task, cx, clock.now()?).await? {
                                    pipeline::Step::Recording(recording::Push::Segment(segment)) => {
                                        let initialization = pipeline.initialization().ok_or("missing media initialization")?;
                                        let mut movie = initialization.bytes().to_vec();
                                        movie.extend_from_slice(segment.fragment().bytes());
                                        let demux = AvcMp4::parse(&movie, None, DemuxLimits::default())?;
                                        let annex = demux.annex_b(0, 3)?;
                                        let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                                        decoded_frames += decoder.decode_annex_b(annex.bytes())?.len();
                                        decoded_frames += decoder.finish()?.len();
                                        segments += 1;
                                    }
                                    pipeline::Step::Recording(_) | pipeline::Step::Progress { .. } => (),
                                    pipeline::Step::Eof => break,
                                    pipeline::Step::LimitReached => return Err("media limit reached".into()),
                                }
                            }
                            if segments == 0 || decoded_frames == 0 { return Err("fixture produced no decodable media".into()); }
                            let _retired = pipeline.retire();
                            let _session_retirement = session.retire();
                        }
                        Err(setup_upgrade::Error::Tls(io::ErrorKind::UnexpectedEof))
                            if !send_tls =>
                        {
                            ()
                        }
                        Err(error) => return Err(format!("setup/upgrade failed: {error:?}").into()),
                        Ok(_) => return Err("unexpected successful setup/upgrade".into()),
                    }
                    match trace.take_outcome() {
                        Some(setup::Outcome::Observed {
                            readback: handoff::Readback::Previous,
                            permit,
                            ..
                        }) if permit.operation() == &operation => (),
                        _ => return Err("unresolved handoff not retained".into()),
                    }
                    drop(http);
                    camera_peer.finish()?;
                    controller_peer.finish()?;
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Indeterminate("fixture handoff requires reconciliation".into())
                } else {
                    TaskOutcome::Failed("fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(599_000_000_000),
                }
            },
        )
        .await?;
        run.receipt?;
        run.output
    })?;
    if effects.journal().operation(&operation).is_none() {
        return Err("missing handoff journal".into());
    }
    Ok(())
}

#[test]
#[ignore = "requires FSS_TEST_CONTROLLER_BIND_IP and disposable FSS_LAB_CERT_DER/FSS_LAB_KEY_DER"]
fn previous_readback_upgrades_or_retains_effect_after_tls_failure() -> Test {
    let peer: Ipv4Addr = std::env::var("FSS_TEST_CONTROLLER_BIND_IP")?.parse()?;
    if !(peer.is_private() || peer.is_link_local()) || peer == Ipv4Addr::new(192, 168, 1, 10) {
        return Err("unsuitable private test interface".into());
    }
    let cert = std::fs::read(std::env::var("FSS_LAB_CERT_DER")?)?;
    let key = std::fs::read(std::env::var("FSS_LAB_KEY_DER")?)?;
    if cert.is_empty() || cert.len() > 8192 || key.is_empty() || key.len() > 8192 {
        return Err("invalid disposable TLS fixture".into());
    }
    scenario(peer, &cert, &key, true, false, false)?;
    scenario(peer, &cert, &key, false, false, false)?;
    scenario(peer, &cert, &key, true, true, false)?;
    scenario(peer, &cert, &key, true, true, true)
}

/// Checks that a fleet route remains the owner of its socket through TLS and
/// that an untrusted WebSocket MAC cannot select a different inventory entry.
fn fleet_upgrade_scenario(peer: Ipv4Addr, cert: &[u8], key: &[u8], wrong_mac: bool) -> Test {
    use fss_reference::unifi_direct::discovery::{
        fleet::{Enrollment, Fleet, RouteError, Router, RouterEvent},
        pump::{Event as PumpEvent, Progress, Pump},
        scan::{Outcome as ScanOutcome, Phase as ScanPhase, Scanner},
    };
    use std::{
        cell::Cell,
        future::{Future, poll_fn},
        pin::Pin,
        rc::Rc,
        task::{Context, Poll},
    };

    struct PausedRead<IO> {
        inner: IO,
        allowed: Rc<Cell<bool>>,
    }
    impl<IO: asupersync::io::AsyncRead + Unpin> asupersync::io::AsyncRead for PausedRead<IO> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut asupersync::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if !self.allowed.get() {
                return Poll::Pending;
            }
            Pin::new(&mut self.inner).poll_read(cx, buffer)
        }
    }
    impl<IO: asupersync::io::AsyncWrite + Unpin> asupersync::io::AsyncWrite for PausedRead<IO> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, data)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    struct Permissive;
    impl PeerAdmission for Permissive {
        fn permits(&self, _: [u8; 6]) -> bool {
            true
        }
    }
    struct FixtureAccess(ContentDigest);
    impl archive::RetainAuthority for FixtureAccess {
        fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool { retention == self.0 }
    }
    impl archive::ReadAuthority for FixtureAccess {
        fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool { retention == self.0 }
    }
    struct DeniedRead;
    impl archive::ReadAuthority for DeniedRead {
        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool { false }
    }
    fn source_confirmed(completion: source_worker::Completion) -> Test {
        if completion.runtime.is_err() { return Err("source publication runtime failed".into()); }
        match completion.outcome {
            source_worker::Outcome::Publication(source_worker::Publication::Published { .. }) => Ok(()),
            _ => Err("source publication requires reconciliation".into()),
        }
    }
    fn control_event(step: supervisor::Step) -> Result<bool, Box<dyn Error>> {
        match step {
            supervisor::Step::Idle | supervisor::Step::Observation(_)
            | supervisor::Step::Media(pipeline::Step::Progress { .. })
            | supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Buffered)) => Ok(false),
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
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert.to_vec()))?;
    let client = Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let path = std::fs::canonicalize(std::env::temp_dir())?.join(format!(
        "fss-fleet-upgrade-{}-{wrong_mac}",
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
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 2_000_000;
    budget.bytes = 128 * 1024 * 1024;
    budget.storage_operations = 10_000;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:fleet-upgrade".into(),
            operation_id: OperationId::parse("operation:fleet-upgrade-owner")?,
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
            .map(|v| v.as_str().into())
            .collect(),
            deadline: Some(TimestampNs(600_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"fleet TLS fixture"),
            generation: 1,
        },
        RegionId::new("region:fleet-upgrade")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let camera = ContentDigest::sha256(b"fleet TLS camera");
    let admission_digest = ContentDigest::sha256(b"fleet TLS admission");
    let cert_handle = ContentDigest::sha256(b"fleet TLS cert handle");
    let credential_handle = ContentDigest::sha256(b"fleet TLS credential handle");
    let resource = format!("camera:{}", camera.to_text());
    let mut leases = LeaseRegistry::new();
    let fence = leases
        .acquire(&resource, "region:fleet-upgrade", None, TimestampNs(2))?
        .fence;
    let leases = RefCell::new(leases);
    let operation = OperationId::parse("operation:fleet-upgrade-setup")?;
    let hello = OperationId::parse("operation:fleet-upgrade-hello")?;
    let agreement = OperationId::parse("operation:fleet-upgrade-agreement")?;
    let stream = OperationId::parse("operation:fleet-upgrade-stream")?;
    let wire = media_fixture_from_frames(include_bytes!("fixtures/synthetic_g4_resolution.264"), 4, 13)?;
    let expected_wire = wire.clone();
    let runtime = RuntimeBuilder::current_thread().blocking_threads(2, 2).build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("runtime context")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:fleet-upgrade")?,
                started_at: TimestampNs(3),
            },
            &cx,
            async |task, cx| {
                let output: Test = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(4))?;
                    let policy = Admission {
                        peer: Ipv4Addr::LOCALHOST,
                        listen: peer,
                        camera,
                        admission: admission_digest,
                        fence,
                        allow_other_source: false,
                    };
                    let udp = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
                    udp.set_read_timeout(Some(Duration::from_secs(15)))?;
                    let SocketAddr::V4(target) = udp.local_addr()? else {
                        return Err("IPv4 required".into());
                    };
                    let sender = Joined(Some(std::thread::spawn(move || {
                        let mut input = [0u8; 64];
                        let (_, source) = udp.recv_from(&mut input)?;
                        udp.send_to(&discovery_packet(Ipv4Addr::LOCALHOST), source)?;
                        Ok(())
                    })));
                    let cfg = discovery::Config::new(
                        Ipv4Addr::LOCALHOST,
                        8,
                        target,
                        "fixture:fleet-discovery",
                        Duration::from_millis(150),
                        8,
                    )?;
                    let report = discovery::discover(task, cx, clock.now()?, &cfg).await?;
                    sender.finish()?;
                    let entry = Enrollment::new(
                        MAC,
                        camera,
                        admission_digest,
                        cert_handle,
                        credential_handle,
                        1,
                    )?;
                    let fleet = Fleet::new(&report, &[entry])?;
                    let listener = controller_listener::Listener::bind(
                        task,
                        cx,
                        clock,
                        &policy,
                        SocketAddrV4::new(peer, 0),
                        &resource,
                        Duration::from_secs(5),
                    )
                    .await?;
                    let endpoint = listener.local_addr();
                    let camera_listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
                    let SocketAddr::V4(camera_address) = camera_listener.local_addr()? else {
                        return Err("IPv4 required".into());
                    };
                    let camera_server = server.clone();
                    let camera_peer = Joined(Some(std::thread::spawn(move || {
                        camera_fixture(camera_listener, endpoint.port(), peer, camera_server)
                    })));
                    let camera_tls = camera_tls::connect(
                        cx,
                        task,
                        clock,
                        camera_address,
                        cert,
                        &resource,
                        Duration::from_secs(5),
                    )
                    .await?;
                    let allowed = Rc::new(Cell::new(false));
                    let io = MeteredIo::with_clock(PausedRead { inner: camera_tls, allowed: Rc::clone(&allowed) }, clock, &resource, 4096)?;
                    let mut http = camera_http::Owner::new(
                        io,
                        task,
                        cx,
                        clock,
                        &policy,
                        Ipv4Addr::LOCALHOST,
                        1,
                        &resource,
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
                    let mut setup = Box::pin(fleet.setup_one(
                        0, &mut owner, &listener, endpoint.port(), &mut http,
                        cert_handle, credential_handle,
                        br#"{"username":"fixture","password":"synthetic"}"#,
                        fence, peer, &operation, handoff::Framing::ContentLength,
                        Duration::from_secs(10), &mut trace,
                    ));
                    poll_fn(|task_context| match setup.as_mut().poll(task_context) {
                        Poll::Pending => Poll::Ready(()),
                        Poll::Ready(_) => panic!("paused setup unexpectedly completed"),
                    }).await;
                    let tls_client = client.clone();
                    let (release_tls, await_tls) = std::sync::mpsc::sync_channel::<()>(1);
                    let (release_scan, await_scan) = std::sync::mpsc::sync_channel::<()>(1);
                    let (release_media, await_media) = std::sync::mpsc::sync_channel::<()>(1);
                    let (release_controller, await_retire) = std::sync::mpsc::sync_channel::<()>(1);
                    let controller_peer =
                        Joined(Some(std::thread::spawn(move || -> io::Result<()> {
                            let socket =
                                Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
                            socket.bind(
                                &SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).into(),
                            )?;
                            socket.connect_timeout(
                                &SocketAddr::V4(endpoint).into(),
                                Duration::from_secs(10),
                            )?;
                            let raw: std::net::TcpStream = socket.into();
                            raw.set_read_timeout(Some(Duration::from_secs(10)))?;
                            raw.set_write_timeout(Some(Duration::from_secs(10)))?;
                            await_tls.recv_timeout(Duration::from_secs(8))
                                .map_err(|_| io::Error::other("TLS fixture not released"))?;
                            let mut tls = StreamOwned::new(
                                ClientConnection::new(
                                    tls_client,
                                    ServerName::try_from("localhost").map_err(io::Error::other)?,
                                )
                                .map_err(io::Error::other)?,
                                raw,
                            );
                            let head = if wrong_mac {
                                HEAD.replace("001122aabbcc", "001122aabbdd")
                            } else {
                                HEAD.to_owned()
                            };
                            let mut request = head.into_bytes();
                            if !wrong_mac {
                                request.extend(frame(HELLO));
                            }
                            tls.write_all(&request)?;
                            tls.flush()?;
                            if wrong_mac {
                                match tls.read(&mut [0u8; 1]) {
                                    Ok(0) => (),
                                    Err(error)
                                        if error.kind() == io::ErrorKind::UnexpectedEof
                                            || error.kind() == io::ErrorKind::ConnectionReset =>
                                    {
                                        ()
                                    }
                                    _ => {
                                        return Err(io::Error::other(
                                            "wrong MAC was not refused promptly",
                                        ));
                                    }
                                }
                            } else {
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
                                    return Err(io::Error::other("upgrade response missing"));
                                }
                                if !receive_binary(&mut tls)?.windows(b"ubnt_avclient_hello".len())
                                    .any(|w| w == b"ubnt_avclient_hello") {
                                    return Err(io::Error::other("missing hello reply"));
                                }
                                let agreement = receive_binary(&mut tls)?;
                                let agreement_id = message_id(std::str::from_utf8(&agreement).map_err(io::Error::other)?)?;
                                await_scan.recv_timeout(Duration::from_secs(8))
                                    .map_err(|_| io::Error::other("periodic scan did not finish during startup"))?;
                                let reply = format!(r#"{{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_paramAgreement","messageId":8,"inResponseTo":{agreement_id}}}"#);
                                tls.write_all(&frame(reply.as_bytes()))?;
                                tls.flush()?;
                                let stream = receive_binary(&mut tls)?;
                                let message = std::str::from_utf8(&stream).map_err(io::Error::other)?;
                                if !message.contains("\"video1\"") {
                                    return Err(io::Error::other("high channel was not requested"));
                                }
                                let destination: SocketAddr = message.split_once("tcp://")
                                    .and_then(|(_, suffix)| suffix.split_once('?'))
                                    .map(|(address, _)| address)
                                    .ok_or_else(|| io::Error::other("missing media destination"))?
                                    .parse().map_err(io::Error::other)?;
                                if !matches!(destination, SocketAddr::V4(address) if *address.ip() == peer && address.port() != 0) {
                                    return Err(io::Error::other("unexpected media destination"));
                                }
                                let stream_id = message_id(message)?;
                                let reply = format!(r#"{{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ChangeVideoSettings","messageId":9,"inResponseTo":{stream_id}}}"#);
                                tls.write_all(&frame(reply.as_bytes()))?;
                                tls.flush()?;
                                let media = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
                                media.bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).into())?;
                                media.connect_timeout(&destination.into(), Duration::from_secs(5))?;
                                let mut media: std::net::TcpStream = media.into();
                                await_media.recv_timeout(Duration::from_secs(8))
                                    .map_err(|_| io::Error::other("periodic scan did not finish during media supervision"))?;
                                media.write_all(&wire)?;
                                drop(media);
                                await_retire.recv_timeout(Duration::from_secs(30))
                                    .map_err(|_| io::Error::other("media supervisor did not retire"))?;
                            }
                            Ok(())
                        })));
                    let mut router = Router::new(&fleet, &listener, 1, 4096, Duration::from_secs(5))?;
                    let mut next = Box::pin(router.next());
                    poll_fn(|task_context| match next.as_mut().poll(task_context) {
                        Poll::Pending if fleet.route_pending(0) => Poll::Ready(()),
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(_) => panic!("early TLS route unexpectedly completed"),
                    }).await;
                    drop(next);
                    assert_eq!(router.pending_len(), 1);
                    allowed.set(true);
                    let setup_outcome = setup.await?;
                    assert!(matches!(setup_outcome, setup::Outcome::Observed {
                        readback: handoff::Readback::Previous, ..
                    }));
                    assert!(fleet.route_ready(0));
                    drop(http);
                    camera_peer.finish()?;
                    use fss_reference::unifi_direct::controller_acceptor::{Acceptor as FleetAcceptor, Event};
                    use unifi_tls_05_server_lab::fleet_transport::LabTls;
                    let admission = Permissive;
                    let mut acceptor = FleetAcceptor::new(
                        router, cx, &admission, LabTls(server.clone()),
                        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
                        Default::default(), ProtocolPolicy::RequireOffer, 4096,
                        Duration::from_secs(10), 2,
                    ).map_err(|error| format!("acceptor configuration: {error:?}"))?;
                    // Hold one handshake open, then show the pump still handles a
                    // new connection. Dropping this wait must retain the owner.
                    let mut stalled = Box::pin(acceptor.next());
                    poll_fn(|task_context| match stalled.as_mut().poll(task_context) {
                        Poll::Pending => Poll::Ready(()),
                        Poll::Ready(_) => panic!("stalled handshake unexpectedly completed"),
                    }).await;
                    drop(stalled);
                    // The first poll may only have resolved the router's early
                    // route. Continue until the TLS handshake is actually owned.
                    poll_fn(|task_context| match acceptor.poll_next(task_context) {
                        Poll::Pending if acceptor.handshake_len() == 1 => Poll::Ready(()),
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(_) => panic!("stalled handshake unexpectedly completed"),
                    }).await;
                    let socket = asupersync::net::TcpSocket::new_v4()?;
                    socket.bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
                    let duplicate = socket.connect(SocketAddr::V4(endpoint)).await?;
                    assert!(matches!(acceptor.next().await,
                        Event::RouteRefused { reason: RouteError::AlreadyActive, .. }));
                    assert_eq!(acceptor.handshake_len(), 1);
                    drop(duplicate);
                    release_tls.send(()).map_err(|_| "TLS fixture stopped")?;
                    let outcome = acceptor.next().await;
                    if wrong_mac {
                        assert!(matches!(
                            outcome,
                            Event::HandshakeFailed { index: 0, reason: controller_upgrade::Error::Upgrade(
                                fss_reference::unifi_direct::owner::Error::PeerDenied
                            ) }
                        ));
                    } else {
                        let mut session = match outcome {
                            Event::Session { index: 0, session } => session,
                            _ => return Err("expected upgraded fleet session".into()),
                        };
                        assert_eq!(session.claimed_mac(), MAC);
                        let socket = asupersync::net::TcpSocket::new_v4()?;
                        socket.bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
                        let duplicate = socket.connect(SocketAddr::V4(endpoint)).await?;
                        assert!(matches!(
                            acceptor.next().await,
                            Event::RouteRefused { reason: RouteError::AlreadyActive, .. }
                        ));
                        drop(duplicate);
                        let management = management::Preconditions {
                            camera, peer_admission: admission_digest, session_generation: 1,
                            previous_association: None, previous_clock: None, lease_fence: fence,
                        };
                        let stream_conditions = intent::Preconditions {
                            camera, peer_admission: admission_digest, stream_generation: 1,
                            previous_settings: None, lease_fence: fence,
                        };
                        let guard = Guard { leases: &leases, clock };
                        let mut conversation = conversation::Owner {
                            cx, task, clock, effects: &mut *owner.effects, leases: &leases,
                            approval: &Approval, management_authority: &guard,
                            stream_authority: &guard, wall: &Wall,
                        };
                        let request = listener::Start {
                            bind: SocketAddrV4::new(peer, 0), resource: &resource,
                            admission: &policy, channel: VideoChannel::Video1,
                            video: VideoCodec::H264, audio: AudioCodec::Aac,
                            stream_name: "0123456789abcdef", hello: &hello,
                            agreement: &agreement, stream: &stream, time_sync: &[],
                            management, stream_conditions, chunk_bytes: 4096,
                            max_bytes: 1_000_000, bind_wait: Duration::from_secs(5),
                            conversation_wait: Duration::from_secs(5),
                            accept_wait: Duration::from_secs(5),
                        };
                        let framer = Framer::new(FlvLimits::default(), 1024 * 1024)?;
                        let recorder = recording::Recorder::new(
                            SourceKey { connection: 1, generation: 1 }, recording::Limits::default(),
                        )?;
                        let mut start_trace = listener::StartTrace::default();
                        let periodic = std::net::UdpSocket::bind(target)?;
                        periodic.set_read_timeout(Some(Duration::from_secs(8)))?;
                        let periodic_sender = Joined(Some(std::thread::spawn(move || -> io::Result<()> {
                            for _ in 0..2 {
                                let mut input = [0u8; 64];
                                let (_, source) = periodic.recv_from(&mut input)?;
                                periodic.send_to(&discovery_packet(Ipv4Addr::LOCALHOST), source)?;
                            }
                            Ok(())
                        })));
                        let scanner = Scanner::new(cx, task, clock, &fleet, cfg.clone(), Duration::from_millis(50))?;
                        let mut pump = Pump::new(&scanner, &mut acceptor)?;
                        let startup_began = std::time::Instant::now();
                        let mut start = Box::pin(listener::start_tracked(
                            &mut conversation, &mut session, &request, framer, recorder, &mut start_trace,
                        ));
                        let mut previous_poll = None;
                        let mut longest_poll_gap = Duration::ZERO;
                        let mut longest_poll = Duration::ZERO;
                        let mut startup_work = Box::pin(poll_fn(|context| {
                            let now = std::time::Instant::now();
                            if let Some(previous) = previous_poll {
                                longest_poll_gap = longest_poll_gap.max(now.duration_since(previous));
                            }
                            let result = start.as_mut().poll(context);
                            let finished = std::time::Instant::now();
                            longest_poll = longest_poll.max(finished.duration_since(now));
                            previous_poll = Some(finished);
                            result
                        }));
                        let mut interrupted_wait = Box::pin(pump.next_with(startup_work.as_mut()));
                        poll_fn(|context| match interrupted_wait.as_mut().poll(context) {
                            Poll::Pending if scanner.phase() == ScanPhase::Probing => Poll::Ready(()),
                            Poll::Pending => { context.waker().wake_by_ref(); Poll::Pending },
                            Poll::Ready(_) => panic!("startup or scan finished before cancellation check"),
                        }).await;
                        drop(interrupted_wait);
                        assert_eq!(scanner.phase(), ScanPhase::Probing);
                        let mut scanned = false;
                        let started = loop {
                            match pump.next_with(startup_work.as_mut()).await {
                                Progress::Event(PumpEvent::Discovery(Ok(ScanOutcome::Updated(snapshot)))) => {
                                    eprintln!("fleet fixture startup discovery after {:?}", startup_began.elapsed());
                                    if scanned || snapshot.report().cameras.len() != 1 {
                                        return Err("unexpected periodic startup discovery".into());
                                    }
                                    scanned = true;
                                    pump.request_scan_stop();
                                    release_scan.send(()).map_err(|_| "startup controller stopped")?;
                                }
                                Progress::Work(result) if scanned => break result,
                                _ => return Err("startup or periodic discovery stopped unexpectedly".into()),
                            }
                        };
                        drop(startup_work);
                        drop(start);
                        let started = started.map_err(|error| format!("fleet startup failed after {:?} (longest poll gap {:?}, longest poll {:?}): {error:?}; trace: {start_trace:?}", startup_began.elapsed(), longest_poll_gap, longest_poll))?;
                        eprintln!("fleet fixture startup timing elapsed={:?} poll_gap={longest_poll_gap:?} poll={longest_poll:?}", startup_began.elapsed());
                        assert!(pump.scan_drained());
                        pump.resume_scanning()?;
                        let supervisor = supervisor::Supervisor::new(session, started.pipeline, management);
                        let retention = ContentDigest::sha256(b"fixture fleet video retention");
                        let source = SourceKey { connection: 1, generation: 1 };
                        let access = Arc::new(FixtureAccess(retention));
                        let replay_authority = fss_core::region::ContextAuthority::new_root(RootAuthoritySpec {
                            trace_id: "trace:fleet-video-replay".into(),
                            operation_id: OperationId::parse("operation:fleet-video-replay")?,
                            principal: "principal:fixture".into(), capabilities: vec!["ADP-REPLAY-001".into()],
                            deadline: None, priority: 1, budgets: budget,
                            privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
                            anchor_universe: ContentDigest::sha256(b"fleet video replay"), generation: 1,
                        })?;
                        let source_replay = fss_reference::ReplayCx::from_context_authority(&replay_authority, temp.0.clone())?;
                        let video_replay = fss_reference::ReplayCx::from_context_authority(&replay_authority, temp.0.clone())?;
                        let storage_root = temp.0.join("owned-storage");
                        let created = recording_storage::create(task, cx, clock, recording_storage::Configuration {
                            root: &storage_root, site_lineage: "site:fleet-video", source,
                            camera_claim: camera, source_retention: retention,
                            source_scope: ContentDigest::sha256(b"fixture source scope"),
                            av_scope: ContentDigest::sha256(b"fixture video scope"),
                            source_deployment_limits: fss_reference::DeploymentLimits::standard(),
                            av_deployment_limits: fss_reference::DeploymentLimits::standard(),
                            source_history_limits: EffectJournalLimits::default(),
                            av_history_limits: EffectJournalLimits::default(),
                            limits: archive::Limits::default(), max_source_bytes: 1024 * 1024,
                            work_limit: 4_000_000_000,
                        }, source_replay, video_replay, access.clone())?;
                        let mut bootstrap = video_bootstrap::Bootstrap::begin(
                            supervisor, created.coordinator.into_worker(), created.av, source, camera,
                            video_bootstrap::Policy { inband: false, retention,
                                media_limits: fss_container::Mp4Limits::default(),
                                evidence_limits: evidence::Limits::default() },
                        ).map_err(|_| "video bootstrap refused")?;
                        let admission = fss_reference::unifi_direct::source_coordinator::ArchiveAdmission {
                            resource: &resource, cost: &BudgetVector::ZERO,
                        };
                        let mut media_scan = false;
                        let mut step_number = 0usize;
                        let mut source_count = 0usize;
                        let mut pins = Vec::new();
                        pins.try_reserve_exact(16)?;
                        loop {
                            if step_number >= 512 { return Err("media bootstrap fixture step limit reached".into()); }
                            let operation = OperationId::parse(format!("operation:fleet-media-step-{step_number}"))?;
                            step_number += 1;
                            let mut work = Box::pin(bootstrap.step(&mut conversation, &operation,
                                Duration::from_millis(100), task, cx, clock, admission));
                            let step = loop {
                                match pump.next_with(work.as_mut()).await {
                                    Progress::Event(PumpEvent::Discovery(Ok(ScanOutcome::Updated(snapshot)))) if !media_scan => {
                                        if snapshot.report().cameras.len() != 1 { return Err("media discovery claim missing".into()); }
                                        media_scan = true;
                                        pump.request_scan_stop();
                                        release_media.send(()).map_err(|_| "media producer stopped")?;
                                    }
                                    Progress::Event(PumpEvent::Route(Event::RouteRefused {
                                        reason: RouteError::Listener(listener::Error::Deadline), ..
                                    })) => (),
                                    Progress::Work(step) => break step,
                                    _ => return Err("media supervision or discovery stopped unexpectedly".into()),
                                }
                            };
                            drop(work);
                            match step {
                                video_bootstrap::Step::SourceOffered(_) | video_bootstrap::Step::Configured
                                | video_bootstrap::Step::SourceStarted => (),
                                video_bootstrap::Step::SourceArchive { control, completion } => {
                                    if let Some(control) = control { if control_event(control)? { return Err("media ended during bootstrap".into()); } }
                                    if let Some(completion) = completion { source_confirmed(completion)?; source_count += 1; }
                                }
                                video_bootstrap::Step::Supervisor(control) => {
                                    if control_event(control)? { return Err("media ended during bootstrap".into()); }
                                }
                                video_bootstrap::Step::Ready => break,
                                _ => return Err("video bootstrap requires reconciliation".into()),
                            }
                        }
                        let mut recording = bootstrap.into_session().map_err(|_| "video session handoff refused")?;
                        loop {
                            if step_number >= 512 { return Err("media session fixture step limit reached".into()); }
                            let operation = OperationId::parse(format!("operation:fleet-media-step-{step_number}"))?;
                            step_number += 1;
                            // A different camera's stalled operation must not
                            // prevent the live media owner from progressing.
                            let mut work = discovery::pump::CameraWorkSet::new(2)
                                .map_err(|_| "camera work capacity refused")?;
                            work.insert(1, Box::pin(std::future::pending::<video_session::Step>()))
                                .map_err(|_| "stalled camera work refused")?;
                            work.insert(0, Box::pin(recording.step(&mut conversation, &operation,
                                Duration::from_millis(100), task, cx, clock, admission, admission)))
                                .map_err(|_| "recording work refused")?;
                            let mut next_work = Box::pin(work.next());
                            let step = loop {
                                match pump.next_with(next_work.as_mut()).await {
                                    Progress::Event(PumpEvent::Route(Event::RouteRefused {
                                        reason: RouteError::Listener(listener::Error::Deadline), ..
                                    })) => (),
                                    Progress::Work((0, step)) => break step,
                                    _ => return Err("unexpected event during video recording".into()),
                                }
                            };
                            drop(next_work);
                            let pending = work.into_pending();
                            if pending.len() != 1 || pending[0].0 != 1 {
                                return Err("stalled camera work was not retained".into());
                            }
                            drop(pending);
                            match step {
                                video_session::Step::SourceOffered(_) | video_session::Step::VideoOffered
                                | video_session::Step::SourceStarted | video_session::Step::VideoStarted => (),
                                video_session::Step::SourceArchive { control, completion } => {
                                    if let Some(control) = control { if control_event(control)? { return Err("media ended during source publication".into()); } }
                                    if let Some(completion) = completion { source_confirmed(completion)?; source_count += 1; }
                                }
                                video_session::Step::VideoArchive { control, completion } => {
                                    if let Some(control) = control { if control_event(control)? { return Err("media ended during video publication".into()); } }
                                    if let Some(completion) = completion {
                                        if completion.runtime.is_err() { return Err("video publication runtime failed".into()); }
                                        let published = match completion.outcome {
                                            video_worker::Outcome::Publication(video_worker::Publication::Published(value)) => value,
                                            _ => return Err("video publication requires reconciliation".into()),
                                        };
                                        if pins.len() == 16 || pins.contains(&published.pin) { return Err("invalid bounded video history".into()); }
                                        pins.push(published.pin);
                                    }
                                }
                                video_session::Step::Supervisor(control) => if control_event(control)? { break; },
                                _ => return Err("video recording requires reconciliation".into()),
                            }
                        }
                        if pins.len() < 2 || source_count == 0 { return Err("multiple video and source publications required".into()); }
                        let mut parts = recording.into_parts().map_err(|_| "video session not drained")?;
                        parts.source_armed = true;
                        let mut parts = match parts.prepare_retirement() {
                            Err(video_session::RetirementRefusal::NotDrained(parts)) => parts,
                            _ => return Err("armed source did not preserve session owners".into()),
                        };
                        if !parts.source_armed || parts.key != source || parts.camera_claim != camera {
                            return Err("retirement refusal changed session ownership".into());
                        }
                        parts.source_armed = false;
                        release_controller.send(()).map_err(|_| "controller fixture stopped")?;
                        let retirement = parts.prepare_retirement().map_err(|_| "session retirement refused")?;
                        if retirement.time_sync.is_some() || retirement.controller.prepared.is_some()
                            || retirement.controller.agreement_id.is_some() || retirement.controller.hello_request_id.is_some()
                            || retirement.controller.time_sync_request_id.is_some() || retirement.controller.stream_request.is_some()
                            || retirement.controller.motion_request.is_some() || retirement.controller.event_reply.is_some()
                            || retirement.controller.rejected_message.is_some() {
                            return Err("controller retirement requires reconciliation".into());
                        }
                        let tail = retirement.tail.plan();
                        let tail_count = tail.len();
                        let tail_start = tail.start.ok_or("expected an unfinished video tail")?;
                        if tail.end != Some(tail.received)
                            || tail.received != u64::try_from(expected_wire.len())?
                            || tail.recorder_fenced || tail.pending_audio.is_some() {
                            return Err("invalid source retirement facts".into());
                        }
                        let mut tail_driver = retirement.tail;
                        let mut tail_offered = 0usize;
                        let mut tail_completed = 0usize;
                        let mut tail_outstanding = false;
                        let mut tail_records = Vec::new();
                        loop {
                            if step_number >= 512 { return Err("tail fixture step limit reached".into()); }
                            step_number += 1;
                            let mut work = Box::pin(tail_driver.step(task, cx, clock, admission));
                            let step = loop {
                                match pump.next_with(work.as_mut()).await {
                                    Progress::Event(PumpEvent::Route(Event::RouteRefused {
                                        reason: RouteError::Listener(listener::Error::Deadline), ..
                                    })) => (),
                                    Progress::Work(step) => break step,
                                    _ => return Err("unexpected event during tail archival".into()),
                                }
                            };
                            drop(work);
                            match step {
                                retirement_source::DriverStep::Offered { offset, len, disposition } if !tail_outstanding => {
                                    tail_offered += 1;
                                    tail_outstanding = true;
                                    tail_records.push((offset, len, disposition));
                                }
                                retirement_source::DriverStep::Started => (),
                                retirement_source::DriverStep::Completed(completion) if tail_outstanding => {
                                    source_confirmed(completion)?;
                                    source_count += 1;
                                    tail_completed += 1;
                                    tail_outstanding = false;
                                }
                                retirement_source::DriverStep::Finished if !tail_outstanding => break,
                                _ => return Err("tail source requires reconciliation".into()),
                            }
                        }
                        let tail_parts = tail_driver.into_parts().map_err(|_| "tail worker not drained")?;
                        if !tail_parts.plan.is_empty() || tail_offered != tail_count || tail_completed != tail_count {
                            return Err("tail source accounting incomplete".into());
                        }
                        let mut video = retirement.video.retire().map_err(|_| "video worker not retired")?;
                        let mut source_retired = tail_parts.worker.retire().map_err(|_| "source worker not retired")?;
                        if video.fenced || video.report.is_some() || source_retired.fenced || source_retired.pending.is_some() {
                            return Err("archive worker requires reconciliation".into());
                        }
                        let page = video.parts.journal.confirmed_page(video.parts.journal.anchor(), 0, 128, &video.parts.replay)?;
                        if page.has_more || page.pending.is_some() || !pins.iter().copied().eq(page.entries.iter().map(|entry| entry.pin)) {
                            return Err("video publication history mismatch".into());
                        }
                        let source_page = source_retired.parts.journal.confirmed_page(source_retired.parts.journal.anchor(), 0, 128, &source_retired.parts.replay)?;
                        if source_page.has_more || source_page.pending.is_some() || source_page.entries.len() != source_count {
                            return Err("source publication history mismatch".into());
                        }
                        let mut source_end = 0u64;
                        let mut source_ranges = Vec::new();
                        for entry in &source_page.entries {
                            task.checkpoint_for(RuntimeGrant::ReadMedia, &resource, clock.now()?, &BudgetVector::ZERO)?;
                            let recovered = archive::read_unknown_time_source(&mut source_retired.parts.deployment,
                                entry.pin, access.as_ref(), archive::Limits::default(),
                                &mut fss_geometry::WorkBudget::new(4_000_000_000), &source_retired.parts.replay)?;
                            let end = recovered.offset().checked_add(u64::try_from(recovered.bytes().len())?)
                                .ok_or("source record offset overflow")?;
                            let start_index = usize::try_from(recovered.offset())?;
                            let end_index = usize::try_from(end)?;
                            if recovered.key() != source || recovered.camera_claim() != camera || recovered.bytes().is_empty()
                                || source_end > recovered.offset()
                                || expected_wire.get(start_index..end_index) != Some(recovered.bytes()) {
                                return Err("source record readback mismatch".into());
                            }
                            if recovered.offset() >= tail_start
                                && !tail_records.contains(&(recovered.offset(), recovered.bytes().len(), recovered.disposition())) {
                                return Err("tail record disposition mismatch".into());
                            }
                            source_end = end;
                            source_ranges.push((recovered.offset(), end));
                        }
                        let mut decoded_frames = 0usize;
                        let mut denial_checked = false;
                        for pin in &pins {
                            task.checkpoint_for(RuntimeGrant::ReadMedia, &resource, clock.now()?, &BudgetVector::ZERO)?;
                            let clip = archive::read_unknown_time_video_clip(&mut video.parts.deployment, *pin,
                                access.as_ref(), archive::Limits::default(), &mut fss_geometry::WorkBudget::new(4_000_000_000), &video.parts.replay)?;
                            if clip.claimed_source() != source || clip.samples() == 0 { return Err("archive source binding mismatch".into()); }
                            for record in clip.source_records() {
                                task.checkpoint_for(RuntimeGrant::ReadMedia, &resource, clock.now()?, &BudgetVector::ZERO)?;
                                if !denial_checked {
                                    if !matches!(archive::read_unknown_time_object(&mut video.parts.deployment, *pin,
                                        record.digest, &DeniedRead, archive::Limits::default(),
                                        &mut fss_geometry::WorkBudget::new(4_000_000_000), &video.parts.replay), Err(archive::Error::Denied)) {
                                        return Err("source object did not enforce read authority".into());
                                    }
                                    denial_checked = true;
                                }
                                let end = record.offset.checked_add(u64::try_from(record.length)?)
                                    .ok_or("video source offset overflow")?;
                                let bytes = archive::read_unknown_time_object(&mut video.parts.deployment, *pin,
                                    record.digest, access.as_ref(), archive::Limits::default(),
                                    &mut fss_geometry::WorkBudget::new(4_000_000_000), &video.parts.replay)?;
                                if bytes.len() != record.length || expected_wire.get(usize::try_from(record.offset)?..usize::try_from(end)?) != Some(bytes.as_slice()) {
                                    return Err("video source readback mismatch".into());
                                }
                                source_ranges.push((record.offset, end));
                            }
                            if decoded_frames == 0 {
                                let demux = AvcMp4::parse(clip.bytes(), None, DemuxLimits::default())?;
                                let annex = demux.annex_b(0, 1)?;
                                let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                                let mut frames = decoder.decode_annex_b(annex.bytes())?;
                                frames.extend(decoder.finish()?);
                                for frame in frames { assert_eq!((frame.width(), frame.height()), (2688, 1512)); decoded_frames += 1; }
                            }
                        }
                        assert!(decoded_frames > 0, "no synthetic full-resolution video decoded");
                        assert!(denial_checked, "source read denial was not checked");
                        source_ranges.sort_unstable();
                        let mut covered = 0u64;
                        for (start, end) in source_ranges {
                            if start != covered || end <= start { return Err("original source coverage gap or overlap".into()); }
                            covered = end;
                        }
                        if covered != u64::try_from(expected_wire.len())? || tail_start >= covered {
                            return Err("original source coverage incomplete".into());
                        }
                        assert!(media_scan && pump.scan_drained());
                        println!("fleet_video_archive_readback=verified width=2688 height=1512 segments={} source_records_readback={} tail_records={} source_bytes={} discovery_windows=2 capture_bounds=unknown", pins.len(), source_count, tail_count, covered);
                        drop(pump);
                        periodic_sender.finish()?;
                    }
                    controller_peer.finish()?;
                    let mut router = acceptor.into_router();
                    let socket = asupersync::net::TcpSocket::new_v4()?;
                    socket.bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
                    let reconnect = socket.connect(SocketAddr::V4(endpoint)).await?;
                    let fresh_route = match router.next().await {
                        RouterEvent::Ready(route) => route,
                        RouterEvent::Refused { reason, .. } => return Err(format!("reconnect refused: {reason:?}").into()),
                    };
                    assert_eq!(fresh_route.claimed_mac(), MAC);
                    let factory_called = Cell::new(false);
                    let invalid = controller_upgrade::upgrade_routed(cx, fresh_route, |route| {
                        factory_called.set(true);
                        async move { Ok::<_, io::Error>(route) }
                    }, ProtocolPolicy::RequireOffer, &admission,
                        Controller::new(Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?, 1)?,
                        4096, Duration::ZERO).await;
                    assert!(matches!(invalid, Err(controller_upgrade::Error::Configuration)));
                    assert!(!factory_called.get(), "invalid request started its handshake");
                    drop(reconnect);
                    let socket = asupersync::net::TcpSocket::new_v4()?;
                    socket.bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
                    let timeout_peer = socket.connect(SocketAddr::V4(endpoint)).await?;
                    let route = match router.next().await {
                        RouterEvent::Ready(route) => route,
                        RouterEvent::Refused { reason, .. } => return Err(format!("timeout test route refused: {reason:?}").into()),
                    };
                    let factory_called = Cell::new(false);
                    let timed_out = controller_upgrade::upgrade_routed(cx, route, |route| {
                        factory_called.set(true);
                        async move {
                            std::future::pending::<()>().await;
                            Ok::<_, io::Error>(route)
                        }
                    }, ProtocolPolicy::RequireOffer, &admission,
                        Controller::new(Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?, 1)?,
                        4096, Duration::from_millis(200)).await;
                    assert!(matches!(timed_out, Err(controller_upgrade::Error::Deadline)));
                    assert!(factory_called.get(), "timeout fixture handshake never started");
                    drop(timeout_peer);
                    let socket = asupersync::net::TcpSocket::new_v4()?;
                    socket.bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
                    let retry_peer = socket.connect(SocketAddr::V4(endpoint)).await?;
                    let route = match router.next().await {
                        RouterEvent::Ready(route) => route,
                        RouterEvent::Refused { reason, .. } => return Err(format!("route was not released after timeout: {reason:?}").into()),
                    };
                    assert_eq!(route.claimed_mac(), MAC);
                    drop(route);
                    drop(retry_peer);
                    Ok(())
                }
                .await;
                TaskCompletion {
                    outcome: if output.is_ok() {
                        TaskOutcome::Indeterminate("fixture handoff requires reconciliation".into())
                    } else {
                        TaskOutcome::Failed("fleet TLS fixture failed".into())
                    },
                    output,
                    completed_at: TimestampNs(599_000_000_000),
                }
            },
        )
        .await?;
        run.receipt?;
        run.output
    })?;
    Ok(())
}

#[test]
#[ignore = "requires FSS_TEST_CONTROLLER_BIND_IP and disposable FSS_LAB_CERT_DER/FSS_LAB_KEY_DER"]
fn fleet_route_upgrades_through_tls_and_rejects_wrong_mac() -> Test {
    let peer: Ipv4Addr = std::env::var("FSS_TEST_CONTROLLER_BIND_IP")?.parse()?;
    if !(peer.is_private() || peer.is_link_local()) || peer == Ipv4Addr::new(192, 168, 1, 10) {
        return Err("unsuitable private test interface".into());
    }
    let cert = std::fs::read(std::env::var("FSS_LAB_CERT_DER")?)?;
    let key = std::fs::read(std::env::var("FSS_LAB_KEY_DER")?)?;
    if cert.is_empty() || cert.len() > 8192 || key.is_empty() || key.len() > 8192 {
        return Err("invalid disposable TLS fixture".into());
    }
    fleet_upgrade_scenario(peer, &cert, &key, false)?;
    fleet_upgrade_scenario(peer, &cert, &key, true)
}

/// Two independently configured synthetic sources share one controller.
/// The first stalls before TLS. The second either completes its own upgrade or
/// is closed at the explicit handshake limit. No physical camera is involved.
fn parallel_fleet_upgrade_scenario(peer: Ipv4Addr, cert: &[u8], key: &[u8], capacity: usize) -> Test {
    use asupersync::{io::AsyncReadExt, time::timeout};
    use fss_reference::unifi_direct::discovery::{
        fleet::{Enrollment, Fleet, Router},
        pump::{Event as PumpEvent, Pump},
        scan::{Outcome as ScanOutcome, Scanner},
    };
    use std::{future::poll_fn, task::Poll};
    use fss_reference::unifi_direct::controller_acceptor::{Acceptor as FleetAcceptor, ConfigurationError, Event};
    use unifi_tls_05_server_lab::fleet_transport::LabTls;

    const MACS: [[u8; 6]; 2] = [MAC, [0, 0x11, 0x22, 0xaa, 0xbb, 0xdd]];
    const PEERS: [Ipv4Addr; 2] = [Ipv4Addr::LOCALHOST, Ipv4Addr::new(127, 0, 0, 2)];
    struct PairPolicy {
        listen: Ipv4Addr,
        cameras: [ContentDigest; 2],
        admissions: [ContentDigest; 2],
        fences: [u64; 2],
        resources: [String; 2],
    }
    impl setup::Admission for PairPolicy {
        fn permits(&self, candidate: &discovery::CameraCandidate, camera: ContentDigest,
            admission: ContentDigest, generation: u64, fence: u64) -> bool {
            (0..2).any(|i| *candidate.source().ip() == PEERS[i]
                && candidate.mac() == Some(MACS[i]) && camera == self.cameras[i]
                && admission == self.admissions[i] && generation == 1 && fence == self.fences[i])
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
        fn controller_camera(&self, bound: SocketAddrV4, listener_resource: &str,
            camera_resource: &str, source: Ipv4Addr) -> bool {
            *bound.ip() == self.listen && listener_resource == "fixture:parallel-controller"
                && (0..2).any(|i| source == PEERS[i] && camera_resource == self.resources[i])
        }
    }
    impl PeerAdmission for PairPolicy {
        fn permits(&self, mac: [u8; 6]) -> bool { MACS.contains(&mac) }
    }

    let provider = Arc::new(rustls_pure::provider());
    let server = Arc::new(ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?.with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())))?);
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert.to_vec()))?;
    let client = Arc::new(ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots).with_no_client_auth());
    let path = std::fs::canonicalize(std::env::temp_dir())?
        .join(format!("fss-parallel-fleet-{}-{capacity}", std::process::id()));
    std::fs::create_dir(&path)?;
    let temp = Temp(path);
    let store = FileEffectJournal::create(temp.0.join("journal"), EffectJournalLimits::default(), Arc::new(HostSpoolIo))?;
    let mut effects = EffectCoordinator::with_journal(Box::new(store))?;
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 4_000_000;
    budget.bytes = 4_000_000;
    let (mut authority, mut tree) = AuthorityCx::root(RootAuthoritySpec {
        trace_id: "trace:parallel-fleet".into(), operation_id: OperationId::parse("operation:parallel-fleet-owner")?,
        principal: "principal:fixture".into(), capabilities: [RuntimeGrant::AdapterNet, RuntimeGrant::AdapterAuth,
            RuntimeGrant::ObserveStatus, RuntimeGrant::CameraManagementPrepare, RuntimeGrant::CameraManagementCommit]
            .iter().map(|grant| grant.as_str().into()).collect(),
        deadline: Some(TimestampNs(600_000_000_000)), priority: 1, budgets: budget,
        privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"parallel fleet fixture"), generation: 1,
    }, RegionId::new("region:parallel-fleet")?, RegionKind::Process, budget, TimestampNs(1))?;
    let cameras = [ContentDigest::sha256(b"parallel camera 1"), ContentDigest::sha256(b"parallel camera 2")];
    let admissions = [ContentDigest::sha256(b"parallel admission 1"), ContentDigest::sha256(b"parallel admission 2")];
    let certificates = [ContentDigest::sha256(b"parallel cert 1"), ContentDigest::sha256(b"parallel cert 2")];
    let handles = [ContentDigest::sha256(b"parallel secret 1"), ContentDigest::sha256(b"parallel secret 2")];
    let operations = [OperationId::parse("operation:parallel-setup-1")?, OperationId::parse("operation:parallel-setup-2")?];
    let resources = cameras.map(|v| format!("camera:{}", v.to_text()));
    let mut leases = LeaseRegistry::new();
    let fences = [leases.acquire(&resources[0], authority.region().as_str(), None, TimestampNs(2))?.fence,
        leases.acquire(&resources[1], authority.region().as_str(), None, TimestampNs(2))?.fence];
    let leases = RefCell::new(leases);
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("runtime context")?;
        let run = run_owned_async(&mut authority, &mut tree,
            TaskSpec { task_id: TaskId::new("task:parallel-fleet")?, started_at: TimestampNs(3) }, &cx,
            async |task, cx| {
                let output: Test = async {
                    let first = std::net::UdpSocket::bind((PEERS[0], 0))?;
                    let port = first.local_addr()?.port();
                    let second = std::net::UdpSocket::bind((PEERS[1], port))?;
                    let mut senders = Vec::new();
                    for (i, socket) in [first, second].into_iter().enumerate() {
                        socket.set_read_timeout(Some(Duration::from_secs(10)))?;
                        senders.push(Joined(Some(std::thread::spawn(move || -> io::Result<()> {
                            let mut input = [0u8; 64];
                            let (_, source) = socket.recv_from(&mut input)?;
                            socket.send_to(&discovery_packet_for(PEERS[i], MACS[i]), source)?;
                            Ok(())
                        }))));
                    }
                    let clock = MeteredClock::new(task, cx, TimestampNs(4))?;
                    let config = discovery::Config::new_many(PEERS[0], 8,
                        &[SocketAddrV4::new(PEERS[0], port), SocketAddrV4::new(PEERS[1], port)],
                        "fixture:parallel-discovery", Duration::from_millis(300), 8)?;
                    let report = discovery::discover(task, cx, clock.now()?, &config).await?;
                    for sender in senders { sender.finish()?; }
                    let inventory = [Enrollment::new(MACS[0], cameras[0], admissions[0], certificates[0], handles[0], 1)?,
                        Enrollment::new(MACS[1], cameras[1], admissions[1], certificates[1], handles[1], 1)?];
                    let fleet = Fleet::new(&report, &inventory)?;
                    let policy = PairPolicy { listen: peer, cameras, admissions, fences, resources: resources.clone() };
                    let listener = controller_listener::Listener::bind(task, cx, clock, &policy,
                        SocketAddrV4::new(peer, 0), "fixture:parallel-controller", Duration::from_secs(5)).await?;
                    let endpoint = listener.local_addr();
                    for i in 0..2 {
                        let camera_listener = std::net::TcpListener::bind((PEERS[i], 0))?;
                        let SocketAddr::V4(address) = camera_listener.local_addr()? else { return Err("IPv4 required".into()) };
                        let camera_server = server.clone();
                        let fixture = Joined(Some(std::thread::spawn(move || camera_fixture(camera_listener, endpoint.port(), peer, camera_server))));
                        let tls = camera_tls::connect(cx, task, clock, address, cert, &resources[i], Duration::from_secs(5)).await?;
                        let io = MeteredIo::with_clock(tls, clock, &resources[i], 4096)?;
                        let mut http = camera_http::Owner::new(io, task, cx, clock, &policy, PEERS[i], 1, &resources[i])?;
                        let mut owner = setup::Owner { cx, task, clock, effects: &mut effects, leases: &leases,
                            approval: &Approval, admission: &policy, handoff_authority: &Handoff };
                        let mut trace = setup::Trace::default();
                        let outcome = fleet.setup_one(i, &mut owner, &listener, endpoint.port(), &mut http,
                            certificates[i], handles[i], br#"{"username":"fixture","password":"synthetic"}"#,
                            fences[i], peer, &operations[i], handoff::Framing::ContentLength,
                            Duration::from_secs(10), &mut trace).await?;
                        assert!(matches!(outcome, setup::Outcome::Observed { .. }));
                        drop(http);
                        fixture.finish()?;
                    }
                    let router = Router::new(&fleet, &listener, 2, 4096, Duration::from_secs(10))?;
                    let identity = Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?;
                    let refused = match FleetAcceptor::new(router, cx, &policy, LabTls(server.clone()), identity,
                        Default::default(), ProtocolPolicy::RequireOffer, 4096, Duration::from_secs(10), 0) {
                        Err(refusal) => refusal,
                        Ok(_) => return Err("zero handshake capacity was accepted".into()),
                    };
                    assert!(matches!(refused.reason, ConfigurationError::Invalid));
                    let mut acceptor = FleetAcceptor::new(refused.router, cx, &policy, refused.transport,
                        refused.identity,
                        Default::default(), ProtocolPolicy::RequireOffer, 4096, Duration::from_secs(10), capacity)
                        .map_err(|error| format!("acceptor configuration: {error:?}"))?;
                    let socket = asupersync::net::TcpSocket::new_v4()?;
                    socket.bind(SocketAddr::V4(SocketAddrV4::new(PEERS[0], 0)))?;
                    let mut stalled = socket.connect(SocketAddr::V4(endpoint)).await?;
                    poll_fn(|context| match acceptor.poll_next(context) {
                        Poll::Pending if acceptor.handshake_len() == 1 => Poll::Ready(()),
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(_) => panic!("first handshake unexpectedly completed"),
                    }).await;
                    // Discover both synthetic cameras while the first TLS
                    // handshake remains owned and unable to finish.
                    let first_scan = std::net::UdpSocket::bind((PEERS[0], port))?;
                    let second_scan = std::net::UdpSocket::bind((PEERS[1], port))?;
                    let mut scan_senders = Vec::new();
                    for (i, socket) in [first_scan, second_scan].into_iter().enumerate() {
                        socket.set_read_timeout(Some(Duration::from_secs(10)))?;
                        scan_senders.push(Joined(Some(std::thread::spawn(move || -> io::Result<()> {
                            let mut input = [0u8; 64];
                            let (_, source) = socket.recv_from(&mut input)?;
                            socket.send_to(&discovery_packet_for(PEERS[i], MACS[i]), source)?;
                            Ok(())
                        }))));
                    }
                    let scanner = Scanner::new(cx, task, clock, &fleet, config.clone(), Duration::from_secs(5))?;
                    let mut pump = Pump::new(&scanner, &mut acceptor)?;
                    match pump.next().await {
                        PumpEvent::Discovery(Ok(ScanOutcome::Updated(snapshot))) => {
                            assert_eq!(snapshot.report().cameras.len(), 2);
                        }
                        _ => return Err("periodic scan did not complete during stalled TLS".into()),
                    }
                    for sender in scan_senders { sender.finish()?; }
                    assert_eq!(pump.driver().handshake_len(), 1);
                    pump.request_scan_stop();
                    assert!(pump.scan_drained());
                    if capacity == 1 {
                        let socket = asupersync::net::TcpSocket::new_v4()?;
                        socket.bind(SocketAddr::V4(SocketAddrV4::new(PEERS[1], 0)))?;
                        let mut refused = socket.connect(SocketAddr::V4(endpoint)).await?;
                        assert!(matches!(pump.next().await, PumpEvent::Route(Event::HandshakeCapacity { index: 1 })));
                        let mut byte = [0u8; 1];
                        assert!(matches!(timeout(cx.now(), Duration::from_secs(5), refused.read(&mut byte)).await?, Ok(0)));
                    } else {
                        let tls_client = client.clone();
                        let other = Joined(Some(std::thread::spawn(move || -> io::Result<()> {
                            let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
                            socket.bind(&SocketAddr::V4(SocketAddrV4::new(PEERS[1], 0)).into())?;
                            socket.connect_timeout(&SocketAddr::V4(endpoint).into(), Duration::from_secs(5))?;
                            let raw: std::net::TcpStream = socket.into();
                            raw.set_read_timeout(Some(Duration::from_secs(10)))?;
                            raw.set_write_timeout(Some(Duration::from_secs(10)))?;
                            let mut tls = StreamOwned::new(ClientConnection::new(tls_client,
                                ServerName::try_from("localhost").map_err(io::Error::other)?).map_err(io::Error::other)?, raw);
                            tls.write_all(HEAD.replace("001122aabbcc", "001122aabbdd").as_bytes())?;
                            tls.flush()?;
                            let mut response = Vec::new();
                            while !response.ends_with(b"\r\n\r\n") {
                                let mut byte = [0u8; 1]; tls.read_exact(&mut byte)?; response.push(byte[0]);
                                if response.len() > 4096 { return Err(io::Error::other("upgrade response limit")); }
                            }
                            if !response.starts_with(b"HTTP/1.1 101 ") { return Err(io::Error::other("upgrade refused")); }
                            Ok(())
                        })));
                        let session = match pump.next().await {
                            PumpEvent::Route(Event::Session { index: 1, session }) => session,
                            _ => return Err("second camera failed to upgrade while first stalled".into()),
                        };
                        assert_eq!(session.claimed_mac(), MACS[1]);
                        assert_eq!(pump.driver().handshake_len(), 1);
                        other.finish()?;
                        drop(session);
                    }
                    drop(pump);
                    drop(acceptor);
                    let mut byte = [0u8; 1];
                    assert!(matches!(timeout(cx.now(), Duration::from_secs(5), stalled.read(&mut byte)).await?, Ok(0)));
                    Ok(())
                }.await;
                TaskCompletion {
                    outcome: if output.is_ok() { TaskOutcome::Indeterminate("fixture handoffs require reconciliation".into()) }
                        else { TaskOutcome::Failed("parallel fleet fixture failed".into()) },
                    output, completed_at: TimestampNs(599_000_000_000),
                }
            }).await?;
        run.receipt?;
        run.output
    })
}

#[test]
#[ignore = "requires FSS_TEST_CONTROLLER_BIND_IP and disposable FSS_LAB_CERT_DER/FSS_LAB_KEY_DER"]
fn fleet_acceptor_progresses_other_camera_and_closes_at_capacity() -> Test {
    let peer: Ipv4Addr = std::env::var("FSS_TEST_CONTROLLER_BIND_IP")?.parse()?;
    if !(peer.is_private() || peer.is_link_local()) || peer == Ipv4Addr::new(192, 168, 1, 10) {
        return Err("unsuitable private test interface".into());
    }
    let cert = std::fs::read(std::env::var("FSS_LAB_CERT_DER")?)?;
    let key = std::fs::read(std::env::var("FSS_LAB_KEY_DER")?)?;
    if cert.is_empty() || cert.len() > 8192 || key.is_empty() || key.len() > 8192 {
        return Err("invalid disposable TLS fixture".into());
    }
    parallel_fleet_upgrade_scenario(peer, &cert, &key, 2)?;
    parallel_fleet_upgrade_scenario(peer, &cert, &key, 1)
}
