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
    controller_listener, conversation, discovery, handoff, intent, listener, management,
    metered::{MeteredClock, MeteredIo},
    owner::PeerAdmission,
    pipeline, recording, setup,
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
    for index in 0..7 {
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
    use fss_reference::unifi_direct::discovery::fleet::{
        Enrollment, Fleet, RouteError, Router, RouterEvent,
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
    budget.bytes = 2_000_000;
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
    let wire = media_fixture_from(include_bytes!("fixtures/synthetic_g4_resolution.264"), 4)?;
    let runtime = RuntimeBuilder::current_thread().build()?;
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
                                media.write_all(&wire)?;
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
                    use unifi_tls_05_server_lab::fleet_acceptor::{Event, FleetAcceptor};
                    let admission = Permissive;
                    let mut acceptor = FleetAcceptor::new(
                        router, cx, &admission, server.clone(),
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
                            Event::HandshakeFailed { index: 0, reason: setup_upgrade::Error::Upgrade(
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
                        let started = listener::start_tracked(
                            &mut conversation, &mut session, &request, framer, recorder, &mut start_trace,
                        ).await?;
                        let mut pipeline = started.pipeline;
                        let mut decoded_frames = 0;
                        loop {
                            match pipeline.step(task, cx, clock.now()?).await? {
                                pipeline::Step::Recording(recording::Push::Segment(segment)) => {
                                    if decoded_frames > 0 {
                                        continue;
                                    }
                                    let initialization = pipeline.initialization().ok_or("missing media initialization")?;
                                    let mut movie = initialization.bytes().to_vec();
                                    movie.extend_from_slice(segment.fragment().bytes());
                                    let demux = AvcMp4::parse(&movie, None, DemuxLimits::default())?;
                                    let annex = demux.annex_b(0, 1)?;
                                    let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                                    let mut frames = decoder.decode_annex_b(annex.bytes())?;
                                    frames.extend(decoder.finish()?);
                                    for frame in frames {
                                        assert_eq!((frame.width(), frame.height()), (2688, 1512));
                                        decoded_frames += 1;
                                    }
                                }
                                pipeline::Step::Recording(_) | pipeline::Step::Progress { .. } => (),
                                pipeline::Step::Eof => break,
                                pipeline::Step::LimitReached => return Err("media limit reached".into()),
                            }
                        }
                        assert!(decoded_frames > 0, "no synthetic full-resolution video decoded");
                        let _retired = pipeline.retire();
                        let _session_retirement = session.retire();
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
                    drop(fresh_route);
                    drop(reconnect);
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
    use fss_reference::unifi_direct::discovery::fleet::{Enrollment, Fleet, Router};
    use std::{future::poll_fn, task::Poll};
    use unifi_tls_05_server_lab::fleet_acceptor::{Event, FleetAcceptor};

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
                    let mut acceptor = FleetAcceptor::new(router, cx, &policy, server.clone(),
                        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
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
                    if capacity == 1 {
                        let socket = asupersync::net::TcpSocket::new_v4()?;
                        socket.bind(SocketAddr::V4(SocketAddrV4::new(PEERS[1], 0)))?;
                        let mut refused = socket.connect(SocketAddr::V4(endpoint)).await?;
                        assert!(matches!(acceptor.next().await, Event::HandshakeCapacity { index: 1 }));
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
                        let session = match acceptor.next().await {
                            Event::Session { index: 1, session } => session,
                            _ => return Err("second camera failed to upgrade while first stalled".into()),
                        };
                        assert_eq!(session.claimed_mac(), MACS[1]);
                        assert_eq!(acceptor.handshake_len(), 1);
                        other.finish()?;
                        drop(session);
                    }
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
