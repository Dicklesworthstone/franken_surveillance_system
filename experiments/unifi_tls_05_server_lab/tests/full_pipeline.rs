#![forbid(unsafe_code)]
#![cfg(unix)]
//! Observe a fixture hello, then durably prepare its response inside the task.
//! The journal calls here are synchronous, not a production async store.
use asupersync::{net::TcpListener, runtime::RuntimeBuilder, time::timeout};
use fss_container::{
    demux::{AvcMp4, DemuxLimits},
    flv_avc::SourceKey,
};
use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, OperationId, RegionId, RegionKind,
    RootAuthoritySpec, RuntimeGrant, TaskId, TaskOutcome, TimestampNs, region::ContextAuthority,
};
use fss_geometry::WorkBudget;
use fss_object::{
    HostSpoolIo,
    effect_journal::{EffectJournalLimits, FileEffectJournal},
};
use fss_packet::extended_flv::{Limits as FlvLimits, stream::Framer};
use fss_reference::unifi_direct::{
    AudioCodec, Controller, Identity, StreamStart, VideoChannel, VideoCodec, archive,
    controller_listener, conversation, evidence,
    ingress::DirectIngress,
    intent, listener,
    management::{Intent, Preconditions},
    metered::{MeteredClock, MeteredIo},
    owner::{self, PeerAdmission},
    pipeline,
    receive::{ManagementAuthority, StreamAuthority},
    recording, supervisor,
    upgrade::ProtocolPolicy,
};
use fss_reference::{ReferenceDeployment, ReplayCx};
use fss_runtime::{
    authority::AuthorityCx,
    effect::{CommitApproval, CommittedEffect, EffectCoordinator, PreparedEffect},
    execution::{TaskCompletion, TaskSpec, run_owned_async},
    lease::LeaseRegistry,
    tcp_ingress::TcpIngress,
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use std::{
    cell::{Cell, RefCell},
    error::Error,
    future::{Future, poll_fn},
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    sync::Arc,
    task::Poll,
    time::Duration,
};
use unifi_tls_05_server_lab::server::Server;

#[path = "../src/bin/trial_checkpoint/mod.rs"]
mod trial_checkpoint;
#[path = "../src/bin/trial_run_id/mod.rs"]
mod trial_run_id;

type Test = Result<(), Box<dyn Error>>;

#[test]
fn trial_run_id_separates_operations_and_runs() -> Test {
    let first = trial_run_id::TrialRunId::fresh()?;
    let second = trial_run_id::TrialRunId::fresh()?;
    assert_eq!(first.as_str().len(), 32);
    assert!(first.as_str().bytes().all(|b| b.is_ascii_hexdigit()));
    assert_ne!(first.as_str(), second.as_str());
    assert_ne!(first.operation("handoff")?, first.operation("stream")?);
    assert_ne!(first.operation("handoff")?, second.operation("handoff")?);
    assert_ne!(first.owned_step(1)?, second.owned_step(1)?);
    assert_ne!(first.owned_event(1)?, second.owned_event(1)?);
    assert_ne!(first.owned_step(1)?, first.owned_event(1)?);
    assert_ne!(first.owned_step(1)?, first.owned_step(2)?);
    assert!(first.operation("invalid name").is_err());
    Ok(())
}

fn connect_fixture_from(
    source: Ipv4Addr,
    destination: SocketAddr,
    timeout: Duration,
) -> io::Result<std::net::TcpStream> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.bind(&SocketAddrV4::new(source, 0).into())?;
    socket.connect_timeout(&destination.into(), timeout)?;
    Ok(socket.into())
}
fn require_fixture_source_preserved(address: Ipv4Addr) -> io::Result<()> {
    let listener = std::net::TcpListener::bind((address, 0))?;
    let destination = listener.local_addr()?;
    let client = connect_fixture_from(address, destination, Duration::from_secs(2))?;
    let (_, peer) = listener.accept()?;
    drop(client);
    if peer.ip() != std::net::IpAddr::V4(address) {
        return Err(io::Error::other(
            "fixture host rewrites the claimed source address",
        ));
    }
    Ok(())
}
const HEAD: &str = "GET / HTTP/1.1\r\nHost: camera.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nCamera-Mac: 001122aabbcc\r\nSec-WebSocket-Protocol: secure_transfer\r\n\r\n";
const HELLO:&[u8]=br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_hello","messageId":7,"payload":{}}"#;
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct FixtureArchiveAuthority {
    retention: ContentDigest,
    allowed: Cell<bool>,
}
impl archive::RetainAuthority for FixtureArchiveAuthority {
    fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool {
        self.allowed.get() && self.retention == retention
    }
}
impl archive::ReadAuthority for FixtureArchiveAuthority {
    fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool {
        self.allowed.get() && self.retention == retention
    }
}
struct FixtureAdmission;
impl PeerAdmission for FixtureAdmission {
    fn permits(&self, claim: [u8; 6]) -> bool {
        claim == [0, 0x11, 0x22, 0xaa, 0xbb, 0xcc]
    }
}
struct FixtureMediaAdmission {
    listen: Cell<bool>,
    peer: Cell<bool>,
}
impl listener::Admission for FixtureMediaAdmission {
    fn listener(&self, requested: SocketAddrV4, bound: Option<SocketAddrV4>) -> bool {
        self.listen.get()
            && requested.ip().is_loopback()
            && bound.is_none_or(|address| address.ip().is_loopback() && address.port() != 0)
    }
    fn peer(&self, bound: SocketAddrV4, source: SocketAddrV4) -> bool {
        self.peer.get() && bound.ip().is_loopback() && source.ip().is_loopback()
    }
}
struct Guard<'a, 'scope, 'task> {
    leases: &'a RefCell<LeaseRegistry>,
    clock: MeteredClock<'scope, 'task>,
}
impl ManagementAuthority for Guard<'_, '_, '_> {
    fn permits(&self, mac: [u8; 6], intent: Intent, permit: &CommittedEffect) -> bool {
        let Ok(now) = self.clock.now() else {
            return false;
        };
        mac == [0, 0x11, 0x22, 0xaa, 0xbb, 0xcc]
            && permit.fence() == intent.fence()
            && self
                .leases
                .borrow_mut()
                .check_fence(&intent.resource(), intent.fence(), now)
                .is_ok()
    }
}
impl StreamAuthority for Guard<'_, '_, '_> {
    fn permits(&self, mac: [u8; 6], intent: intent::Intent, permit: &CommittedEffect) -> bool {
        let Ok(now) = self.clock.now() else {
            return false;
        };
        mac == [0, 0x11, 0x22, 0xaa, 0xbb, 0xcc]
            && permit.fence() == intent.fence()
            && self
                .leases
                .borrow_mut()
                .check_fence(&intent.resource(), intent.fence(), now)
                .is_ok()
    }
}
fn frame(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= u16::MAX as usize);
    let mask = [1, 2, 3, 4];
    let mut bytes = vec![0x82];
    if payload.len() < 126 {
        bytes.push(0x80 | payload.len() as u8);
    } else {
        bytes.push(0x80 | 126);
        bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    bytes.extend_from_slice(&mask);
    bytes.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    bytes
}

fn receive_binary(socket: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut head = [0u8; 2];
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
        _ => return Err(io::Error::other("frame size")),
    };
    if len > 4096 {
        return Err(io::Error::other("frame bound"));
    }
    let mut data = vec![0; len];
    socket.read_exact(&mut data)?;
    Ok(data)
}

fn flv_tag(timestamp: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut result = vec![
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
    result.extend_from_slice(payload);
    result.extend_from_slice(&(11_u32 + n as u32).to_be_bytes());
    result
}

fn media_fixture() -> Result<Vec<u8>, Box<dyn Error>> {
    media_fixture_from(include_bytes!("../../../crates/fss-packet/tests/fixtures/avc/baseline.264"), 3)
}

fn media_fixture_from(annex_b: &[u8], cycle: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    media_fixture_from_frames(annex_b, cycle, 7)
}

fn media_fixture_from_frames(annex_b: &[u8], cycle: usize, frames: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let nals: Vec<_> = fss_codec_h264::annex_b_nal_units(annex_b).collect();
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
    let mut result = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    result.extend(flv_tag(0, &config));
    for index in 0..frames {
        let nal = pictures[index % cycle];
        let mut payload = vec![0x17, 1, 0, 0, 0];
        payload.extend_from_slice(&u32::try_from(nal.len())?.to_be_bytes());
        payload.extend_from_slice(nal);
        result.extend(flv_tag(index as u32 * 40, &payload));
    }
    Ok(result)
}

struct FixtureClock;
impl conversation::WallClock for FixtureClock {
    fn observe(&self) -> Option<conversation::WallTime> {
        Some(conversation::WallTime {
            unix_ms: 1_700_000_000_000,
            timestamp: "2026-11-05T10:00:00.000Z".into(),
        })
    }
}
struct FixtureApproval<'a> {
    revoke_stream: Option<&'a Cell<bool>>,
}
impl conversation::Approval for FixtureApproval<'_> {
    fn approve(&self, prepared: &PreparedEffect) -> Option<CommitApproval> {
        if prepared.effect_class() == "EFFECT-CAMERA-SETTING-001" {
            if let Some(policy) = self.revoke_stream {
                policy.set(false);
            }
        }
        Some(CommitApproval {
            prepared_digest: prepared.digest(),
            current_precondition_digest: prepared.precondition_digest(),
        })
    }
}

fn conversation_scenario(revoke_stream: bool) -> Test {
    let cert = std::fs::read(std::env::var("FSS_LAB_CERT_DER")?)?;
    let key = std::fs::read(std::env::var("FSS_LAB_KEY_DER")?)?;
    let provider = Arc::new(rustls_pure::provider());
    let server_config = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        )?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert))?;
    let client_config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let path = std::fs::canonicalize(std::env::temp_dir())?.join(format!(
        "fss-unifi-task-conversation-{}-{revoke_stream}",
        std::process::id(),
    ));
    std::fs::create_dir(&path)?;
    let temp = Temp(path);
    // Synthetic fixture authority and capture bounds. This is intentionally
    // synchronous and is not a production archive worker or a camera clock.
    let archive_context = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:tls-fixture-archive".into(),
        operation_id: OperationId::parse("operation:tls-fixture-archive")?,
        principal: "principal:fixture".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 1,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:fixture".into(),
        retention_scope: "retention:fixture".into(),
        anchor_universe: ContentDigest::sha256(b"synthetic TLS fixture archive"),
        generation: 1,
    })?;
    let archive_cx = ReplayCx::from_context_authority(&archive_context, temp.0.clone())?;
    let archive_root = temp.0.join("archive");
    let archive_access = FixtureArchiveAuthority {
        retention: ContentDigest::sha256(b"synthetic retention policy"),
        allowed: Cell::new(true),
    };
    let store = FileEffectJournal::create(
        temp.0.join("journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut effects = EffectCoordinator::with_journal(Box::new(store))?;
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 1_000_000;
    budget.bytes = 1_000_000;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:conversation".into(),
            operation_id: OperationId::parse("operation:conversation-owner")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::CameraManagementPrepare.as_str().into(),
                RuntimeGrant::CameraManagementCommit.as_str().into(),
                RuntimeGrant::CameraSettingPrepare.as_str().into(),
                RuntimeGrant::CameraSettingCommit.as_str().into(),
                RuntimeGrant::ReadMedia.as_str().into(),
            ],
            deadline: Some(TimestampNs(60_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"fixture"),
            generation: 1,
        },
        RegionId::new("region:conversation")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let camera = ContentDigest::sha256(b"verified fixture camera");
    let resource = format!("camera:{}", camera.to_text());
    let mut leases = LeaseRegistry::new();
    let fence = leases
        .acquire(&resource, authority.region().as_str(), None, TimestampNs(2))?
        .fence;
    let leases = RefCell::new(leases);
    let conditions = Preconditions {
        camera,
        peer_admission: ContentDigest::sha256(b"fixture admission"),
        session_generation: 1,
        previous_association: None,
        previous_clock: None,
        lease_fence: fence,
    };
    let stream_conditions = intent::Preconditions {
        camera,
        peer_admission: conditions.peer_admission,
        stream_generation: 1,
        previous_settings: None,
        lease_fence: fence,
    };
    let operations = [
        OperationId::parse("operation:conversation-hello")?,
        OperationId::parse("operation:conversation-agreement")?,
        OperationId::parse("operation:conversation-stream")?,
        OperationId::parse("operation:conversation-time-sync")?,
        OperationId::parse("operation:conversation-later-time-sync")?,
    ];
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx=asupersync::Cx::current().ok_or("missing runtime")?;
        let result=run_owned_async(&mut authority,&mut tree,TaskSpec { task_id:TaskId::new("task:conversation")?, started_at:TimestampNs(3) },&cx,async |task,cx| {
            let output: Test = async {
                let clock=MeteredClock::new(task,cx,TimestampNs(4))?;
                let policy=FixtureMediaAdmission {listen:Cell::new(false),peer:Cell::new(true)};
                let bind=SocketAddrV4::new(Ipv4Addr::LOCALHOST,0);
                assert!(matches!(listener::Listener::bind(task,cx,clock,&policy,bind,"fixture:camera",Duration::from_secs(5)).await,Err(listener::Error::Denied)));
                policy.listen.set(true);
                let revoked=listener::Listener::bind(task,cx,clock,&policy,bind,"fixture:camera",Duration::from_secs(5)).await?;
                let revoked_address=SocketAddr::V4(revoked.local_addr());
                let framer=Framer::new(FlvLimits::default(),1024*1024)?;
                let recorder=recording::Recorder::new(SourceKey {connection:3,generation:1},recording::Limits::default())?;
                let mut waiting=Box::pin(revoked.accept(framer,recorder,4096,1_000_000,Duration::from_secs(5)));
                poll_fn(|context| match waiting.as_mut().poll(context) {Poll::Pending=>Poll::Ready(()),Poll::Ready(_)=>panic!("accept should wait")}).await;
                policy.listen.set(false);
                let wake=std::net::TcpStream::connect_timeout(&revoked_address,Duration::from_secs(1))?;
                assert!(matches!(waiting.await,Err(listener::Error::Denied)));
                drop(wake);
                policy.listen.set(true);
                policy.peer.set(false);
                let denied_peer=listener::Listener::bind(task,cx,clock,&policy,bind,"fixture:camera",Duration::from_secs(5)).await?;
                let denied_address=SocketAddr::V4(denied_peer.local_addr());
                let unexpected=std::thread::spawn(move || std::net::TcpStream::connect_timeout(&denied_address,Duration::from_secs(5)).map(drop));
                let framer=Framer::new(FlvLimits::default(),1024*1024)?;
                let recorder=recording::Recorder::new(SourceKey {connection:4,generation:1},recording::Limits::default())?;
                assert!(matches!(denied_peer.accept(framer,recorder,4096,1_000_000,Duration::from_secs(5)).await,Err(listener::Error::Denied)));
                unexpected.join().map_err(|_|"unexpected peer panic")??;
                policy.peer.set(true);
                let controller_listener=controller_listener::Listener::bind(task,cx,clock,&policy,bind,"fixture:camera",Duration::from_secs(5)).await?;
                let address=SocketAddr::V4(controller_listener.local_addr());
                let wire=media_fixture()?;
                let expected=wire.clone();
                let peer=std::thread::spawn(move || -> io::Result<()> {
                    let raw=std::net::TcpStream::connect_timeout(&address,Duration::from_secs(5))?;
                    raw.set_read_timeout(Some(Duration::from_secs(5)))?;raw.set_write_timeout(Some(Duration::from_secs(5)))?;
                    let connection=ClientConnection::new(Arc::new(client_config),ServerName::try_from("localhost").map_err(io::Error::other)?).map_err(io::Error::other)?;
                    let mut socket=StreamOwned::new(connection,raw);
                    let mut request=HEAD.as_bytes().to_vec(); request.extend(frame(HELLO)); socket.write_all(&request)?;socket.flush()?;
                    let mut header=Vec::new(); let mut byte=[0u8;1];
                    while !header.ends_with(b"\r\n\r\n") { socket.read_exact(&mut byte)?; header.push(byte[0]); if header.len()>4096 { return Err(io::Error::other("upgrade limit")); } }
                    if !header.starts_with(b"HTTP/1.1 101 ") { return Err(io::Error::other("upgrade refused")); }
                    if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_hello".len()).any(|w|w==b"ubnt_avclient_hello") { return Err(io::Error::other("missing hello reply")); }
                    socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":10}"#))?;socket.flush()?;
                    if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_timeSync".len()).any(|w|w==b"ubnt_avclient_timeSync") { return Err(io::Error::other("missing time-sync reply")); }
                    if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_paramAgreement".len()).any(|w|w==b"ubnt_avclient_paramAgreement") { return Err(io::Error::other("missing agreement")); }
                    socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_paramAgreement","messageId":8,"inResponseTo":3}"#))?;socket.flush()?;
                    if revoke_stream {
                        return match receive_binary(&mut socket) {
                            Err(error) if error.kind()==io::ErrorKind::UnexpectedEof=>Ok(()),
                            _=>Err(io::Error::other("revoked stream was sent")),
                        };
                    }
                    let stream_request=receive_binary(&mut socket)?;
                    if !stream_request.windows(b"ChangeVideoSettings".len()).any(|w|w==b"ChangeVideoSettings") { return Err(io::Error::other("missing stream request")); }
                    let message=std::str::from_utf8(&stream_request).map_err(io::Error::other)?;
                    let destination=message.split_once("tcp://").and_then(|(_,suffix)|suffix.split_once('?')).map(|(addr,_)|addr).ok_or_else(||io::Error::other("missing stream destination"))?;
                    let destination:SocketAddr=destination.parse().map_err(io::Error::other)?;
                    if !matches!(destination,SocketAddr::V4(addr) if addr.ip().is_loopback() && addr.port()!=0) {return Err(io::Error::other("invalid stream destination"));}
                    socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ChangeVideoSettings","messageId":9,"inResponseTo":4}"#))?;socket.flush()?;
                    let mut media=std::net::TcpStream::connect_timeout(&destination,Duration::from_secs(5))?;
                    let split=wire.len().min(100);
                    media.write_all(&wire[..split])?;
                    socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":11}"#))?;socket.flush()?;
                    if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_timeSync".len()).any(|w|w==b"ubnt_avclient_timeSync") { return Err(io::Error::other("missing post-start time-sync reply")); }
                    media.write_all(&wire[split..])?;
                    drop(media);
                    let mut last=[0u8;1];
                    match socket.read(&mut last) { Ok(0)=>Ok(()), Err(error) if error.kind()==io::ErrorKind::UnexpectedEof=>Ok(()), _=>Err(io::Error::other("controller did not retire")) }
                });
                let (raw,gate)=controller_listener.accept(37,Duration::from_secs(5)).await?;
                let tls=timeout(cx.now(),Duration::from_secs(5),Server::new(ServerConnection::new(Arc::new(server_config))?,raw).handshake(cx)).await??;
                let io=MeteredIo::with_clock(gate.wrap(tls),clock,"fixture:camera",4096)?;
                let controller=Controller::new(Identity::new("FSS","12345678-1234-4abc-9abc-123456789abc","1.20.0")?,1)?;
                let mut session=owner::accept_guarded(io,ProtocolPolicy::RequireOffer,&FixtureAdmission,gate,controller,Duration::from_secs(5)).await?;
                let guard=Guard { leases:&leases, clock };
                let request=StreamStart::new(VideoChannel::Video2,SocketAddrV4::new(Ipv4Addr::LOCALHOST,17551),VideoCodec::H264,AudioCodec::Aac,"0123456789abcdef")?;
                let config=conversation::Config { hello:&operations[0], agreement:&operations[1], stream:&operations[2], time_sync:&operations[3..4], management:conditions, stream_conditions, request:&request, wait:Duration::from_secs(5) };
                let approval=FixtureApproval {revoke_stream:revoke_stream.then_some(&policy.listen)};
                let other_clock=MeteredClock::new(task,cx,TimestampNs(5))?;
                let mut wrong_owner=conversation::Owner { cx, task, clock:other_clock, effects:&mut effects, leases:&leases, approval:&approval, management_authority:&guard, stream_authority:&guard, wall:&FixtureClock };
                assert_eq!(wrong_owner.start(&mut session,&config).await,Err(conversation::Error::Configuration));
                let mut owner=conversation::Owner { cx, task, clock, effects:&mut effects, leases:&leases, approval:&approval, management_authority:&guard, stream_authority:&guard, wall:&FixtureClock };
                let duplicate=conversation::Config { agreement:&operations[0], ..config };
                assert_eq!(owner.start(&mut session,&duplicate).await,Err(conversation::Error::Configuration));
                let mismatched=conversation::Config { stream_conditions:intent::Preconditions { lease_fence:fence+1, ..stream_conditions }, ..config };
                assert_eq!(owner.start(&mut session,&mismatched).await,Err(conversation::Error::Configuration));
                let start=listener::Start {bind,resource:"fixture:camera",admission:&policy,channel:VideoChannel::Video2,video:VideoCodec::H264,audio:AudioCodec::Aac,stream_name:"0123456789abcdef",hello:&operations[0],agreement:&operations[1],stream:&operations[2],time_sync:&operations[3..4],management:conditions,stream_conditions,chunk_bytes:4096,max_bytes:u64::try_from(expected.len())?+1,bind_wait:Duration::from_secs(5),conversation_wait:Duration::from_secs(5),accept_wait:Duration::from_secs(5)};
                let invalid=listener::Start {max_bytes:0,..start};
                let framer=Framer::new(FlvLimits::default(),1024*1024)?;
                let recorder=recording::Recorder::new(SourceKey {connection:5,generation:1},recording::Limits::default())?;
                assert!(matches!(listener::start(&mut owner,&mut session,&invalid,framer,recorder).await,Err(listener::StartError::Listener(listener::Error::Configuration))));
                let framer=Framer::new(FlvLimits::default(),1024*1024)?;
                let recorder=recording::Recorder::new(SourceKey {connection:1,generation:1},recording::Limits::default())?;
                let started=listener::start(&mut owner,&mut session,&start,framer,recorder).await;
                if revoke_stream {
                    assert!(matches!(started,Err(listener::StartError::Conversation(conversation::Error::Effect))));
                    let retired=session.retire();
                    assert!(retired.prepared.is_some());
                    peer.join().map_err(|_|"fixture peer panic")??;
                    return Ok(());
                }
                let started=started?;
                assert_eq!(started.reply,conversation::Reply { status_code:None, success:None, time_syncs:1 });
                let mut supervisor=supervisor::Supervisor::new(session,started.pipeline,conditions);
                let mut later_syncs=0;
                let mut originals=Vec::new();
                let mut segments=0;
                let mut frames=0;
                let mut configuration=None;
                let mut pins=Vec::new();
                let mut archive=ReferenceDeployment::open(&archive_root,"site:tls-fixture",&archive_cx)?;
                loop {
                    match supervisor.step(&mut owner,&operations[4],Duration::from_secs(5)).await {
                        supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {record,disposition})) => {
                            originals.extend_from_slice(record.bytes());
                            if disposition == recording::SourceDisposition::Configuration { configuration=Some(record); }
                        },
                        supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Buffered) | pipeline::Step::Progress {..}) => (),
                        supervisor::Step::TimeSyncWritten { mut trace } => {
                            assert!(trace.dispatch_started());
                            assert!(matches!(trace.take_written(),Some(fss_reference::unifi_direct::receive::ManagementWrite::Written {..})));
                            later_syncs+=1;
                        },
                        supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Segment(segment))) => {
                            for record in segment.source() { originals.extend_from_slice(record.bytes()); }
                            let initialization=supervisor.initialization().ok_or("missing initialization")?;
                            let plan=evidence::Prepared::new_with_capture(
                                &segment,configuration.as_ref().ok_or("missing configuration")?,initialization,
                                archive_access.retention,Some(CaptureInterval::new(TimestampNs(1),TimestampNs(10))?),
                                evidence::Limits::default())?;
                            let pin=archive::Pin::from_plan(&plan).ok_or("fixture capture missing")?;
                            let receipt=archive::publish(&plan,&mut archive,&archive_access,archive::Limits::default(),&mut WorkBudget::new(10_000_000_000),&archive_cx)?;
                            assert_eq!(receipt.root,pin.root);
                            pins.push(pin);
                            let mut movie=initialization.bytes().to_vec();
                            movie.extend_from_slice(segment.fragment().bytes());
                            let demux=AvcMp4::parse(&movie,None,DemuxLimits::default())?;
                            let annex=demux.annex_b(0,3)?;
                            let mut decoder=fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                            frames+=decoder.decode_annex_b(annex.bytes())?.len();
                            frames+=decoder.finish()?.len();
                            segments+=1;
                        }
                        supervisor::Step::Media(pipeline::Step::Eof) => break,
                        other => return Err(format!("unexpected supervisor result: {other:?}").into()),
                    }
                }
                assert_eq!(later_syncs,1);
                let retired=supervisor.retire();
                assert_eq!(retired.controller.previous_phase, fss_reference::unifi_direct::Phase::AgreementReplyObserved);
                assert_eq!(retired.controller.stream_request, None);
                let retired_media=retired.media;
                assert!(retired_media.ingress.buffered.is_none());
                assert!(retired_media.ingress.source.pending.is_none());
                for record in retired_media.recorder.pending { originals.extend_from_slice(record.bytes()); }
                originals.extend_from_slice(retired_media.ingress.framing.bytes());
                assert_eq!(originals,expected);
                assert_eq!((segments,frames),(2,6));
                assert_eq!(pins.len(),2);
                drop(archive);
                let mut reopened=ReferenceDeployment::reopen(&archive_root,"site:tls-fixture",&archive_cx)?;
                let mut recovered_frames=0;
                for pin in pins {
                    let recovered=archive::read_clip(&mut reopened,pin,&archive_access,archive::Limits::default(),&mut WorkBudget::new(10_000_000_000),&archive_cx)?;
                    let movie=AvcMp4::parse(recovered.bytes(),None,DemuxLimits::default())?;
                    let annex=movie.annex_b(0,recovered.samples())?;
                    let mut decoder=fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                    recovered_frames+=decoder.decode_annex_b(annex.bytes())?.len();
                    recovered_frames+=decoder.finish()?.len();
                }
                assert_eq!(recovered_frames,6);
                drop(reopened);
                // A recorder capacity failure must stop further reads while
                // returning every received source byte to its current owner.
                let fault_listener=TcpListener::bind("127.0.0.1:0").await?;
                let fault_address=fault_listener.local_addr()?;
                let fault_wire=expected.clone();
                let fault_sender=std::thread::spawn(move || -> io::Result<()> {
                    let mut stream=std::net::TcpStream::connect_timeout(&fault_address,Duration::from_secs(5))?;
                    stream.write_all(&fault_wire)
                });
                let (fault_socket,_)=timeout(cx.now(),Duration::from_secs(5),fault_listener.accept()).await??;
                let fault_tcp=TcpIngress::new(fault_socket,"fixture:camera",4096,u64::try_from(expected.len())?+1)?;
                let fault_framer=Framer::new(FlvLimits::default(),1024*1024)?;
                let fault_recorder=recording::Recorder::new(SourceKey {connection:2,generation:1},recording::Limits {max_records:1,..Default::default()})?;
                let mut fault=pipeline::Pipeline::new(DirectIngress::new(fault_tcp,fault_framer),fault_recorder);
                let mut retained=Vec::new();
                let unaccepted=loop {
                    match timeout(cx.now(),Duration::from_secs(5),fault.step(task,cx,clock.now()?)).await? {
                        Ok(pipeline::Step::Recording(recording::Push::Source {record,..}))=>retained.extend_from_slice(record.bytes()),
                        Ok(pipeline::Step::Recording(recording::Push::Buffered)|pipeline::Step::Progress {..})=>(),
                        Err(pipeline::Error::Recording(refusal))=>{
                            assert_eq!(refusal.reason,recording::Error::Limit);
                            break refusal.unaccepted.ok_or("missing refused source")?;
                        }
                        _=>return Err("unexpected fault result".into()),
                    }
                };
                assert!(matches!(fault.step(task,cx,clock.now()?).await,Err(pipeline::Error::Stopped)));
                let retirement=fault.retire();
                assert!(retirement.recorder.fenced);
                for record in retirement.recorder.pending {retained.extend_from_slice(record.bytes());}
                retained.extend_from_slice(unaccepted.bytes());
                retained.extend_from_slice(retirement.ingress.framing.bytes());
                if let Some(buffered)=retirement.ingress.buffered {retained.extend_from_slice(&buffered.source.bytes()[buffered.appended..]);}
                if let Some(pending)=retirement.ingress.source.pending {retained.extend_from_slice(pending.bytes());}
                assert_eq!(retained.len() as u64,retirement.ingress.source.received);
                assert_eq!(retained,expected[..retained.len()]);
                fault_sender.join().map_err(|_|"fault sender panic")??;
                peer.join().map_err(|_|"fixture peer panic")??;
                Ok(())
            }.await;
            let outcome=if output.is_ok() { TaskOutcome::Indeterminate("fixture changes require reconciliation".into()) } else { TaskOutcome::Failed("conversation fixture failed".into()) };
            TaskCompletion { output, outcome, completed_at:TimestampNs(59_000_000_000) }
        }).await?;
        result.receipt?; result.output
    })?;
    for operation in &operations[..if revoke_stream { 4 } else { 5 }] {
        assert_eq!(
            effects
                .journal()
                .operation(operation)
                .ok_or("missing journal operation")?
                .state,
            fss_core::EffectState::Committed
        );
    }
    assert!(!authority.finalize_report(&tree)?.is_empty());
    Ok(())
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn owned_conversation_requests_a_stream_that_reaches_the_recording_pipeline() -> Test {
    conversation_scenario(false)
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn revoked_listener_policy_prevents_stream_setting_dispatch() -> Test {
    conversation_scenario(true)
}

// Verify the upper guard against actual plaintext buffered in rustls. The
// unguarded control first proves that raw admission alone cannot stop it.
fn buffered_tls_revocation(guard_plaintext: bool) -> Test {
    let cert = std::fs::read(std::env::var("FSS_LAB_CERT_DER")?)?;
    let key = std::fs::read(std::env::var("FSS_LAB_KEY_DER")?)?;
    let provider = Arc::new(rustls_pure::provider());
    let server_config = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        )?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert))?;
    let client_config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 1_000_000;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:buffered-tls".into(),
            operation_id: OperationId::parse("operation:buffered-tls")?,
            principal: "principal:fixture".into(),
            capabilities: vec![RuntimeGrant::AdapterNet.as_str().into()],
            deadline: Some(TimestampNs(60_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:fixture".into(),
            retention_scope: "retention:fixture".into(),
            anchor_universe: ContentDigest::sha256(b"fixture"),
            generation: 1,
        },
        RegionId::new("region:buffered-tls")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:buffered-tls")?,
                started_at: TimestampNs(3),
            },
            &cx,
            async |task, cx| {
                let output: Test = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(4))?;
                    let policy = FixtureMediaAdmission {
                        listen: Cell::new(true),
                        peer: Cell::new(true),
                    };
                    let bind = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
                    let listener = controller_listener::Listener::bind(
                        task,
                        cx,
                        clock,
                        &policy,
                        bind,
                        "fixture:camera",
                        Duration::from_secs(5),
                    )
                    .await?;
                    let address = SocketAddr::V4(listener.local_addr());
                    let (done_tx, done_rx) = std::sync::mpsc::channel();
                    let peer = std::thread::spawn(move || -> io::Result<()> {
                        let raw =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        raw.set_read_timeout(Some(Duration::from_secs(5)))?;
                        raw.set_write_timeout(Some(Duration::from_secs(5)))?;
                        let connection = ClientConnection::new(
                            Arc::new(client_config),
                            ServerName::try_from("localhost").map_err(io::Error::other)?,
                        )
                        .map_err(io::Error::other)?;
                        let mut socket = StreamOwned::new(connection, raw);
                        socket.write_all(b"xy")?;
                        socket.flush()?;
                        done_rx
                            .recv_timeout(Duration::from_secs(5))
                            .map_err(io::Error::other)?;
                        Ok(())
                    });
                    let (raw, gate) = listener.accept(4096, Duration::from_secs(5)).await?;
                    let tls = timeout(
                        cx.now(),
                        Duration::from_secs(5),
                        Server::new(ServerConnection::new(Arc::new(server_config))?, raw)
                            .handshake(cx),
                    )
                    .await??;
                    if guard_plaintext {
                        let mut upper = gate.wrap(tls);
                        let mut byte = [0u8; 1];
                        asupersync::io::AsyncReadExt::read_exact(&mut upper, &mut byte).await?;
                        assert_eq!(byte, *b"x");
                        policy.peer.set(false);
                        assert_eq!(
                            asupersync::io::AsyncReadExt::read(&mut upper, &mut byte)
                                .await
                                .unwrap_err()
                                .kind(),
                            io::ErrorKind::PermissionDenied
                        );
                        policy.peer.set(true);
                        assert_eq!(
                            asupersync::io::AsyncReadExt::read(&mut upper, &mut byte)
                                .await
                                .unwrap_err()
                                .kind(),
                            io::ErrorKind::PermissionDenied
                        );
                        assert_eq!(
                            asupersync::io::AsyncWriteExt::write(&mut upper, b"z")
                                .await
                                .unwrap_err()
                                .kind(),
                            io::ErrorKind::PermissionDenied
                        );
                    } else {
                        let mut upper = tls;
                        let mut byte = [0u8; 1];
                        asupersync::io::AsyncReadExt::read_exact(&mut upper, &mut byte).await?;
                        assert_eq!(byte, *b"x");
                        policy.peer.set(false);
                        asupersync::io::AsyncReadExt::read_exact(&mut upper, &mut byte).await?;
                        assert_eq!(
                            byte, *b"y",
                            "control must prove plaintext was buffered above raw policy"
                        );
                    }
                    done_tx.send(())?;
                    peer.join().map_err(|_| "TLS peer panic")??;
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("buffered TLS fixture failed".into())
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
    Ok(())
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn revocation_stops_buffered_tls_plaintext_and_fences_connection() -> Test {
    buffered_tls_revocation(false)?;
    buffered_tls_revocation(true)
}

/// Process fixture owns and reaps its one child on every return path.
struct TrialChild(Option<std::process::Child>);
impl Drop for TrialChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            if let Ok(output) = child.wait_with_output() {
                eprintln!(
                    "trial fixture child status: {}\n{}\n{}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }
}

/// A bounded synthetic discovery and HTTPS camera owned by one test.
struct SetupFixture {
    discovery: Option<std::thread::JoinHandle<io::Result<()>>>,
    camera: Option<std::thread::JoinHandle<io::Result<()>>>,
    discovery_port: u16,
    https_port: u16,
}
impl Drop for SetupFixture {
    fn drop(&mut self) {
        if let Some(handle) = self.discovery.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.camera.take() {
            let _ = handle.join();
        }
    }
}
impl SetupFixture {
    fn finish(mut self) -> Test {
        self.discovery
            .take()
            .ok_or("missing discovery fixture")?
            .join()
            .map_err(|_| "discovery fixture panicked")??;
        self.camera
            .take()
            .ok_or("missing camera fixture")?
            .join()
            .map_err(|_| "camera fixture panicked")??;
        Ok(())
    }
}

fn setup_process_fixture(
    cert: &[u8],
    key: &[u8],
    controller_port: u16,
    bind: Ipv4Addr,
    chunked: bool,
) -> Result<SetupFixture, Box<dyn Error>> {
    let udp = std::net::UdpSocket::bind((bind, 0))?;
    udp.set_read_timeout(Some(Duration::from_secs(15)))?;
    let discovery_port = udp.local_addr()?.port();
    let camera_listener = std::net::TcpListener::bind((bind, 0))?;
    camera_listener.set_nonblocking(true)?;
    let https_port = camera_listener.local_addr()?.port();
    let server = Arc::new(
        ServerConfig::builder_with_provider(Arc::new(rustls_pure::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
            )?,
    );
    let discovery = std::thread::spawn(move || -> io::Result<()> {
        let mut query = [0u8; 64];
        let (_, source) = udp.recv_from(&mut query)?;
        let mac = [0, 0x11, 0x22, 0xaa, 0xbb, 0xcc];
        let mut address = Vec::from(mac);
        address.extend_from_slice(&bind.octets());
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
        udp.send_to(&packet, source)?;
        Ok(())
    });
    let camera = std::thread::spawn(move || -> io::Result<()> {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let (raw, _) = loop {
            match camera_listener.accept() {
                Ok(peer) => break peer,
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(e) => return Err(e),
            }
        };
        raw.set_nonblocking(false)?;
        raw.set_read_timeout(Some(Duration::from_secs(15)))?;
        raw.set_write_timeout(Some(Duration::from_secs(15)))?;
        let mut tls = StreamOwned::new(
            ServerConnection::new(server).map_err(io::Error::other)?,
            raw,
        );
        let routes = [
            "POST /api/1.1/login ",
            "GET /api/1.1/status ",
            "GET /api/1.1/settings ",
            "GET /api/1.1/settings ",
            "PUT /api/1.1/settings ",
            "GET /api/1.1/settings ",
        ];
        for (index, route) in routes.iter().enumerate() {
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                tls.read_exact(&mut byte)?;
                request.push(byte[0]);
                if request.len() > 8192 {
                    return Err(io::Error::other("header limit"));
                }
            }
            let text = std::str::from_utf8(&request).map_err(io::Error::other)?;
            if !text.starts_with(route) {
                return Err(io::Error::other("camera route mismatch"));
            }
            let is_chunked = text.contains("Transfer-Encoding: chunked\r\n");
            if index == 4 && is_chunked != chunked {
                return Err(io::Error::other("handoff framing mismatch"));
            }
            let n = if is_chunked {
                let mut size = Vec::new();
                while !size.ends_with(b"\r\n") {
                    tls.read_exact(&mut byte)?;
                    size.push(byte[0]);
                    if size.len() > 16 {
                        return Err(io::Error::other("chunk header limit"));
                    }
                }
                usize::from_str_radix(
                    std::str::from_utf8(&size[..size.len() - 2]).map_err(io::Error::other)?,
                    16,
                )
                .map_err(io::Error::other)?
            } else {
                text.lines()
                    .find_map(|s| s.strip_prefix("Content-Length: "))
                    .map_or(Ok(0), str::parse::<usize>)
                    .map_err(io::Error::other)?
            };
            if n > 4096 {
                return Err(io::Error::other("body limit"));
            }
            let mut body = vec![0; n];
            tls.read_exact(&mut body)?;
            if is_chunked {
                let mut end = [0u8; 7];
                tls.read_exact(&mut end)?;
                if &end != b"\r\n0\r\n\r\n" {
                    return Err(io::Error::other("invalid chunk terminator"));
                }
            }
            if index == 4 && body != format!(r#"{{"controller":{{"addr":"{bind}"}}}}"#).as_bytes() {
                return Err(io::Error::other("handoff destination mismatch"));
            }
            let reply = match index {
                1 => format!(r#"{{"controller":{{"port":{controller_port}}}}}"#),
                2 | 3 | 5 => {
                    let prior = if bind == Ipv4Addr::new(192, 168, 1, 10) {
                        "192.168.1.11"
                    } else {
                        "192.168.1.10"
                    };
                    format!(r#"{{"controller":{{"addr":"{prior}"}}}}"#)
                }
                4 => r#"{"success":true}"#.into(),
                _ => "{}".into(),
            };
            let cookie = if index == 0 {
                "Set-Cookie: authId=fixture-cookie\r\n"
            } else {
                ""
            };
            write!(
                tls,
                "HTTP/1.1 200 OK\r\n{cookie}Content-Length: {}\r\nConnection: keep-alive\r\n\r\n{reply}",
                reply.len()
            )?;
            tls.flush()?;
        }
        Ok(())
    });
    Ok(SetupFixture {
        discovery: Some(discovery),
        camera: Some(camera),
        discovery_port,
        https_port,
    })
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_process_produces_a_private_decodable_clip() -> Test {
    direct_trial_process_clip(false, false, false, false, 0, 0, false, false, false, false)
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_process_requests_first_video_channel() -> Test {
    direct_trial_process_clip_for_channel(false, false, false, false, 0, 0, false, false, false, false, Some(1), None, None)
}

#[test]
#[ignore = "requires disposable TLS certificate and key; synthetic full-resolution AVC"]
fn direct_trial_process_decodes_synthetic_g4_resolution() -> Test {
    direct_trial_process_clip_for_channel(false, false, false, false, 0, 0, false, false, false, false, Some(1), Some(include_bytes!("fixtures/synthetic_g4_resolution.264")), Some((2688, 1512)))
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_process_defaults_to_second_video_channel() -> Test {
    direct_trial_process_clip(false, false, false, false, 0, 0, false, false, false, false)
}

#[test]
fn direct_trial_process_refuses_invalid_video_channel_before_io() -> Test {
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_unifi_direct_trial"))
        .args(["127.0.0.1:1", "127.0.0.1", "001122aabbcc", "/absent/cert", "/absent/key",
            "/absent/journal", "/absent/output", "12345678-1234-4abc-9abc-123456789abc",
            "--video-channel=4", "--owner-authorized"])
        .output()?;
    if result.status.success() || !String::from_utf8_lossy(&result.stderr).contains("video channel must be 1, 2, or 3") {
        return Err("invalid channel was not refused before I/O".into());
    }
    Ok(())
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_process_publishes_owned_archive() -> Test {
    direct_trial_process_clip(false, false, false, false, 0, 1, false, false, false, false)
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_process_publishes_two_owned_segments() -> Test {
    direct_trial_process_clip(false, false, false, false, 0, 2, false, false, false, false)
}

#[test]
#[ignore = "requires private test interface and disposable TLS fixtures; synthetic full-resolution AVC"]
fn direct_trial_setup_archives_and_decodes_full_resolution() -> Test {
    if run_private_namespace_if_requested("direct_trial_setup_archives_and_decodes_full_resolution")? { return Ok(()); }
    direct_trial_process_clip_for_channel(false, false, true, false, 0, 2, false, false, false, true,
        Some(1), Some(include_bytes!("fixtures/synthetic_g4_resolution_gop4.264")), Some((2688, 1512)))
}

#[test]
#[ignore = "requires private test interface and disposable TLS fixtures; synthetic all-keyframe AVC"]
fn direct_trial_all_keyframes_archive_video_then_audio() -> Test {
    if run_private_namespace_if_requested("direct_trial_all_keyframes_archive_video_then_audio")? { return Ok(()); }
    direct_trial_process_clip_for_channel(false, false, true, false, 0, 2, false, false, false, true,
        Some(1), Some(include_bytes!("fixtures/synthetic_g4_resolution.264")), Some((2688, 1512)))
}

#[test]
#[ignore = "requires private test interface and disposable TLS fixtures; synthetic all-keyframe AVC"]
fn direct_trial_video_only_cold_readback() -> Test {
    if run_private_namespace_if_requested("direct_trial_video_only_cold_readback")? { return Ok(()); }
    direct_trial_process_clip_for_channel(false, false, true, false, 0, 1, false, false, false, true,
        Some(1), Some(include_bytes!("fixtures/synthetic_g4_resolution.264")), Some((2688, 1512)))
}

fn run_private_namespace_if_requested(test: &str) -> Result<bool, Box<dyn Error>> {
    // Some Linux workers SNAT local connections to private bridge addresses.
    // The optional isolated namespace supplies a private, source-preserving
    // fixture address without changing the worker's host network.
    if std::env::var_os("FSS_TEST_PRIVATE_NETNS").as_deref() == Some(std::ffi::OsStr::new("1")) {
        let status = std::process::Command::new("unshare")
            .args(["--net", "--", "sh", "-c",
                "ip link set lo up && ip addr add 10.253.47.1/32 dev lo && exec \"$@\"", "sh"])
            .arg(std::env::current_exe()?)
            .args([test, "--ignored", "--exact", "--nocapture", "--test-threads=1"])
            .env_remove("FSS_TEST_PRIVATE_NETNS")
            .env("FSS_TEST_CONTROLLER_BIND_IP", "10.253.47.1")
            .status()?;
        return if status.success() { Ok(true) } else { Err("isolated fixture failed".into()) };
    }
    Ok(false)
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_process_publishes_owned_archive_with_retained_anchors() -> Test {
    direct_trial_process_clip(false, false, false, false, 0, 2, false, false, false, true)
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_process_owned_event_replies() -> Test {
    direct_trial_process_clip(false, true, false, false, 0, 1, false, true, false, false)
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_process_owned_event_refuses_without_permission() -> Test {
    direct_trial_process_clip(false, false, false, false, 0, 1, false, true, true, false)
}

#[test]
#[ignore = "requires bounded private camera-derived input on stdin and disposable TLS fixtures"]
fn direct_trial_process_replays_camera_derived_media() -> Test {
    direct_trial_process_clip(false, false, false, false, 0, 2, true, false, false, false)
}

#[test]
#[ignore = "requires bounded private camera-derived input on stdin and disposable TLS fixtures"]
fn direct_trial_process_replays_camera_with_control_effects() -> Test {
    direct_trial_process_clip(false, true, false, false, 0, 2, true, true, false, false)
}

#[test]
#[ignore = "requires bounded private camera-derived input on stdin and disposable TLS fixtures"]
fn direct_trial_process_replays_camera_with_retained_anchors() -> Test {
    direct_trial_process_clip(false, false, false, false, 0, 2, true, false, false, true)
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_process_handles_time_sync_before_hello_and_produces_clip() -> Test {
    direct_trial_process_clip(true, false, false, false, 0, 0, false, false, false, false)
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_process_receives_media_without_settings_reply() -> Test {
    direct_trial_process_clip(true, true, false, false, 0, 0, false, false, false, false)
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_process_discovers_sets_up_and_records_fixture() -> Test {
    direct_trial_process_clip(false, false, true, false, 0, 0, false, false, false, false)
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_process_discovers_chunked_setup_and_records_fixture() -> Test {
    direct_trial_process_clip(false, false, true, true, 0, 0, false, false, false, false)
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "requires disposable TLS certificate, key and private fixture interface"]
fn direct_trial_process_waits_for_delayed_camera_after_setup() -> Test {
    direct_trial_process_clip(false, false, true, false, 12, 0, false, false, false, false)
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "requires disposable TLS certificate, key and private fixture interface"]
fn direct_trial_setup_timeout_preserves_handoff_trace_and_indeterminate_receipt() -> Test {
    use std::{
        os::unix::fs::{DirBuilderExt, OpenOptionsExt},
        process::{Command, Stdio},
        time::Instant,
    };
    let root =
        std::env::temp_dir().join(format!("fss-direct-setup-timeout-{}", std::process::id()));
    std::fs::DirBuilder::new().mode(0o700).create(&root)?;
    let temp = Temp(root);
    let bind: Ipv4Addr = std::env::var("FSS_TEST_CONTROLLER_BIND_IP")?.parse()?;
    if !(bind.is_private() || bind.is_link_local()) {
        return Err("private fixture interface required".into());
    }
    require_fixture_source_preserved(bind)?;
    let reserve = std::net::TcpListener::bind((bind, 0))?;
    let port = reserve.local_addr()?.port();
    drop(reserve);
    let cert = PathBuf::from(std::env::var("FSS_LAB_CERT_DER")?);
    let key = PathBuf::from(std::env::var("FSS_LAB_KEY_DER")?);
    let fixture = setup_process_fixture(
        &std::fs::read(&cert)?,
        &std::fs::read(&key)?,
        port,
        bind,
        false,
    )?;
    let credential = temp.0.join("fixture-credential.json");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&credential)?;
    file.write_all(br#"{"username":"fixture","password":"synthetic"}"#)?;
    drop(file);
    let journal = temp.0.join("journal");
    let clip = temp.0.join("clip.mp4");
    let child = Command::new(env!("CARGO_BIN_EXE_unifi_direct_trial"))
        .arg(format!("{bind}:{port}"))
        .arg(bind.to_string())
        .arg("001122aabbcc")
        .arg(&cert)
        .arg(&key)
        .arg(&journal)
        .arg(&clip)
        .arg("12345678-1234-4abc-9abc-123456789abc")
        .arg("3")
        .arg(format!(
            "--setup-camera={},{},{},{}",
            fixture.discovery_port,
            fixture.https_port,
            cert.display(),
            credential.display()
        ))
        .arg("--owner-authorized")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut child = TrialChild(Some(child));
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if child
            .0
            .as_mut()
            .ok_or("missing child")?
            .try_wait()?
            .is_some()
        {
            break;
        }
        if Instant::now() > deadline {
            return Err("setup timeout fixture did not terminate".into());
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    let output = child.0.take().ok_or("missing child")?.wait_with_output()?;
    fixture.finish()?;
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    if output.status.success()
        || !stdout.contains("trial_stage=setup_trace outcome=previous dispatch_started=true accept_started=true claims_unverified=true")
        || !stdout.contains("trial_task_outcome=effect_unsettled")
        || !stderr.contains("Deadline")
        || !journal.is_dir()
        || clip.exists()
    {
        return Err(format!("setup timeout lost evidence: stdout={stdout} stderr={stderr}").into());
    }
    Ok(())
}

fn direct_trial_process_clip(
    sync_before_hello: bool,
    media_before_reply: bool,
    with_setup: bool,
    setup_chunked: bool,
    connection_delay_secs: u64,
    owned_segments: usize,
    camera_derived: bool,
    request_event: bool,
    reject_event: bool,
    retained_anchors: bool,
) -> Test {
    direct_trial_process_clip_for_channel(sync_before_hello, media_before_reply, with_setup, setup_chunked,
        connection_delay_secs, owned_segments, camera_derived, request_event, reject_event, retained_anchors, None, None, None)
}

fn direct_trial_process_clip_for_channel(
    sync_before_hello: bool,
    media_before_reply: bool,
    with_setup: bool,
    setup_chunked: bool,
    connection_delay_secs: u64,
    owned_segments: usize,
    camera_derived: bool,
    request_event: bool,
    reject_event: bool,
    retained_anchors: bool,
    video_channel: Option<u8>,
    synthetic_avc: Option<&[u8]>,
    expected_dimensions: Option<(usize, usize)>,
) -> Test {
    use std::{
        os::unix::fs::{DirBuilderExt, PermissionsExt},
        process::{Command, Stdio},
        time::Instant,
    };
    let owned_archive=owned_segments>0;
    let decode_owned=(owned_archive && expected_dimensions.is_some()) || std::env::var_os("FSS_TEST_DECODE_OWNED").as_deref() == Some(std::ffi::OsStr::new("1"));
    if decode_owned && !owned_archive { return Err("owned decode requires archive fixture".into()); }
    let supplied_wire=if camera_derived {
        let mut wire=Vec::new();
        std::io::stdin().lock().take((8*1024*1024+1) as u64).read_to_end(&mut wire)?;
        if wire.len()<13 || wire.len()>8*1024*1024 || !wire.starts_with(b"FLV\x01") {return Err("bounded replay input refused".into());}
        Some(wire)
    } else {None};
    let cert_path = PathBuf::from(std::env::var("FSS_LAB_CERT_DER")?);
    let key_path = PathBuf::from(std::env::var("FSS_LAB_KEY_DER")?);
    let root = std::env::temp_dir().join(format!(
        "fss-direct-trial-process-{}-{sync_before_hello}-{media_before_reply}-{with_setup}-{setup_chunked}-{connection_delay_secs}",
        std::process::id()
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&root)?;
    let temp = Temp(root);
    let bind = if with_setup {
        let addr: Ipv4Addr = std::env::var("FSS_TEST_CONTROLLER_BIND_IP")?.parse()?;
        if !(addr.is_private() || addr.is_link_local()) {
            return Err("private fixture interface required".into());
        }
        require_fixture_source_preserved(addr)?;
        addr
    } else {
        Ipv4Addr::LOCALHOST
    };
    let reserve = std::net::TcpListener::bind((bind, 0))?;
    let port = reserve.local_addr()?.port();
    drop(reserve);
    let journal = temp.0.join("journal");
    let clip = temp.0.join("clip.mp4");
    let anchor_root=temp.0.join("archive-roots");
    let setup_fixture = if with_setup {
        Some(setup_process_fixture(
            &std::fs::read(&cert_path)?,
            &std::fs::read(&key_path)?,
            port,
            bind,
            setup_chunked,
        )?)
    } else {
        None
    };
    let trial_binary = std::env::var_os("FSS_TEST_TRIAL_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_unifi_direct_trial")));
    if !trial_binary.is_absolute() { return Err("trial executable path must be absolute".into()); }
    let mut command = Command::new(trial_binary);
    command
        .arg(format!("{bind}:{port}"))
        .arg(bind.to_string())
        .arg("001122aabbcc")
        .arg(&cert_path)
        .arg(&key_path)
        .arg(&journal)
        .arg(&clip)
        .arg("12345678-1234-4abc-9abc-123456789abc");
    if let Some(channel) = video_channel { command.arg(format!("--video-channel={channel}")); }
    if media_before_reply {
        command.arg("--media-before-reply");
    }
    if request_event && !reject_event {command.arg("--reply-events");}
    if owned_archive {
        if camera_derived && std::env::var_os("FSS_TEST_INBAND_AAC").as_deref() == Some(std::ffi::OsStr::new("1")) {
            command.arg("--lab-aac-source");
        } else {
            command.arg("--lab-aac-config=1408");
        }
        if camera_derived {command.arg("--lab-zero-stream-id");}
        command.arg(format!("--lab-segments={owned_segments}")).arg("--lab-owned-archive");
        if decode_owned {command.arg("--lab-decode-owned");}
        if retained_anchors {command.arg(format!("--lab-anchor-root={}",anchor_root.display()));}
    }
    if request_event && !reject_event {
        command.arg(format!("--anchored-journal={},{}",temp.0.join("effect-keeper").display(),temp.0.join("effect-root").display()));
    }
    if let Some(fixture) = &setup_fixture {
        use std::os::unix::fs::OpenOptionsExt;
        let credential = temp.0.join("fixture-credential.json");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&credential)?;
        file.write_all(br#"{"username":"fixture","password":"synthetic"}"#)?;
        command.arg(format!(
            "--setup-camera={},{},{},{}{}",
            fixture.discovery_port,
            fixture.https_port,
            cert_path.display(),
            credential.display(),
            if setup_chunked { ",chunked" } else { "" }
        ));
    }
    let child = command
        .arg("--owner-authorized")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut child = TrialChild(Some(child));
    let (event_ready_tx,event_ready_rx)=std::sync::mpsc::channel();
    let stdout_reader=if request_event {
        let stdout=child.0.as_mut().ok_or("missing child")?.stdout.take().ok_or("missing child stdout")?;
        Some(std::thread::spawn(move || -> io::Result<String> {
            use std::io::BufRead;
            let mut reader=io::BufReader::new(stdout);let mut report=String::new();
            loop {let mut line=String::new();if reader.read_line(&mut line)?==0 {break;}
                if line.starts_with("trial_mode=owned_archive") {let _=event_ready_tx.send(());}
                report.push_str(&line);
            }
            Ok(report)
        }))
    } else {None};
    if connection_delay_secs > 0 {
        let fixture = setup_fixture
            .as_ref()
            .ok_or("missing delayed setup fixture")?;
        let deadline = Instant::now() + Duration::from_secs(15);
        while !fixture
            .camera
            .as_ref()
            .ok_or("missing camera fixture")?
            .is_finished()
        {
            if Instant::now() > deadline {
                return Err("setup fixture did not finish".into());
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        std::thread::sleep(Duration::from_secs(connection_delay_secs));
    }
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(std::fs::read(cert_path)?))?;
    let client_config = Arc::new(
        ClientConfig::builder_with_provider(Arc::new(rustls_pure::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let address = SocketAddr::from((bind, port));
    let deadline = Instant::now() + Duration::from_secs(15);
    {
        let initial = loop {
            match connect_fixture_from(bind, address, Duration::from_millis(300)) {
                Ok(socket) => break socket,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(30))
                }
                Err(error) => return Err(error.into()),
            }
        };
        drop(initial);
        // A camera can upgrade and then disconnect before sending hello. No
        // management effect has been prepared, so one bounded reconnect is safe.
        let early_raw = connect_fixture_from(bind, address, Duration::from_secs(5))?;
        early_raw.set_read_timeout(Some(Duration::from_secs(10)))?;
        early_raw.set_write_timeout(Some(Duration::from_secs(10)))?;
        let early_connection =
            ClientConnection::new(client_config.clone(), ServerName::try_from("localhost")?)?;
        let mut early = StreamOwned::new(early_connection, early_raw);
        early.write_all(HEAD.as_bytes())?;
        early.flush()?;
        let mut early_header = Vec::new();
        let mut early_byte = [0u8; 1];
        while !early_header.ends_with(b"\r\n\r\n") {
            early.read_exact(&mut early_byte)?;
            early_header.push(early_byte[0]);
            if early_header.len() > 4096 {
                return Err("early upgrade limit".into());
            }
        }
        if !early_header.starts_with(b"HTTP/1.1 101 ") {
            return Err("early upgrade refused".into());
        }
        drop(early);
    }
    let raw = loop {
        match connect_fixture_from(bind, address, Duration::from_millis(300)) {
            Ok(socket) => break socket,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(30)),
            Err(error) => return Err(error.into()),
        }
    };
    raw.set_read_timeout(Some(Duration::from_secs(10)))?;
    raw.set_write_timeout(Some(Duration::from_secs(10)))?;
    let connection = ClientConnection::new(client_config, ServerName::try_from("localhost")?)?;
    let mut socket = StreamOwned::new(connection, raw);
    let mut request = HEAD.as_bytes().to_vec();
    if sync_before_hello {
        request.extend(frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":10}"#));
    } else {
        request.extend(frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":10,"inResponseTo":99}"#));
    }
    request.extend(frame(HELLO));
    socket.write_all(&request)?;
    socket.flush()?;
    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    while !header.ends_with(b"\r\n\r\n") {
        socket.read_exact(&mut byte)?;
        header.push(byte[0]);
        if header.len() > 4096 {
            return Err("upgrade limit".into());
        }
    }
    if !header.starts_with(b"HTTP/1.1 101 ") {
        return Err("upgrade refused".into());
    }
    if sync_before_hello {
        let early_sync = receive_binary(&mut socket)?;
        let json = fss_core::json_input::parse(std::str::from_utf8(&early_sync)?)?;
        let fields = json.object().ok_or("invalid early time sync response")?;
        if fields.get("functionName").and_then(|v| v.text()) != Some("ubnt_avclient_timeSync")
            || fields.get("inResponseTo").and_then(|v| v.integer()) != Some(10)
        {
            return Err("early time sync response did not correlate".into());
        }
    }
    if !receive_binary(&mut socket)
        .map_err(|e| format!("hello reply: {e}"))?
        .windows(b"ubnt_avclient_hello".len())
        .any(|w| w == b"ubnt_avclient_hello")
    {
        return Err("missing hello".into());
    }
    socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":11}"#))?;
    socket.flush()?;
    let sync_reply = receive_binary(&mut socket).map_err(|e| format!("time-sync reply: {e}"))?;
    let sync_json = fss_core::json_input::parse(std::str::from_utf8(&sync_reply)?)?;
    let sync_fields = sync_json.object().ok_or("invalid time sync response")?;
    if sync_fields.get("functionName").and_then(|v| v.text()) != Some("ubnt_avclient_timeSync")
        || sync_fields.get("inResponseTo").and_then(|v| v.integer()) != Some(11)
    {
        return Err("time sync response did not correlate to the camera request".into());
    }
    let agreement = receive_binary(&mut socket).map_err(|e| format!("agreement request: {e}"))?;
    if !agreement
        .windows(b"ubnt_avclient_paramAgreement".len())
        .any(|w| w == b"ubnt_avclient_paramAgreement")
    {
        return Err("missing agreement".into());
    }
    let agreement_json = fss_core::json_input::parse(std::str::from_utf8(&agreement)?)?;
    let agreement_id = agreement_json
        .object()
        .and_then(|v| v.get("messageId"))
        .and_then(|v| v.integer())
        .ok_or("missing agreement ID")?;
    let agreement_reply = format!(
        r#"{{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_paramAgreement","messageId":8,"inResponseTo":{agreement_id}}}"#
    );
    socket.write_all(&frame(agreement_reply.as_bytes()))?;
    socket.flush()?;
    let setting = receive_binary(&mut socket)?;
    if !setting
        .windows(b"ChangeVideoSettings".len())
        .any(|w| w == b"ChangeVideoSettings")
    {
        return Err("missing stream setting".into());
    }
    let text = std::str::from_utf8(&setting)?;
    let destination = text
        .split_once("tcp://")
        .and_then(|(_, s)| s.split_once('?'))
        .map(|(address, _)| address)
        .ok_or("missing stream address")?;
    let destination: SocketAddr = destination.parse()?;
    if destination.ip() != std::net::IpAddr::V4(bind) {
        return Err("stream destination escaped fixture interface".into());
    }
    let setting_json = fss_core::json_input::parse(std::str::from_utf8(&setting)?)?;
    let video = setting_json.object().and_then(|v| v.get("payload"))
        .and_then(|v| v.object()).and_then(|v| v.get("video"))
        .and_then(|v| v.object()).ok_or("missing video settings")?;
    let expected_channel = format!("video{}", video_channel.unwrap_or(2));
    if video.len() != 1 || !video.contains_key(expected_channel.as_str()) {
        return Err("stream request selected the wrong video channel".into());
    }
    let setting_id = setting_json
        .object()
        .and_then(|v| v.get("messageId"))
        .and_then(|v| v.integer())
        .ok_or("missing setting ID")?;
    let setting_reply = format!(
        r#"{{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ChangeVideoSettings","messageId":9,"inResponseTo":{setting_id}}}"#
    );
    if !media_before_reply {
        socket.write_all(&frame(setting_reply.as_bytes()))?;
        socket.flush()?;
    }
    let mut media = connect_fixture_from(bind, destination, Duration::from_secs(5))?;
    if request_event {
        event_ready_rx.recv_timeout(Duration::from_secs(10)).map_err(|_|"owned session did not start")?;
        if !reject_event {
            let clock=br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":19,"responseExpected":true}"#;
            socket.write_all(&frame(clock))?;socket.flush()?;
            let reply=receive_binary(&mut socket)?;
            let parsed=fss_core::json_input::parse(std::str::from_utf8(&reply)?)?;
            let fields=parsed.object().ok_or("clock response object")?;
            if fields.get("functionName").and_then(|v|v.text())!=Some("ubnt_avclient_timeSync") || fields.get("inResponseTo").and_then(|v|v.integer())!=Some(19) {return Err("incorrect owned clock reply".into());}
        }
        let event=br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventExample","messageId":20,"responseExpected":true,"payload":{"private":"fixture"}}"#;
        socket.write_all(&frame(event))?;socket.flush()?;
        let response=receive_binary(&mut socket);
        if reject_event {
            if response.is_ok() {return Err("disabled event reply was sent".into());}
            let output=child.0.take().ok_or("missing child")?.wait_with_output()?;
            let report=stdout_reader.ok_or("missing event stdout reader")?.join().map_err(|_|"stdout reader panicked")??;
            if output.status.success() || !String::from_utf8(output.stderr)?.contains("event reply required") || report.contains("trial_owned_event_reply=written") {return Err("disabled event reply did not stop cleanly".into());}
            return Ok(());
        }
        let response=response?;
        let parsed=fss_core::json_input::parse(std::str::from_utf8(&response)?)?;
        let fields=parsed.object().ok_or("event response object")?;
        if fields.get("functionName").and_then(|v|v.text())!=Some("EventExample") || fields.get("inResponseTo").and_then(|v|v.integer())!=Some(20) {return Err("incorrect event reply".into());}
    }
    let mut wire=match supplied_wire {Some(wire)=>wire,None=>match synthetic_avc {Some(avc) if owned_archive=>media_fixture_from_frames(avc,4,11)?,Some(avc)=>media_fixture_from(avc,4)?,None=>media_fixture()?}};
    if owned_archive && !camera_derived {
        wire[4]=5;
        let mut offset=13usize;
        let mut index=0u32;
        while offset<wire.len() {
            let size=(usize::from(wire[offset+1])<<16)|(usize::from(wire[offset+2])<<8)|usize::from(wire[offset+3]);
            if wire[offset]==9 && wire[offset+12]==1 {
                let mut audio=flv_tag(index*64,&[0xaf,1,2]); audio[0]=8;
                let len=audio.len(); wire.splice(offset..offset,audio); offset+=len; index+=1;
            }
            offset+=11+size+4;
        }
    }
    media.set_write_timeout(Some(Duration::from_secs(15)))?;
    let writer=std::thread::spawn(move || media.write_all(&wire));
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if child
            .0
            .as_mut()
            .ok_or("missing child")?
            .try_wait()?
            .is_some()
        {
            break;
        }
        if Instant::now() > deadline {
            return Err("trial did not terminate".into());
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    let output = child.0.take().ok_or("missing child")?.wait_with_output()?;
    match writer.join().map_err(|_|"fixture media writer panicked")? {
        Ok(())=>(),
        Err(error) if output.status.success() && matches!(error.kind(),io::ErrorKind::BrokenPipe|io::ErrorKind::ConnectionReset)=>(),
        Err(error)=>return Err(error.into()),
    }
    let report = if let Some(reader)=stdout_reader {reader.join().map_err(|_|"stdout reader panicked")??} else {String::from_utf8(output.stdout)?};
    if !output.status.success() {
        // Report only fixed stage labels; never print input media or event payloads.
        let stages = report.lines().filter_map(|line| line.split_whitespace().next())
            .filter(|word| word.starts_with("trial_stage=") || word.starts_with("trial_owned_event_reply="))
            .take(128).collect::<Vec<_>>().join(",");
        return Err(format!("trial failed: {} stages={stages}", String::from_utf8_lossy(&output.stderr)).into());
    }
    let expected_startup_clocks = if sync_before_hello { 2 } else { 1 };
    if !report.contains(&format!("trial_stage=startup_protocol_trace clocks={expected_startup_clocks} effects_require_reconciliation=true")) {
        return Err("startup protocol trace was not retained".into());
    }
    if !report.contains("trial_complete")
        || !report.contains("trial_task_outcome=effect_unsettled")
        || !report.contains("trial_stage=tcp_accepted")
        || (!with_setup && !report.contains("trial_stage=handshake_eof_retry"))
        || !report.contains("trial_stage=pre_effect_websocket_eof_retry")
        || !report.contains("trial_stage=tls_handshake_completed")
        || (with_setup && (!report.contains("trial_stage=setup_websocket_accepted")
            || !report.contains("trial_stage=setup_trace outcome=previous dispatch_started=true accept_started=true claims_unverified=true")))
        || !report.contains("trial_stage=websocket_accepted")
        || (!owned_archive && !report.contains("effects=reconciliation_required"))
        || !report.contains("continuous_recording=false")
    {
        return Err(format!("incomplete report: {report}").into());
    }
    if owned_archive {
        if synthetic_avc.is_some_and(|bytes| bytes == include_bytes!("fixtures/synthetic_g4_resolution.264"))
            && !report.contains("trial_stage=owned_segment_published count=1 kind=VideoOnly")
        { return Err("initial video-only segment not reported".into()); }
        if request_event && !report.contains("trial_owned_event_reply=written effects_require_reconciliation=true") {return Err("owned event reply was not journaled".into());}
        if request_event && !reject_event {
            let run_id=report.lines().find_map(|line|line.strip_prefix("trial_run_id=")).ok_or("missing trial run identity")?;
            let (store,minimum)=trial_checkpoint::reopen(&journal,&temp.0.join("effect-keeper"),&temp.0.join("effect-root"),"12345678-1234-4abc-9abc-123456789abc",[0,0x11,0x22,0xaa,0xbb,0xcc])?;
            let recovered=EffectCoordinator::recover(store,minimum)?;
            if !recovered.is_reconciliation_only() {return Err("effect recovery admitted dispatch".into());}
            let step_prefix=format!("operation:unifi-trial-{run_id}-owned-step-");
            let event_prefix=format!("operation:unifi-trial-{run_id}-owned-event-");
            let mut saw_step=false; let mut saw_event=false;
            for receipt in recovered.journal().operations() {
                let operation=receipt.intent.operation_id.as_str();
                saw_step|=operation.starts_with(&step_prefix);
                saw_event|=operation.starts_with(&event_prefix);
                if !operation.starts_with(&format!("operation:unifi-trial-{run_id}-")) {return Err("effect belongs to a different run".into());}
            }
            if !saw_step || !saw_event {return Err("owned clock or event effect absent from run-scoped journal".into());}
        }
        if !report.contains(&format!("trial_complete archive=published segments={owned_segments}")) || !clip.join("source").is_dir() || !clip.join("av").is_dir() || !clip.join("av-intent").is_dir() || !journal.is_dir() {
            return Err(format!("owned archive incomplete: {report}").into());
        }
        let readback=report.lines().find(|line|line.starts_with("trial_owned_readback ")).ok_or("missing source-checked archive readback")?;
        let count=|name:&str| -> Result<usize,Box<dyn Error>> {Ok(readback.split_whitespace().find_map(|word|word.strip_prefix(name)).ok_or("missing readback count")?.parse()?)};
        let only_video = owned_segments == 1 && synthetic_avc.is_some_and(|bytes| bytes == &include_bytes!("fixtures/synthetic_g4_resolution.264")[..]);
        if only_video && !report.contains("trial_stage=owned_segment_published count=1 kind=VideoOnly") {return Err("expected video-only first segment".into());}
        if count("segments=")?!=owned_segments || count("video_samples=")?==0 || (count("audio_frames=")?==0 && !only_video) {return Err("archive readback counts invalid".into());}
        if decode_owned {
            if owned_segments > 1 && !report.contains(&format!("trial_owned_sequence segments={owned_segments} capture_bounds=unknown")) {return Err("verified archive sequence missing".into());}
            let decoded=report.lines().find(|line|line.starts_with("trial_owned_decoded ")).ok_or("owned video decode missing")?;
            let value=|name:&str| -> Result<usize,Box<dyn Error>> {Ok(decoded.split_whitespace().find_map(|word|word.strip_prefix(name)).ok_or("missing decoded field")?.parse()?)};
            let (width,height,frames)=(value("width=")?,value("height=")?,value("frames=")?);
            if width==0 || height==0 || frames==0 {return Err("owned video decode empty".into());}
            if owned_segments>1 && synthetic_avc.is_some_and(|bytes| bytes == &include_bytes!("fixtures/synthetic_g4_resolution.264")[..]) && frames<2 {return Err("mixed sequence did not decode across fragment boundary".into());}
            if expected_dimensions.is_some_and(|expected| expected != (width, height)) {
                return Err("archived video dimensions did not match synthetic input".into());
            }
            println!("owned_archive_decoded width={width} height={height} frames={frames} capture_bounds=unknown");
        }
        if std::fs::metadata(&clip)?.permissions().mode() & 0o077 != 0 {return Err("archive root is not private".into());}
        if retained_anchors {
            use fss_runtime::effect_journal::EffectPinRetainer;
            if !report.contains("trial_owned_anchors=retained root_trust=operator_selected independence=unverified") {return Err("anchor custody report missing".into());}
            if std::fs::metadata(&anchor_root)?.permissions().mode() & 0o077 != 0 {return Err("anchor root is not private".into());}
            for name in ["source-journal","source-keeper","av-journal","av-keeper"] {
                let mut encoder=fss_core::CanonicalEncoder::new();
                encoder.text("fss.unifi-owned-trial.root.v1");encoder.text(name);encoder.digest(ContentDigest::sha256(&[0,0x11,0x22,0xaa,0xbb,0xcc]));
                let scope=ContentDigest::sha256(&encoder.finish_checked()?);
                let mut root=fss_object::effect_journal::FileTrustedRootPinRetainer::open_trusting_storage(anchor_root.join(name),EffectJournalLimits::default(),Arc::new(HostSpoolIo),scope)?;
                if root.retained_pin()?.is_none() {return Err("archive anchor missing".into());}
            }
            let inspect=Command::new(env!("CARGO_BIN_EXE_unifi_direct_trial"))
                .arg("--inspect-owned-archive").arg(&clip).arg(&anchor_root).arg("001122aabbcc").arg("--owner-authorized").output()?;
            let inspection=String::from_utf8(inspect.stdout)?;
            if !inspect.status.success() || !inspection.contains("trial_owned_recovery=inspection_only")
                || !inspection.contains("source_confirmed=true source_pending=false source_replay_required=true source_keeper_caught_up=true")
                || !inspection.contains("av_confirmed=true av_pending=false av_replay_required=true av_keeper_caught_up=true") {
                return Err(format!("archive history inspection failed: {inspection} {}",String::from_utf8_lossy(&inspect.stderr)).into());
            }
            let verify=Command::new(env!("CARGO_BIN_EXE_unifi_direct_trial"))
                .arg("--verify-owned-archive").arg(&clip).arg(&anchor_root).arg("001122aabbcc").arg("--owner-authorized").output()?;
            let verified=String::from_utf8(verify.stdout)?;
            let readback=verified.lines().find(|line|line.starts_with("trial_owned_readback_after_exit=verified ")).ok_or_else(||format!("cold readback missing: {verified} {}",String::from_utf8_lossy(&verify.stderr)))?;
            let count=|name:&str| -> Result<usize,Box<dyn Error>> {Ok(readback.split_whitespace().find_map(|word|word.strip_prefix(name)).ok_or("missing cold readback count")?.parse()?)};
            let audio_valid = if only_video { readback.contains("audio_frames=unknown") } else { count("audio_frames=")? > 0 };
            if !verify.status.success() || count("source_bytes=")?==0 || count("source_connection=")?<=1 || count("source_generation=")?!=1 || count("video_samples=")?==0 || !audio_valid || !readback.contains("replay_still_required=true") {return Err("cold readback counts or connection claim invalid".into());}
            let missing=clip.join("av-test-missing");
            std::fs::rename(clip.join("av"),&missing)?;
            let refused=Command::new(env!("CARGO_BIN_EXE_unifi_direct_trial"))
                .arg("--verify-owned-archive").arg(&clip).arg(&anchor_root).arg("001122aabbcc").arg("--owner-authorized").output();
            std::fs::rename(&missing,clip.join("av"))?;
            let refused=refused?;
            if refused.status.success() || String::from_utf8_lossy(&refused.stdout).contains("trial_owned_readback_after_exit=verified") {return Err("missing A/V deployment accepted".into());}
            let wrong=Command::new(env!("CARGO_BIN_EXE_unifi_direct_trial"))
                .arg("--inspect-owned-archive").arg(&clip).arg(&anchor_root).arg("001122aabbcd").arg("--owner-authorized").output()?;
            if wrong.status.success() || String::from_utf8_lossy(&wrong.stdout).contains("trial_owned_recovery=inspection_only") {return Err("wrong camera scope accepted".into());}
            let unauthorized=Command::new(env!("CARGO_BIN_EXE_unifi_direct_trial"))
                .arg("--inspect-owned-archive").arg(&clip).arg(&anchor_root).arg("001122aabbcc").output()?;
            if unauthorized.status.success() {return Err("unauthorized inspection accepted".into());}
        }
        if camera_derived {println!("owned_executable_camera_replay=passed segments={owned_segments} controller=simulated capture_bounds=unknown");}
        if let Some(fixture) = setup_fixture { fixture.finish()?; }
        return Ok(());
    }
    let bytes = std::fs::read(&clip)?;
    let movie = AvcMp4::parse(&bytes, None, DemuxLimits::default())?;
    if movie.samples().is_empty() {
        return Err("empty clip".into());
    }
    let field = |name: &str| -> Result<usize, Box<dyn Error>> {
        let prefix = format!("{name}=");
        Ok(report
            .split_whitespace()
            .find_map(|word| word.strip_prefix(&prefix))
            .ok_or("missing report field")?
            .parse()?)
    };
    if field("clip_bytes")? != bytes.len()
        || field("decoded_frames")? == 0
        || field("width")? == 0
        || field("height")? == 0
        || field("source_bytes_omitted")? == 0
    {
        return Err("clip verification report does not match artifacts".into());
    }
    if let Some((width,height))=expected_dimensions {
        if field("width")? != width || field("height")? != height {
            return Err("decoded dimensions did not match synthetic input".into());
        }
    }
    if std::fs::metadata(&clip)?.permissions().mode() & 0o077 != 0 {
        return Err("clip permissions are not private".into());
    }
    if !journal.is_dir() {
        return Err("missing effect journal".into());
    }
    if let Some(fixture) = setup_fixture {
        fixture.finish()?;
    }
    Ok(())
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_no_camera_reports_deadline_without_claiming_an_effect() -> Test {
    use std::{
        os::unix::fs::DirBuilderExt,
        process::{Command, Stdio},
        time::Instant,
    };
    let root =
        std::env::temp_dir().join(format!("fss-direct-trial-timeout-{}", std::process::id()));
    std::fs::DirBuilder::new().mode(0o700).create(&root)?;
    let temp = Temp(root);
    let reserve = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = reserve.local_addr()?.port();
    drop(reserve);
    let journal = temp.0.join("journal");
    let clip = temp.0.join("clip.mp4");
    let child = Command::new(env!("CARGO_BIN_EXE_unifi_direct_trial"))
        .arg(format!("127.0.0.1:{port}"))
        .args(["127.0.0.1", "001122aabbcc"])
        .arg(std::env::var("FSS_LAB_CERT_DER")?)
        .arg(std::env::var("FSS_LAB_KEY_DER")?)
        .arg(&journal)
        .arg(&clip)
        .args([
            "12345678-1234-4abc-9abc-123456789abc",
            "1",
            "--owner-authorized",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut child = TrialChild(Some(child));
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if child
            .0
            .as_mut()
            .ok_or("missing child")?
            .try_wait()?
            .is_some()
        {
            break;
        }
        if Instant::now() > deadline {
            return Err("timeout trial did not terminate".into());
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    let output = child.0.take().ok_or("missing child")?.wait_with_output()?;
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    if output.status.success()
        || !stdout.contains("controller_listener_ready")
        || !stdout.contains("trial_task_outcome=failed_before_approval")
        || !stderr.contains("Deadline")
        || stderr.contains("completion is inconsistent")
    {
        return Err(format!("incorrect timeout result: stdout={stdout} stderr={stderr}").into());
    }
    if !journal.is_dir() || clip.exists() {
        return Err("incorrect timeout artifacts".into());
    }
    Ok(())
}

#[test]
fn direct_trial_rejects_overlapping_anchored_custody_before_creating_files() -> Test {
    use std::{os::unix::fs::DirBuilderExt, process::Command};
    let root =
        std::env::temp_dir().join(format!("fss-direct-overlap-custody-{}", std::process::id()));
    std::fs::DirBuilder::new().mode(0o700).create(&root)?;
    let temp = Temp(root);
    let journal = temp.0.join("journal");
    let keeper = journal.join("keeper");
    let anchor = temp.0.join("anchor");
    let output = Command::new(env!("CARGO_BIN_EXE_unifi_direct_trial"))
        .args(["127.0.0.1:12345", "127.0.0.1", "001122aabbcc"])
        .arg(temp.0.join("unused-cert"))
        .arg(temp.0.join("unused-key"))
        .arg(&journal)
        .arg(temp.0.join("clip.mp4"))
        .arg("12345678-1234-4abc-9abc-123456789abc")
        .arg(format!(
            "--anchored-journal={},{}",
            keeper.display(),
            anchor.display()
        ))
        .arg("--owner-authorized")
        .output()?;
    assert!(!output.status.success());
    assert!(!journal.exists());
    assert!(!anchor.exists());
    assert!(String::from_utf8(output.stderr)?.contains("anchored journal and output paths"));
    Ok(())
}

#[test]
fn direct_trial_recovery_inspection_requires_owner_authorization() -> Test {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_unifi_direct_trial"))
        .args([
            "--inspect-anchored",
            "/nonexistent/journal",
            "/nonexistent/keeper",
            "/nonexistent/root",
            "12345678-1234-4abc-9abc-123456789abc",
            "001122aabbcc",
        ])
        .output()?;
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)?.contains("usage: unifi_direct_trial --inspect-anchored")
    );
    Ok(())
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_initializes_anchored_custody_before_listening() -> Test {
    use std::{
        os::unix::fs::DirBuilderExt,
        process::{Command, Stdio},
        time::Instant,
    };
    let root =
        std::env::temp_dir().join(format!("fss-direct-rooted-custody-{}", std::process::id()));
    std::fs::DirBuilder::new().mode(0o700).create(&root)?;
    let temp = Temp(root);
    let reserve = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = reserve.local_addr()?.port();
    drop(reserve);
    let journal = temp.0.join("journal");
    let keeper = temp.0.join("keeper");
    let anchor = temp.0.join("anchor");
    let clip = temp.0.join("clip.mp4");
    let child = Command::new(env!("CARGO_BIN_EXE_unifi_direct_trial"))
        .arg(format!("127.0.0.1:{port}"))
        .args(["127.0.0.1", "001122aabbcc"])
        .arg(std::env::var("FSS_LAB_CERT_DER")?)
        .arg(std::env::var("FSS_LAB_KEY_DER")?)
        .arg(&journal)
        .arg(&clip)
        .args(["12345678-1234-4abc-9abc-123456789abc", "1"])
        .arg(format!(
            "--anchored-journal={},{}",
            keeper.display(),
            anchor.display()
        ))
        .arg("--owner-authorized")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut child = TrialChild(Some(child));
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if child
            .0
            .as_mut()
            .ok_or("missing child")?
            .try_wait()?
            .is_some()
        {
            break;
        }
        if Instant::now() > deadline {
            return Err("anchored trial did not terminate".into());
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    let output = child.0.take().ok_or("missing child")?.wait_with_output()?;
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    assert!(!output.status.success());
    assert!(
        stdout.contains(
            "trial_journal=anchored root_trust=operator_selected independence=unverified"
        )
    );
    assert!(stdout.contains("controller_listener_ready"));
    assert!(stderr.contains("Deadline"));
    assert!(journal.is_dir() && keeper.is_dir() && anchor.is_dir());
    assert!(!clip.exists());
    Ok(())
}

#[test]
#[ignore = "requires disposable TLS certificate and key; takes at least 30 seconds"]
fn direct_trial_waits_across_a_single_accept_window() -> Test {
    use std::{
        io::{BufRead, BufReader, Read},
        os::unix::fs::DirBuilderExt,
        process::{Command, Stdio},
        time::Instant,
    };
    let root = std::env::temp_dir().join(format!("fss-direct-long-accept-{}", std::process::id()));
    std::fs::DirBuilder::new().mode(0o700).create(&root)?;
    let temp = Temp(root);
    let reserve = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = reserve.local_addr()?.port();
    drop(reserve);
    let journal = temp.0.join("journal");
    let clip = temp.0.join("clip.mp4");
    let child = Command::new(env!("CARGO_BIN_EXE_unifi_direct_trial"))
        .arg(format!("127.0.0.1:{port}"))
        .args(["127.0.0.1", "001122aabbcc"])
        .arg(std::env::var("FSS_LAB_CERT_DER")?)
        .arg(std::env::var("FSS_LAB_KEY_DER")?)
        .arg(&journal)
        .arg(&clip)
        .args([
            "12345678-1234-4abc-9abc-123456789abc",
            "33",
            "--owner-authorized",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut child = TrialChild(Some(child));
    let output = child
        .0
        .as_mut()
        .ok_or("missing child")?
        .stdout
        .take()
        .ok_or("missing stdout")?;
    let mut stdout = BufReader::new(output);
    let mut ready = false;
    for _ in 0..32 {
        let mut line = String::new();
        if stdout.read_line(&mut line)? == 0 {
            break;
        }
        if line.contains("controller_listener_ready") {
            ready = true;
            break;
        }
    }
    if !ready {
        return Err("listener was not ready".into());
    }
    std::thread::sleep(Duration::from_millis(30_250));
    let socket = std::net::TcpStream::connect_timeout(
        &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        Duration::from_secs(2),
    )?;
    drop(socket);
    let finish = Instant::now() + Duration::from_secs(10);
    loop {
        if child
            .0
            .as_mut()
            .ok_or("missing child")?
            .try_wait()?
            .is_some()
        {
            break;
        }
        if Instant::now() > finish {
            return Err("long accept trial did not terminate".into());
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    let mut rest = String::new();
    stdout.read_to_string(&mut rest)?;
    let result = child.0.take().ok_or("missing child")?.wait_with_output()?;
    if result.status.success()
        || !rest.contains("trial_stage=accept_window_elapsed")
        || !rest.contains("trial_stage=tcp_accepted")
        || clip.exists()
        || !journal.is_dir()
    {
        return Err("long accept did not preserve its bounded listener".into());
    }
    Ok(())
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_reports_the_session_retirement_reason() -> Test {
    direct_trial_retirement_case(
        "invalid-json",
        &frame(b"not-json"),
        "SessionRetired { reason: Protocol(InvalidJson), phase: AwaitHello, rejected_message: None }",
        false,
    )
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_reports_unmasked_websocket_frame() -> Test {
    direct_trial_retirement_case(
        "unmasked",
        &[0x82, 1, b'x'],
        "SessionRetired { reason: TransportDetail(UnmaskedClientFrame), phase: AwaitHello, rejected_message: None }",
        false,
    )
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_does_not_retry_after_a_clock_effect() -> Test {
    direct_trial_retirement_case(
        "effect-before-eof",
        &[],
        "SessionRetired { reason: TransportDetail(Io(UnexpectedEof)), phase: AwaitHello, rejected_message: None }",
        true,
    )
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_reports_correlated_request_to_its_written_clock_reply() -> Test {
    direct_trial_retirement_case(
        "correlated-after-effect",
        &[],
        "SessionRetired { reason: TransportDetail(Io(UnexpectedEof)), phase: AwaitHello, rejected_message: None }",
        true,
    )
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn trial_run_id_reopens_anchored_effects_only_for_reconciliation() -> Test {
    let first = direct_trial_retirement_case_with_id(
        "anchored-effect",
        &[],
        "SessionRetired { reason: TransportDetail(Io(UnexpectedEof)), phase: AwaitHello, rejected_message: None }",
        true,
    )?;
    let second = direct_trial_retirement_case_with_id(
        "anchored-effect",
        &[],
        "SessionRetired { reason: TransportDetail(Io(UnexpectedEof)), phase: AwaitHello, rejected_message: None }",
        true,
    )?;
    assert_ne!(first, second);
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_setup_does_not_retry_after_a_clock_effect() -> Test {
    direct_trial_retirement_case(
        "effect-after-setup",
        &[],
        "SessionRetired { reason: TransportDetail(Io(UnexpectedEof)), phase: AwaitHello, rejected_message: None }",
        true,
    )
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_reports_phase_on_deadline_after_clock_effect() -> Test {
    direct_trial_retirement_case("deadline", &[], "Conversation(Deadline)", true)
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_reports_phase_when_total_deadline_races_conversation() -> Test {
    direct_trial_retirement_case("short-deadline", &[], "", true)
}

fn direct_trial_retirement_case(
    case: &str,
    bad_frame: &[u8],
    expected: &str,
    after_effect: bool,
) -> Test {
    direct_trial_retirement_case_with_id(case, bad_frame, expected, after_effect).map(|_| ())
}

fn direct_trial_retirement_case_with_id(
    case: &str,
    bad_frame: &[u8],
    expected: &str,
    after_effect: bool,
) -> Result<String, Box<dyn Error>> {
    use std::{
        os::unix::fs::DirBuilderExt,
        process::{Command, Stdio},
        time::Instant,
    };
    let root = std::env::temp_dir().join(format!(
        "fss-direct-retire-process-{}-{case}", std::process::id()
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&root)?;
    let temp = Temp(root);
    let with_setup = case == "effect-after-setup";
    let bind = if with_setup {
        let addr: Ipv4Addr = std::env::var("FSS_TEST_CONTROLLER_BIND_IP")?.parse()?;
        if !(addr.is_private() || addr.is_link_local()) {
            return Err("private fixture interface required".into());
        }
        require_fixture_source_preserved(addr)?;
        addr
    } else {
        Ipv4Addr::LOCALHOST
    };
    let reserve = std::net::TcpListener::bind((bind, 0))?;
    let port = reserve.local_addr()?.port();
    drop(reserve);
    let cert_path = PathBuf::from(std::env::var("FSS_LAB_CERT_DER")?);
    let key_path = PathBuf::from(std::env::var("FSS_LAB_KEY_DER")?);
    let clip = temp.0.join("clip.mp4");
    let setup_fixture = if with_setup {
        Some(setup_process_fixture(
            &std::fs::read(&cert_path)?,
            &std::fs::read(&key_path)?,
            port,
            bind,
            false,
        )?)
    } else {
        None
    };
    let mut command = Command::new(env!("CARGO_BIN_EXE_unifi_direct_trial"));
    command
        .arg(format!("{bind}:{port}"))
        .arg(bind.to_string())
        .arg("001122aabbcc")
        .arg(&cert_path)
        .arg(&key_path)
        .arg(temp.0.join("journal"))
        .arg(&clip)
        .arg("12345678-1234-4abc-9abc-123456789abc");
    if case == "deadline" {
        command.arg("40");
    }
    if case == "short-deadline" {
        command.arg("10");
    }
    if case == "anchored-effect" {
        command.arg(format!(
            "--anchored-journal={},{}",
            temp.0.join("keeper").display(),
            temp.0.join("root").display()
        ));
    }
    if let Some(fixture) = &setup_fixture {
        use std::os::unix::fs::OpenOptionsExt;
        let credential = temp.0.join("fixture-credential.json");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&credential)?;
        file.write_all(br#"{"username":"fixture","password":"synthetic"}"#)?;
        command.arg(format!(
            "--setup-camera={},{},{},{}",
            fixture.discovery_port,
            fixture.https_port,
            cert_path.display(),
            credential.display()
        ));
    }
    let child = command
        .arg("--owner-authorized")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut child = TrialChild(Some(child));
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(std::fs::read(&cert_path)?))?;
    let config = ClientConfig::builder_with_provider(Arc::new(rustls_pure::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let address = SocketAddr::from((bind, port));
    let deadline = Instant::now() + Duration::from_secs(if case == "deadline" { 45 } else { 20 });
    let raw = loop {
        match connect_fixture_from(bind, address, Duration::from_millis(300)) {
            Ok(socket) => break socket,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(30)),
            Err(error) => return Err(error.into()),
        }
    };
    raw.set_read_timeout(Some(Duration::from_secs(10)))?;
    raw.set_write_timeout(Some(Duration::from_secs(10)))?;
    let connection = ClientConnection::new(Arc::new(config), ServerName::try_from("localhost")?)?;
    let mut socket = StreamOwned::new(connection, raw);
    socket.write_all(HEAD.as_bytes())?;
    socket.flush()?;
    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    while !header.ends_with(b"\r\n\r\n") {
        socket.read_exact(&mut byte)?;
        header.push(byte[0]);
        if header.len() > 4096 {
            return Err("upgrade limit".into());
        }
    }
    if !header.starts_with(b"HTTP/1.1 101 ") {
        return Err("upgrade refused".into());
    }
    if after_effect {
        if case == "deadline" || case == "short-deadline" {
            socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":9,"inResponseTo":99,"responseExpected":true}"#))?;
        }
        socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":10}"#))?;
        socket.flush()?;
        let response = receive_binary(&mut socket)?;
        let response_json = fss_core::json_input::parse(std::str::from_utf8(&response)?)?;
        let response_fields = response_json.object().ok_or("invalid time-sync reply")?;
        if response_fields.get("functionName").and_then(|v| v.text())
            != Some("ubnt_avclient_timeSync")
            || response_fields
                .get("inResponseTo")
                .and_then(|v| v.integer())
                != Some(10)
        {
            return Err("missing committed time-sync response".into());
        }
        if case == "correlated-after-effect" {
            let reply_id = response_fields
                .get("messageId")
                .and_then(|v| v.integer())
                .ok_or("missing time-sync reply ID")?;
            let correlated = format!(
                r#"{{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":11,"inResponseTo":{reply_id},"responseExpected":true}}"#
            );
            socket.write_all(&frame(correlated.as_bytes()))?;
            socket.flush()?;
        }
        if case == "deadline" {
            std::thread::sleep(Duration::from_secs(31));
        }
        if case == "short-deadline" {
            std::thread::sleep(Duration::from_secs(11));
        }
        drop(socket);
    } else {
        socket.write_all(bad_frame)?;
        socket.flush()?;
    }
    loop {
        if child
            .0
            .as_mut()
            .ok_or("missing child")?
            .try_wait()?
            .is_some()
        {
            break;
        }
        if Instant::now() > deadline {
            return Err("retirement trial did not terminate".into());
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    let output = child.0.take().ok_or("missing child")?.wait_with_output()?;
    let stderr = String::from_utf8(output.stderr)?;
    let stdout = String::from_utf8(output.stdout)?;
    if output.status.success()
        || !stderr.contains(expected)
        || (after_effect && !stdout.contains("trial_task_outcome=effect_unsettled"))
        || (!after_effect && !stdout.contains("trial_task_outcome=failed_before_approval"))
        || (case == "effect-after-setup" && !stdout.contains("trial_stage=setup_trace outcome=previous dispatch_started=true accept_started=true claims_unverified=true"))
        || clip.exists()
        || stdout.contains("pre_effect_websocket_eof_retry")
        || (after_effect
            && case != "deadline"
            && case != "short-deadline"
            && !stdout.contains("trial_stage=pre_hello_eof_stop effect_prepared=true"))
        || (case == "deadline"
            && !stdout.contains(
                "trial_stage=conversation_deadline phase=AwaitHello effect_prepared=true",
            ))
        || (case == "short-deadline"
            && !stdout.contains("deadline phase=AwaitHello effect_prepared=true"))
        || ((case == "deadline" || case == "short-deadline")
            && !stdout.contains("management_gate_passed=true"))
        || ((case == "deadline" || case == "short-deadline")
            && !stdout.contains("sync_uncorrelated=1 sync_correlated=1 sync_correlated_expected=1"))
        || (case == "correlated-after-effect"
            && !stdout.contains("sync_uncorrelated=1 sync_correlated=1 sync_correlated_expected=1 sync_to_last_written=1 sync_expected_to_last_written=1"))
    {
        return Err(format!("retirement was not reported: {stderr}").into());
    }
    if let Some(fixture) = setup_fixture {
        fixture.finish()?;
    }
    if case == "anchored-effect" {
        let (journal, minimum) = trial_checkpoint::reopen(
            &temp.0.join("journal"),
            &temp.0.join("keeper"),
            &temp.0.join("root"),
            "12345678-1234-4abc-9abc-123456789abc",
            [0, 0x11, 0x22, 0xaa, 0xbb, 0xcc],
        )?;
        let recovered = EffectCoordinator::recover(journal, minimum)?;
        assert!(recovered.is_reconciliation_only());
        assert!(recovered.journal().operations().count() > 0);
        let run_id = stdout.lines().find_map(|line| line.strip_prefix("trial_run_id="))
            .ok_or("missing trial run identity")?;
        if run_id.len() != 32 || !run_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("malformed trial run identity".into());
        }
        let prefix = format!("operation:unifi-trial-{run_id}-");
        if recovered.journal().operations().any(|receipt| !receipt.intent.operation_id.as_str().starts_with(&prefix)) {
            return Err("journal contains an effect outside the trial run identity".into());
        }
        drop(recovered);
        let inspection = Command::new(env!("CARGO_BIN_EXE_unifi_direct_trial"))
            .arg("--inspect-anchored")
            .arg(temp.0.join("journal"))
            .arg(temp.0.join("keeper"))
            .arg(temp.0.join("root"))
            .args([
                "12345678-1234-4abc-9abc-123456789abc",
                "001122aabbcc",
                "--owner-authorized",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut inspection = TrialChild(Some(inspection));
        let inspect_deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if inspection
                .0
                .as_mut()
                .ok_or("missing inspection child")?
                .try_wait()?
                .is_some()
            {
                break;
            }
            if Instant::now() > inspect_deadline {
                return Err("recovery inspection did not terminate".into());
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        let output = inspection
            .0
            .take()
            .ok_or("missing inspection child")?
            .wait_with_output()?;
        let stdout = String::from_utf8(output.stdout)?;
        if !output.status.success()
            || !stdout.contains("trial_recovery=reconciliation_only")
            || !stdout.contains("root_trust=operator_selected independence=unverified")
        {
            return Err("anchored recovery inspection failed".into());
        }
    }
    let run_id = stdout.lines().find_map(|line| line.strip_prefix("trial_run_id="))
        .ok_or("missing trial run identity")?;
    Ok(run_id.to_owned())
}
