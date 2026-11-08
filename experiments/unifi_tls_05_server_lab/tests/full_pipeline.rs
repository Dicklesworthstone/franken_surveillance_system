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

type Test = Result<(), Box<dyn Error>>;
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
    let nals: Vec<_> = fss_codec_h264::annex_b_nal_units(include_bytes!(
        "../../../crates/fss-packet/tests/fixtures/avc/baseline.264"
    ))
    .collect();
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
    if pictures.len() != 4 || pictures[0][0] & 31 != 5 {
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
    for index in 0..7 {
        let nal = pictures[index % 3];
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
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_process_produces_a_private_decodable_clip() -> Test {
    direct_trial_process_clip(false, false)
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_process_handles_time_sync_before_hello_and_produces_clip() -> Test {
    direct_trial_process_clip(true, false)
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn direct_trial_process_receives_media_without_settings_reply() -> Test {
    direct_trial_process_clip(true, true)
}

fn direct_trial_process_clip(sync_before_hello: bool, media_before_reply: bool) -> Test {
    use std::{
        os::unix::fs::{DirBuilderExt, PermissionsExt},
        process::{Command, Stdio},
        time::Instant,
    };
    let cert_path = PathBuf::from(std::env::var("FSS_LAB_CERT_DER")?);
    let key_path = PathBuf::from(std::env::var("FSS_LAB_KEY_DER")?);
    let root =
        std::env::temp_dir().join(format!("fss-direct-trial-process-{}-{sync_before_hello}-{media_before_reply}", std::process::id()));
    std::fs::DirBuilder::new().mode(0o700).create(&root)?;
    let temp = Temp(root);
    let reserve = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = reserve.local_addr()?.port();
    drop(reserve);
    let journal = temp.0.join("journal");
    let clip = temp.0.join("clip.mp4");
    let mut command = Command::new(env!("CARGO_BIN_EXE_unifi_direct_trial"));
    command.arg(format!("127.0.0.1:{port}"))
        .args(["127.0.0.1", "001122aabbcc"])
        .arg(&cert_path)
        .arg(&key_path)
        .arg(&journal)
        .arg(&clip)
        .arg("12345678-1234-4abc-9abc-123456789abc");
    if media_before_reply { command.arg("--media-before-reply"); }
    let child = command.arg("--owner-authorized")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut child = TrialChild(Some(child));
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(std::fs::read(cert_path)?))?;
    let client_config = Arc::new(
        ClientConfig::builder_with_provider(Arc::new(rustls_pure::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let deadline = Instant::now() + Duration::from_secs(15);
    let initial = loop {
        match std::net::TcpStream::connect_timeout(&address, Duration::from_millis(300)) {
            Ok(socket) => break socket,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(30)),
            Err(error) => return Err(error.into()),
        }
    };
    drop(initial);
    // A camera can upgrade and then disconnect before sending hello. No
    // management effect has been prepared, so one bounded reconnect is safe.
    let early_raw = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
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
    let raw = loop {
        match std::net::TcpStream::connect_timeout(&address, Duration::from_millis(300)) {
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
    let agreement = receive_binary(&mut socket)
        .map_err(|e| format!("agreement request: {e}"))?;
    if !agreement
        .windows(b"ubnt_avclient_paramAgreement".len())
        .any(|w| w == b"ubnt_avclient_paramAgreement")
    {
        return Err("missing agreement".into());
    }
    let agreement_json = fss_core::json_input::parse(std::str::from_utf8(&agreement)?)?;
    let agreement_id = agreement_json.object().and_then(|v| v.get("messageId")).and_then(|v| v.integer()).ok_or("missing agreement ID")?;
    let agreement_reply = format!(r#"{{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_paramAgreement","messageId":8,"inResponseTo":{agreement_id}}}"#);
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
    if !destination.ip().is_loopback() {
        return Err("stream destination escaped loopback".into());
    }
    let setting_json = fss_core::json_input::parse(std::str::from_utf8(&setting)?)?;
    let setting_id = setting_json.object().and_then(|v| v.get("messageId")).and_then(|v| v.integer()).ok_or("missing setting ID")?;
    let setting_reply = format!(r#"{{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ChangeVideoSettings","messageId":9,"inResponseTo":{setting_id}}}"#);
    if !media_before_reply {
        socket.write_all(&frame(setting_reply.as_bytes()))?;
        socket.flush()?;
    }
    let mut media = std::net::TcpStream::connect_timeout(&destination, Duration::from_secs(5))?;
    media.write_all(&media_fixture()?)?;
    drop(media);
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
    if !output.status.success() {
        return Err(format!("trial failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    let report = String::from_utf8(output.stdout)?;
    let expected_startup_clocks = if sync_before_hello { 2 } else { 1 };
    if !report.contains(&format!("trial_stage=startup_protocol_trace clocks={expected_startup_clocks} effects_require_reconciliation=true")) {
        return Err("startup protocol trace was not retained".into());
    }
    if !report.contains("trial_complete")
        || !report.contains("trial_stage=tcp_accepted")
        || !report.contains("trial_stage=handshake_eof_retry")
        || !report.contains("trial_stage=pre_effect_websocket_eof_retry")
        || !report.contains("trial_stage=tls_handshake_completed")
        || !report.contains("trial_stage=websocket_accepted")
        || !report.contains("effects=reconciliation_required")
        || !report.contains("continuous_recording=false")
    {
        return Err(format!("incomplete report: {report}").into());
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
    if std::fs::metadata(&clip)?.permissions().mode() & 0o077 != 0 {
        return Err("clip permissions are not private".into());
    }
    if !journal.is_dir() {
        return Err("missing effect journal".into());
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
    let mut first = String::new();
    stdout.read_line(&mut first)?;
    if !first.contains("controller_listener_ready") {
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
fn direct_trial_reports_phase_on_deadline_after_clock_effect() -> Test {
    direct_trial_retirement_case(
        "deadline",
        &[],
        "Conversation(Deadline)",
        true,
    )
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
    use std::{
        os::unix::fs::DirBuilderExt,
        process::{Command, Stdio},
        time::Instant,
    };
    let root = std::env::temp_dir().join(format!(
        "fss-direct-retire-process-{}-{case}",
        std::process::id()
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&root)?;
    let temp = Temp(root);
    let reserve = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = reserve.local_addr()?.port();
    drop(reserve);
    let cert_path = PathBuf::from(std::env::var("FSS_LAB_CERT_DER")?);
    let clip = temp.0.join("clip.mp4");
    let mut command = Command::new(env!("CARGO_BIN_EXE_unifi_direct_trial"));
    command.arg(format!("127.0.0.1:{port}"))
        .args(["127.0.0.1", "001122aabbcc"])
        .arg(&cert_path)
        .arg(std::env::var("FSS_LAB_KEY_DER")?)
        .arg(temp.0.join("journal"))
        .arg(&clip)
        .arg("12345678-1234-4abc-9abc-123456789abc");
    if case == "deadline" { command.arg("40"); }
    if case == "short-deadline" { command.arg("10"); }
    let child = command.arg("--owner-authorized")
        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let mut child = TrialChild(Some(child));
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(std::fs::read(cert_path)?))?;
    let config = ClientConfig::builder_with_provider(Arc::new(rustls_pure::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let deadline = Instant::now() + Duration::from_secs(if case == "deadline" { 45 } else { 20 });
    let raw = loop {
        match std::net::TcpStream::connect_timeout(&address, Duration::from_millis(300)) {
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
        if response_fields.get("functionName").and_then(|v| v.text()) != Some("ubnt_avclient_timeSync")
            || response_fields.get("inResponseTo").and_then(|v| v.integer()) != Some(10) {
            return Err("missing committed time-sync response".into());
        }
        if case == "deadline" { std::thread::sleep(Duration::from_secs(31)); }
        if case == "short-deadline" { std::thread::sleep(Duration::from_secs(11)); }
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
        || clip.exists()
        || stdout.contains("pre_effect_websocket_eof_retry")
        || (after_effect && case != "deadline" && case != "short-deadline" && !stdout.contains("trial_stage=pre_hello_eof_stop effect_prepared=true"))
        || (case == "deadline" && !stdout.contains("trial_stage=conversation_deadline phase=AwaitHello effect_prepared=true"))
        || (case == "short-deadline" && !stdout.contains("deadline phase=AwaitHello effect_prepared=true"))
        || ((case == "deadline" || case == "short-deadline") && !stdout.contains("management_gate_passed=true"))
        || ((case == "deadline" || case == "short-deadline") && !stdout.contains("sync_uncorrelated=1 sync_correlated=1 sync_correlated_expected=1"))
    {
        return Err(format!("retirement was not reported: {stderr}").into());
    }
    Ok(())
}
