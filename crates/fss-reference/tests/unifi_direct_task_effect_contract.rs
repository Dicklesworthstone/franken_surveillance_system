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
    BudgetVector, ContentDigest, IdempotencyKey, OperationId, RegionId, RegionKind,
    RootAuthoritySpec, RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_object::{
    HostSpoolIo,
    effect_journal::{EffectJournalLimits, FileEffectJournal},
};
use fss_packet::extended_flv::{Limits as FlvLimits, stream::Framer};
use fss_reference::unifi_direct::{
    AudioCodec, Controller, Identity, Observation, StreamStart, VideoChannel, VideoCodec,
    controller_listener, conversation,
    ingress::DirectIngress,
    intent, listener,
    management::{Intent, Preconditions},
    metered::{MeteredClock, MeteredIo},
    owner::{self, PeerAdmission},
    pipeline,
    receive::{ManagementAuthority, ManagementWrite, Step, StreamAuthority},
    recording, supervisor,
    upgrade::ProtocolPolicy,
};
use fss_runtime::{
    authority::AuthorityCx,
    effect::{CommitApproval, CommittedEffect, EffectCoordinator, PrepareSpec, PreparedEffect},
    execution::{TaskCompletion, TaskSpec, run_owned_async},
    lease::LeaseRegistry,
    tcp_ingress::TcpIngress,
};
use std::{
    cell::{Cell, RefCell},
    error::Error,
    future::{Future, poll_fn},
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    rc::Rc,
    sync::Arc,
    task::Poll,
    time::Duration,
};

type Test = Result<(), Box<dyn Error>>;
const HEAD: &str = "GET / HTTP/1.1\r\nHost: camera.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nCamera-Mac: 001122aabbcc\r\nSec-WebSocket-Protocol: secure_transfer\r\n\r\n";
const HELLO:&[u8]=br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_hello","messageId":7,"payload":{}}"#;
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
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
    assert!(payload.len() < 126);
    let mask = [1, 2, 3, 4];
    let mut bytes = vec![0x82, 0x80 | payload.len() as u8];
    bytes.extend_from_slice(&mask);
    bytes.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    bytes
}

#[test]
fn observed_hello_gets_its_own_durable_permit_inside_task() -> Test {
    let path = std::fs::canonicalize(std::env::temp_dir())?
        .join(format!("fss-unifi-task-effect-{}", std::process::id()));
    std::fs::create_dir(&path)?;
    let temp = Temp(path);
    let store = FileEffectJournal::create(
        temp.0.join("journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut effects = EffectCoordinator::with_journal(Box::new(store))?;
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 1_000_000;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:task-unifi".into(),
            operation_id: OperationId::parse("operation:camera-task-owner")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::CameraManagementCommit.as_str().into(),
                RuntimeGrant::CameraManagementPrepare.as_str().into(),
            ],
            deadline: Some(TimestampNs(60_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"fixture"),
            generation: 1,
        },
        RegionId::new("region:task-unifi")?,
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
    let leases = Rc::new(RefCell::new(leases));
    let conditions = Preconditions {
        camera,
        peer_admission: ContentDigest::sha256(b"fixture admission"),
        session_generation: 1,
        previous_association: None,
        previous_clock: None,
        lease_fence: fence,
    };
    let operation = OperationId::parse("operation:fixture-observed-hello")?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx=asupersync::Cx::current().ok_or("missing runtime")?;
        let result=run_owned_async(&mut authority,&mut tree,TaskSpec {task_id:TaskId::new("task:unifi-live-fixture")?,started_at:TimestampNs(3)},&cx,async |task,cx| {
            let output:Test=async {
                let listener=TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;
                let peer=std::thread::spawn(move || -> io::Result<()> {
                    let mut socket=std::net::TcpStream::connect_timeout(&address,Duration::from_secs(5))?;socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let mut request=HEAD.as_bytes().to_vec();request.extend(frame(HELLO));socket.write_all(&request)?;
                    let mut header=Vec::new();let mut byte=[0_u8;1];
                    while !header.ends_with(b"\r\n\r\n") {socket.read_exact(&mut byte)?;header.push(byte[0]);if header.len()>4096{return Err(io::Error::other("upgrade limit"));}}
                    if !header.starts_with(b"HTTP/1.1 101 "){return Err(io::Error::other("upgrade refused"));}
                    let mut h=[0_u8;2];socket.read_exact(&mut h)?;if h[0]!=0x82||h[1]&0x80!=0{return Err(io::Error::other("not binary"));}
                    let len=match h[1] { n@0..=125=>usize::from(n),126=>{let mut x=[0_u8;2];socket.read_exact(&mut x)?;usize::from(u16::from_be_bytes(x))},_=>return Err(io::Error::other("frame size"))};
                    if len>4096{return Err(io::Error::other("message bound"));}let mut payload=vec![0;len];socket.read_exact(&mut payload)?;
                    if !payload.windows(b"ubnt_avclient_hello".len()).any(|w|w==b"ubnt_avclient_hello"){return Err(io::Error::other("wrong message"));}
                    Ok(())
                });
                let (socket,_)=timeout(cx.now(),Duration::from_secs(5),listener.accept()).await??;
                let clock=MeteredClock::new(task,cx,TimestampNs(4))?;
                let io=MeteredIo::with_clock(socket,clock,"fixture:camera",4096)?;
                let controller=Controller::new(Identity::new("FSS","12345678-1234-4abc-9abc-123456789abc","1.20.0")?,1)?;
                let mut session=owner::accept(io,ProtocolPolicy::RequireOffer,&FixtureAdmission,controller,Duration::from_secs(5)).await?;
                assert_eq!(session.next(Duration::from_secs(3)).await?,Step::Observation(Observation::Hello));
                session.prepare_hello("2026-11-05T10:00:00.000Z")?;
                let intent=session.management_intent(conditions)?;
                let prepared=task.prepare_effect(cx,&mut effects,&mut leases.borrow_mut(),PrepareSpec {
                    operation:&operation,idempotency_key:IdempotencyKey::parse(operation.as_str())?,request_digest:intent.request_digest(),precondition_digest:intent.precondition_digest(),resource:&resource,fence,
                    prepare_grant:RuntimeGrant::CameraManagementPrepare,commit_grant:RuntimeGrant::CameraManagementCommit,terminal_predicate:"independent association observation or reconciliation",
                },clock.now()?)?;
                let approval=CommitApproval {prepared_digest:prepared.digest(),current_precondition_digest:intent.precondition_digest()};
                let permit=task.commit_effect(cx,&mut effects,&mut leases.borrow_mut(),prepared,clock.now()?,approval)?;
                assert!(permit.journal_backed());
                let guard=Guard {leases:&leases,clock};
                let result=session.dispatch_management(intent,conditions,permit,&guard,Duration::from_secs(3)).await.map_err(|_|"management dispatch refused")?;
                assert!(matches!(result,ManagementWrite::Written {..}));
                peer.join().map_err(|_|"fixture peer panic")??;
                let retirement=session.retire();assert_eq!(retirement.previous_phase,fss_reference::unifi_direct::Phase::AwaitAgreementPreparation);
                Ok(())
            }.await;
            let outcome=if output.is_ok(){TaskOutcome::Indeterminate("fixture association needs reconciliation".into())}else{TaskOutcome::Failed("task effect fixture failed".into())};
            TaskCompletion {output,outcome,completed_at:TimestampNs(59_000_000_000)}
        }).await?;
        result.receipt?;result.output
    })?;
    assert_eq!(
        effects
            .journal()
            .operation(&operation)
            .ok_or("missing journal operation")?
            .state,
        fss_core::EffectState::Committed
    );
    assert!(!authority.finalize_report(&tree)?.is_empty());
    Ok(())
}

fn receive_binary(socket: &mut std::net::TcpStream) -> io::Result<Vec<u8>> {
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
        "../../fss-packet/tests/fixtures/avc/baseline.264"
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

fn conversation_scenario(revoke_stream: bool, revoke_after_start: bool) -> Test {
    let path = std::fs::canonicalize(std::env::temp_dir())?.join(format!(
        "fss-unifi-task-conversation-{}-{revoke_stream}-{revoke_after_start}",
        std::process::id(),
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
                assert!(matches!(controller_listener::Listener::bind(task,cx,clock,&policy,bind,"fixture:camera",Duration::from_secs(5)).await,Err(listener::Error::Denied)));
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
                let denied_control=controller_listener::Listener::bind(task,cx,clock,&policy,bind,"fixture:camera",Duration::from_secs(5)).await?;
                let denied_control_address=SocketAddr::V4(denied_control.local_addr());
                let unexpected_control=std::thread::spawn(move || std::net::TcpStream::connect_timeout(&denied_control_address,Duration::from_secs(5)).map(drop));
                assert!(matches!(denied_control.accept(4096,Duration::from_secs(5)).await,Err(listener::Error::Denied)));
                unexpected_control.join().map_err(|_|"unexpected controller peer panic")??;
                policy.peer.set(true);
                let guarded_control=controller_listener::Listener::bind(task,cx,clock,&policy,bind,"fixture:camera",Duration::from_secs(5)).await?;
                let guarded_address=SocketAddr::V4(guarded_control.local_addr());
                let sending_control=std::thread::spawn(move || -> io::Result<()> {
                    let mut socket=std::net::TcpStream::connect_timeout(&guarded_address,Duration::from_secs(5))?;
                    socket.write_all(b"fixture")
                });
                let (mut guarded_io,_)=guarded_control.accept(4096,Duration::from_secs(5)).await?;
                sending_control.join().map_err(|_|"guarded controller peer panic")??;
                policy.peer.set(false);
                let mut byte=[0u8;1];
                assert_eq!(asupersync::io::AsyncReadExt::read(&mut guarded_io,&mut byte).await.unwrap_err().kind(),io::ErrorKind::PermissionDenied);
                assert_eq!(asupersync::io::AsyncWriteExt::write(&mut guarded_io,b"x").await.unwrap_err().kind(),io::ErrorKind::PermissionDenied);
                policy.peer.set(true);
                assert_eq!(asupersync::io::AsyncReadExt::read(&mut guarded_io,&mut byte).await.unwrap_err().kind(),io::ErrorKind::PermissionDenied);
                drop(guarded_io);
                policy.peer.set(true);
                // The upgrade parser has already buffered the hello, so a raw
                // socket or TLS policy check cannot protect this observation.
                let buffered_control=controller_listener::Listener::bind(task,cx,clock,&policy,bind,"fixture:camera",Duration::from_secs(5)).await?;
                let buffered_address=SocketAddr::V4(buffered_control.local_addr());
                let buffered_peer=std::thread::spawn(move || std::net::TcpStream::connect_timeout(&buffered_address,Duration::from_secs(5)));
                let (buffered_raw,buffered_gate)=buffered_control.accept(4096,Duration::from_secs(5)).await?;
                let buffered_peer=buffered_peer.join().map_err(|_|"buffered controller peer panic")??;
                let mut pipelined=HEAD.as_bytes().to_vec();
                pipelined.extend(frame(HELLO));
                let prepared=fss_reference::unifi_direct::upgrade::PreparedUpgrade::parse(&pipelined,ProtocolPolicy::RequireOffer)?;
                let buffered_io=MeteredIo::with_clock(buffered_gate.wrap(buffered_raw),clock,"fixture:camera",4096)?;
                let buffered_controller=Controller::new(Identity::new("FSS","12345678-1234-4abc-9abc-123456789abc","1.20.0")?,1)?;
                let mut buffered_session=fss_reference::unifi_direct::receive::Session::from_upgrade(prepared,buffered_io,fss_reference::unifi_direct::Dispatch::Written,buffered_controller)?;
                buffered_session.bind_admission(buffered_gate)?;
                policy.peer.set(false);
                match buffered_session.next(Duration::from_secs(5)).await? {
                    fss_reference::unifi_direct::receive::Step::Retired {reason:fss_reference::unifi_direct::receive::Stop::AdmissionRevoked,controller} => {
                        assert_eq!(controller.previous_phase,fss_reference::unifi_direct::Phase::AwaitHello);
                        assert_eq!(controller.hello_request_id,None);
                    },
                    other=>return Err(format!("buffered message survived revocation: {other:?}").into()),
                }
                policy.peer.set(true);
                assert!(matches!(buffered_session.next(Duration::from_secs(5)).await,Err(fss_reference::unifi_direct::receive::Error::Retired)));
                drop(buffered_peer);
                let invalid_control=controller_listener::Listener::bind(task,cx,clock,&policy,bind,"fixture:camera",Duration::from_secs(5)).await?;
                assert!(matches!(invalid_control.accept(0,Duration::from_secs(5)).await,Err(listener::Error::Configuration)));
                let revoked_control=controller_listener::Listener::bind(task,cx,clock,&policy,bind,"fixture:camera",Duration::from_secs(5)).await?;
                let revoked_control_address=SocketAddr::V4(revoked_control.local_addr());
                let mut waiting_control=Box::pin(revoked_control.accept(4096,Duration::from_secs(5)));
                poll_fn(|context| match waiting_control.as_mut().poll(context) {Poll::Pending=>Poll::Ready(()),Poll::Ready(_)=>panic!("controller accept should wait")}).await;
                policy.listen.set(false);
                let wake_control=std::net::TcpStream::connect_timeout(&revoked_control_address,Duration::from_secs(1))?;
                assert!(matches!(waiting_control.await,Err(listener::Error::Denied)));
                drop(wake_control);
                policy.listen.set(true);
                let controller_listener=controller_listener::Listener::bind(task,cx,clock,&policy,bind,"fixture:camera",Duration::from_secs(5)).await?;
                let address=SocketAddr::V4(controller_listener.local_addr());
                let wire=media_fixture()?;
                let expected=wire.clone();
                let peer=std::thread::spawn(move || -> io::Result<()> {
                    let mut socket=std::net::TcpStream::connect_timeout(&address,Duration::from_secs(5))?;
                    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let mut request=HEAD.as_bytes().to_vec(); request.extend(frame(HELLO)); socket.write_all(&request)?;
                    let mut header=Vec::new(); let mut byte=[0u8;1];
                    while !header.ends_with(b"\r\n\r\n") { socket.read_exact(&mut byte)?; header.push(byte[0]); if header.len()>4096 { return Err(io::Error::other("upgrade limit")); } }
                    if !header.starts_with(b"HTTP/1.1 101 ") { return Err(io::Error::other("upgrade refused")); }
                    if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_hello".len()).any(|w|w==b"ubnt_avclient_hello") { return Err(io::Error::other("missing hello reply")); }
                    socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":10}"#))?;
                    if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_timeSync".len()).any(|w|w==b"ubnt_avclient_timeSync") { return Err(io::Error::other("missing time-sync reply")); }
                    if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_paramAgreement".len()).any(|w|w==b"ubnt_avclient_paramAgreement") { return Err(io::Error::other("missing agreement")); }
                    socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_paramAgreement","messageId":8,"inResponseTo":3}"#))?;
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
                    socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ChangeVideoSettings","messageId":9,"inResponseTo":4}"#))?;
                    let mut media=std::net::TcpStream::connect_timeout(&destination,Duration::from_secs(5))?;
                    let split=wire.len().min(100);
                    media.write_all(&wire[..split])?;
                    if revoke_after_start {
                        let mut last=[0u8;1];
                        return match socket.read(&mut last) { Ok(0)=>Ok(()), _=>Err(io::Error::other("revoked controller did not retire")) };
                    }
                    socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":11}"#))?;
                    if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_timeSync".len()).any(|w|w==b"ubnt_avclient_timeSync") { return Err(io::Error::other("missing post-start time-sync reply")); }
                    media.write_all(&wire[split..])?;
                    drop(media);
                    let mut last=[0u8;1];
                    match socket.read(&mut last) { Ok(0)=>Ok(()), _=>Err(io::Error::other("controller did not retire")) }
                });
                let (io,gate)=controller_listener.accept(4096,Duration::from_secs(5)).await?;
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
                if revoke_after_start {
                    let mut retained=Vec::new();
                    match supervisor.step(&mut owner,&operations[4],Duration::from_secs(5)).await {
                        supervisor::Step::Media(pipeline::Step::Progress {appended}) if appended>0=>(),
                        supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {record,..}))=>retained.extend_from_slice(record.bytes()),
                        other=>return Err(format!("expected buffered media: {other:?}").into()),
                    };
                    policy.peer.set(false);
                    assert!(matches!(supervisor.step(&mut owner,&operations[4],Duration::from_secs(5)).await,
                        supervisor::Step::ControllerStopped(fss_reference::unifi_direct::receive::Stop::AdmissionRevoked)));
                    policy.peer.set(true);
                    assert!(matches!(supervisor.step(&mut owner,&operations[4],Duration::from_secs(5)).await,supervisor::Step::Stopped));
                    let retired=supervisor.retire();
                    assert_eq!(retired.controller.previous_phase,fss_reference::unifi_direct::Phase::AgreementReplyObserved);
                    for record in retired.media.recorder.pending {retained.extend_from_slice(record.bytes());}
                    retained.extend_from_slice(retired.media.ingress.framing.bytes());
                    if let Some(buffered)=retired.media.ingress.buffered {retained.extend_from_slice(&buffered.source.bytes()[buffered.appended..]);}
                    if let Some(pending)=retired.media.ingress.source.pending {retained.extend_from_slice(pending.bytes());}
                    assert_eq!(retained.len() as u64,retired.media.ingress.source.received);
                    assert_eq!(retained,expected[..retained.len()]);
                    peer.join().map_err(|_|"fixture peer panic")??;
                    return Ok(());
                }
                let mut later_syncs=0;
                let mut originals=Vec::new();
                let mut segments=0;
                let mut frames=0;
                loop {
                    match supervisor.step(&mut owner,&operations[4],Duration::from_secs(5)).await {
                        supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {record,..})) => originals.extend_from_slice(record.bytes()),
                        supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Buffered) | pipeline::Step::Progress {..}) => (),
                        supervisor::Step::TimeSyncWritten => later_syncs+=1,
                        supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Segment(segment))) => {
                            for record in segment.source() { originals.extend_from_slice(record.bytes()); }
                            let mut movie=supervisor.initialization().ok_or("missing initialization")?.bytes().to_vec();
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
    for operation in &operations[..if revoke_stream || revoke_after_start {
        4
    } else {
        5
    }] {
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
fn owned_conversation_requests_a_stream_that_reaches_the_recording_pipeline() -> Test {
    conversation_scenario(false, false)
}

#[test]
fn revoked_listener_policy_prevents_stream_setting_dispatch() -> Test {
    conversation_scenario(true, false)
}

#[test]
fn revoked_controller_admission_stops_buffered_media_and_retains_it() -> Test {
    conversation_scenario(false, true)
}
