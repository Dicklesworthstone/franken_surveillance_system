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
const EVENT:&[u8]=br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventSmartDetect","messageId":20,"payload":{"edgeType":"enter","descriptors":[{"objectType":"person","trackerID":1,"confidenceLevel":80,"coord":[0,1,500,1000]}]}}"#;
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
    assert!(payload.len() <= usize::from(u16::MAX));
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

#[test]
fn observed_hello_gets_its_own_durable_permit_inside_task() -> Test {
    management_authority_scenario(false)
}

#[test]
fn management_revoked_after_partial_write_fences_session() -> Test {
    management_authority_scenario(true)
}

#[test]
fn event_reply_requires_separate_disclosure_authority_and_journal() -> Test {
    struct EchoGuard<'a, 'scope, 'task>(&'a Guard<'a, 'scope, 'task>);
    impl ManagementAuthority for EchoGuard<'_, '_, '_> {
        fn permits(&self, mac: [u8; 6], intent: Intent, permit: &CommittedEffect) -> bool {
            ManagementAuthority::permits(self.0, mac, intent, permit)
        }
        fn permits_event_reply(&self, mac: [u8; 6], intent: Intent, permit: &CommittedEffect) -> bool {
            ManagementAuthority::permits(self.0, mac, intent, permit) && intent.source_digest().is_some()
        }
    }
    const REQUEST: &[u8] = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventExample","messageId":20,"responseExpected":true,"payload":{"private":"fixture","count":2}}"#;
    let path=std::fs::canonicalize(std::env::temp_dir())?.join(format!("fss-unifi-event-reply-{}",std::process::id()));
    std::fs::create_dir(&path)?;
    let temp=Temp(path);
    let store=FileEffectJournal::create(temp.0.join("journal"),EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
    let mut effects=EffectCoordinator::with_journal(Box::new(store))?;
    let mut budget=BudgetVector::ZERO;budget.network_bytes=1_000_000;
    let (mut authority,mut tree)=AuthorityCx::root(RootAuthoritySpec {
        trace_id:"trace:event-reply".into(),operation_id:OperationId::parse("operation:event-owner")?,principal:"principal:fixture".into(),
        capabilities:vec![RuntimeGrant::AdapterNet.as_str().into(),RuntimeGrant::CameraManagementPrepare.as_str().into(),RuntimeGrant::CameraManagementCommit.as_str().into()],
        deadline:Some(TimestampNs(60_000_000_000)),priority:1,budgets:budget,privacy_scope:"privacy:test".into(),retention_scope:"retention:test".into(),anchor_universe:ContentDigest::sha256(b"fixture"),generation:1,
    },RegionId::new("region:event-reply")?,RegionKind::Process,budget,TimestampNs(1))?;
    let camera=ContentDigest::sha256(b"fixture camera");let resource=format!("camera:{}",camera.to_text());
    let mut leases=LeaseRegistry::new();let fence=leases.acquire(&resource,authority.region().as_str(),None,TimestampNs(2))?.fence;let leases=RefCell::new(leases);
    let conditions=Preconditions {camera,peer_admission:ContentDigest::sha256(b"fixture peer"),session_generation:1,previous_association:None,previous_clock:None,lease_fence:fence};
    let operation=OperationId::parse("operation:event-reply")?;
    let runtime=RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx=asupersync::Cx::current().ok_or("missing runtime")?;
        let result=run_owned_async(&mut authority,&mut tree,TaskSpec {task_id:TaskId::new("task:event-reply")?,started_at:TimestampNs(3)},&cx,async |task,cx| {
            let output:Test=async {
                let listener=TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;
                let (check_tx,check_rx)=std::sync::mpsc::channel();
                let (quiet_tx,quiet_rx)=std::sync::mpsc::channel();
                let peer=std::thread::spawn(move || -> io::Result<()> {
                    let mut socket=std::net::TcpStream::connect_timeout(&address,Duration::from_secs(5))?;socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let mut request=HEAD.as_bytes().to_vec();request.extend(frame(REQUEST));socket.write_all(&request)?;
                    let mut header=Vec::new();let mut byte=[0u8;1];while !header.ends_with(b"\r\n\r\n") {socket.read_exact(&mut byte)?;header.push(byte[0]);if header.len()>4096{return Err(io::Error::other("upgrade limit"));}}
                    if !header.starts_with(b"HTTP/1.1 101 "){return Err(io::Error::other("upgrade refused"));}
                    check_rx.recv_timeout(Duration::from_secs(5)).map_err(io::Error::other)?;
                    socket.set_read_timeout(Some(Duration::from_millis(150)))?;
                    match socket.peek(&mut byte) {Err(error) if matches!(error.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::TimedOut)=>(),_=>return Err(io::Error::other("denied reply reached peer"))};
                    quiet_tx.send(()).map_err(io::Error::other)?;socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let response=receive_binary(&mut socket)?;
                    let parsed=fss_core::json_input::parse(std::str::from_utf8(&response).map_err(io::Error::other)?).map_err(io::Error::other)?;
                    let fields=parsed.object().ok_or_else(||io::Error::other("reply object"))?;
                    if fields.get("functionName").and_then(|v|v.text())!=Some("EventExample") || fields.get("inResponseTo").and_then(|v|v.integer())!=Some(20) || fields.get("payload").and_then(|v|v.object()).and_then(|v|v.get("private")).and_then(|v|v.text())!=Some("fixture") {return Err(io::Error::other("wrong reply"));}
                    Ok(())
                });
                let (socket,_)=timeout(cx.now(),Duration::from_secs(5),listener.accept()).await??;
                let clock=MeteredClock::new(task,cx,TimestampNs(4))?;let io=MeteredIo::with_clock(socket,clock,"fixture:camera",4096)?;
                let controller=Controller::new(Identity::new("FSS","12345678-1234-4abc-9abc-123456789abc","1.20.0")?,1)?;
                let inbox=fss_reference::unifi_direct::events::StartupInbox::new(2,fss_reference::unifi_direct::MAX_MESSAGE_BYTES)?;
                let mut session=owner::accept(io,ProtocolPolicy::RequireOffer,&FixtureAdmission,controller,Duration::from_secs(5)).await?;
                session.bind_startup_events(&inbox)?;
                assert!(matches!(session.next(Duration::from_secs(5)).await?,Step::Observation(Observation::Other)));
                let event=inbox.take().ok_or("missing event")?;
                assert!(matches!(session.next(Duration::from_secs(5)).await?,Step::EventReplyBackpressure));
                session.prepare_event_reply(&event,"2026-11-05T10:00:00.000Z")?;
                let intent=session.management_intent(conditions)?;assert_eq!(intent.source_digest(),Some(event.digest()));
                let prepared=task.prepare_effect(cx,&mut effects,&mut leases.borrow_mut(),PrepareSpec {operation:&operation,idempotency_key:IdempotencyKey::parse(operation.as_str())?,request_digest:intent.request_digest(),precondition_digest:intent.precondition_digest(),resource:&resource,fence,prepare_grant:RuntimeGrant::CameraManagementPrepare,commit_grant:RuntimeGrant::CameraManagementCommit,terminal_predicate:"event reply reconciliation"},clock.now()?)?;
                let approval=CommitApproval {prepared_digest:prepared.digest(),current_precondition_digest:intent.precondition_digest()};
                let permit=task.commit_effect(cx,&mut effects,&mut leases.borrow_mut(),prepared,clock.now()?,approval)?;
                let guard=Guard {leases:&leases,clock};
                let denied=session.dispatch_management(intent,conditions,permit,&guard,Duration::from_secs(5)).await.err().ok_or("default authority allowed disclosure")?;
                assert_eq!(denied.reason,fss_reference::unifi_direct::receive::Error::Denied);
                check_tx.send(()).map_err(io::Error::other)?;quiet_rx.recv_timeout(Duration::from_secs(5)).map_err(io::Error::other)?;
                let result=session.dispatch_management(intent,conditions,denied.permit,&EchoGuard(&guard),Duration::from_secs(5)).await.map_err(|_|"event dispatch refused")?;
                assert!(matches!(result,ManagementWrite::Written {..}));
                peer.join().map_err(|_|"peer panic")??;
                assert_eq!(session.retire().event_reply,None);
                Ok(())
            }.await;
            let outcome=if output.is_ok(){TaskOutcome::Indeterminate("fixture reply requires reconciliation".into())}else{TaskOutcome::Failed("event reply fixture failed".into())};
            TaskCompletion {output,outcome,completed_at:TimestampNs(59_000_000_000)}
        }).await?;result.receipt?;result.output
    })?;
    assert_eq!(effects.journal().operation(&operation).ok_or("event operation missing")?.state,fss_core::EffectState::Committed);
    Ok(())
}

#[test]
fn startup_event_reply_continues_handshake_with_source_custody() -> Test {
    startup_event_reply_scenario(true, false)
}

#[test]
fn startup_event_disclosure_denial_retains_request_and_permit() -> Test {
    startup_event_reply_scenario(false, false)
}

#[test]
fn startup_event_reply_is_serviced_while_waiting_for_media() -> Test {
    startup_event_reply_scenario(true, true)
}

fn startup_event_reply_scenario(allow: bool, during_accept: bool) -> Test {
    struct EchoGuard<'a, 'scope, 'task> { guard: &'a Guard<'a, 'scope, 'task>, allow: bool }
    impl ManagementAuthority for EchoGuard<'_, '_, '_> {
        fn permits(&self, mac:[u8;6], intent:Intent, permit:&CommittedEffect)->bool {
            ManagementAuthority::permits(self.guard,mac,intent,permit)
        }
        fn permits_event_reply(&self, mac:[u8;6], intent:Intent, permit:&CommittedEffect)->bool {
            self.allow && ManagementAuthority::permits(self.guard,mac,intent,permit)
        }
    }
    const REQUEST:&[u8]=br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventExample","messageId":20,"responseExpected":true,"payload":{"private":"fixture"}}"#;
    let path=std::fs::canonicalize(std::env::temp_dir())?.join(format!("fss-startup-event-{}-{allow}-{during_accept}",std::process::id()));
    std::fs::create_dir(&path)?;let temp=Temp(path);
    let store=FileEffectJournal::create(temp.0.join("journal"),EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
    let mut effects=EffectCoordinator::with_journal(Box::new(store))?;
    let mut budget=BudgetVector::ZERO;budget.network_bytes=1_000_000;budget.bytes=1_000_000;
    let (mut authority,mut tree)=AuthorityCx::root(RootAuthoritySpec {
        trace_id:"trace:startup-event".into(),operation_id:OperationId::parse("operation:startup-event-owner")?,principal:"principal:fixture".into(),
        capabilities:vec![RuntimeGrant::AdapterNet.as_str().into(),RuntimeGrant::ReadMedia.as_str().into(),RuntimeGrant::CameraManagementPrepare.as_str().into(),RuntimeGrant::CameraManagementCommit.as_str().into(),RuntimeGrant::CameraSettingPrepare.as_str().into(),RuntimeGrant::CameraSettingCommit.as_str().into()],
        deadline:Some(TimestampNs(60_000_000_000)),priority:1,budgets:budget,privacy_scope:"privacy:test".into(),retention_scope:"retention:test".into(),anchor_universe:ContentDigest::sha256(b"fixture"),generation:1,
    },RegionId::new("region:startup-event")?,RegionKind::Process,budget,TimestampNs(1))?;
    let camera=ContentDigest::sha256(b"fixture camera");let resource=format!("camera:{}",camera.to_text());
    let mut leases=LeaseRegistry::new();let fence=leases.acquire(&resource,authority.region().as_str(),None,TimestampNs(2))?.fence;let leases=RefCell::new(leases);
    let conditions=Preconditions {camera,peer_admission:ContentDigest::sha256(b"fixture peer"),session_generation:1,previous_association:None,previous_clock:None,lease_fence:fence};
    let stream_conditions=intent::Preconditions {camera,peer_admission:conditions.peer_admission,stream_generation:1,previous_settings:None,lease_fence:fence};
    let hello=OperationId::parse("operation:startup-hello")?;let agreement=OperationId::parse("operation:startup-agreement")?;let stream=OperationId::parse("operation:startup-stream")?;
    let event_ops=[OperationId::parse("operation:startup-event-reply")?];
    let runtime=RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx=asupersync::Cx::current().ok_or("missing runtime")?;
        let result=run_owned_async(&mut authority,&mut tree,TaskSpec {task_id:TaskId::new("task:startup-event")?,started_at:TimestampNs(3)},&cx,async |task,cx| {
            let output:Test=async {
                let listener=TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;
                let (startup_done_tx,startup_done_rx)=std::sync::mpsc::channel();
                let peer=std::thread::spawn(move || -> io::Result<()> {
                    let mut socket=std::net::TcpStream::connect_timeout(&address,Duration::from_secs(5))?;socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let mut request=HEAD.as_bytes().to_vec();if !during_accept {request.extend(frame(REQUEST));}request.extend(frame(HELLO));socket.write_all(&request)?;
                    let mut header=Vec::new();let mut byte=[0u8;1];while !header.ends_with(b"\r\n\r\n") {socket.read_exact(&mut byte)?;header.push(byte[0]);if header.len()>4096{return Err(io::Error::other("upgrade limit"));}}
                    if !header.starts_with(b"HTTP/1.1 101 "){return Err(io::Error::other("upgrade refused"));}
                    if !allow {return match socket.read(&mut byte) {Ok(0)=>Ok(()),_=>Err(io::Error::other("denied reply reached peer"))};}
                    let check_event=|bytes:&[u8]| -> io::Result<()> {
                        let parsed=fss_core::json_input::parse(std::str::from_utf8(bytes).map_err(io::Error::other)?).map_err(io::Error::other)?;
                        let fields=parsed.object().ok_or_else(||io::Error::other("reply object"))?;
                        if fields.get("inResponseTo").and_then(|v|v.integer())!=Some(20) || fields.get("payload").and_then(|v|v.object()).and_then(|v|v.get("private")).and_then(|v|v.text())!=Some("fixture") {return Err(io::Error::other("wrong startup event reply"));} Ok(())
                    };
                    if !during_accept {check_event(&receive_binary(&mut socket)?)?;}
                    if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_hello".len()).any(|v|v==b"ubnt_avclient_hello") {return Err(io::Error::other("missing hello"));}
                    if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_paramAgreement".len()).any(|v|v==b"ubnt_avclient_paramAgreement") {return Err(io::Error::other("missing agreement"));}
                    let agreement_id=if during_accept {2} else {3};
                    socket.write_all(&frame(format!("{{\"from\":\"ubnt_avclient\",\"to\":\"UniFiVideo\",\"functionName\":\"ubnt_avclient_paramAgreement\",\"messageId\":8,\"inResponseTo\":{agreement_id}}}").as_bytes()))?;
                    let stream=receive_binary(&mut socket)?;
                    if !stream.windows(b"ChangeVideoSettings".len()).any(|v|v==b"ChangeVideoSettings") {return Err(io::Error::other("missing stream request"));}
                    if during_accept {
                        let message=std::str::from_utf8(&stream).map_err(io::Error::other)?;
                        let destination=message.split_once("tcp://").and_then(|(_,s)|s.split_once('?')).map(|(a,_)|a).ok_or_else(||io::Error::other("missing destination"))?.parse::<SocketAddr>().map_err(io::Error::other)?;
                        if !matches!(destination,SocketAddr::V4(a) if a.ip().is_loopback() && a.port()!=0) {return Err(io::Error::other("invalid destination"));}
                        socket.write_all(&frame(REQUEST))?;check_event(&receive_binary(&mut socket)?)?;
                        let mut media=std::net::TcpStream::connect_timeout(&destination,Duration::from_secs(5))?;
                        media.write_all(b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00")?;
                        // Keep both connections alive until the owner observes
                        // startup. Otherwise controller EOF races media accept.
                        startup_done_rx.recv_timeout(Duration::from_secs(5)).map_err(io::Error::other)?;
                    }
                    Ok(())
                });
                let (socket,_)=timeout(cx.now(),Duration::from_secs(5),listener.accept()).await??;
                let clock=MeteredClock::new(task,cx,TimestampNs(4))?;let io=MeteredIo::with_clock(socket,clock,"fixture:camera",4096)?;
                let controller=Controller::new(Identity::new("FSS","12345678-1234-4abc-9abc-123456789abc","1.20.0")?,1)?;
                let inbox=fss_reference::unifi_direct::events::StartupInbox::new(2,2*fss_reference::unifi_direct::MAX_MESSAGE_BYTES)?;
                let mut session=owner::accept(io,ProtocolPolicy::RequireOffer,&FixtureAdmission,controller,Duration::from_secs(5)).await?;session.bind_startup_events(&inbox)?;
                let guard=Guard {leases:&leases,clock};let echo=EchoGuard {guard:&guard,allow};let approval=FixtureApproval {revoke_stream:None};
                let mut owner=conversation::Owner {cx,task,clock,effects:&mut effects,leases:&leases,approval:&approval,management_authority:&echo,stream_authority:&guard,wall:&FixtureClock};
                let request=StreamStart::new(VideoChannel::Video2,SocketAddrV4::new(Ipv4Addr::LOCALHOST,17551),VideoCodec::H264,AudioCodec::Aac,"0123456789abcdef")?;
                let cfg=conversation::Config {hello:&hello,agreement:&agreement,stream:&stream,time_sync:&[],management:conditions,stream_conditions,request:&request,wait:Duration::from_secs(5)};
                let options=conversation::StartupEventReplies {operations:&event_ops};let mut trace=conversation::StartupEventTrace::default();
                let result=if during_accept {
                    let policy=FixtureMediaAdmission {listen:Cell::new(true),peer:Cell::new(true)};
                    let start=listener::Start {bind:SocketAddrV4::new(Ipv4Addr::LOCALHOST,0),resource:"fixture:camera",admission:&policy,channel:VideoChannel::Video2,video:VideoCodec::H264,audio:AudioCodec::Aac,stream_name:"0123456789abcdef",hello:&hello,agreement:&agreement,stream:&stream,time_sync:&[],management:conditions,stream_conditions,chunk_bytes:4096,max_bytes:100_000,bind_wait:Duration::from_secs(5),conversation_wait:Duration::from_secs(5),accept_wait:Duration::from_secs(5)};
                    let mut start_trace=listener::StartTrace::default();
                    listener::start_before_reply_with_events_tracked(&mut owner,&mut session,&start,Framer::new(FlvLimits::default(),1024*1024)?,recording::Recorder::new(SourceKey {connection:1,generation:1},recording::Limits::default())?,&mut start_trace,None,&options,&mut trace).await.map(|started| {let _=started.pipeline.retire();}).map_err(|e|format!("listener startup stopped: {e:?}"))
                } else {
                    owner.start_dispatched_with_options(&mut session,&cfg,None,Some((&options,&mut trace))).await.map(|_|()).map_err(|e|format!("conversation stopped: {e:?}"))
                };
                if during_accept {startup_done_tx.send(()).map_err(io::Error::other)?;}
                if during_accept {if let Err(error)=&result {return Err(error.clone().into());}}
                assert!(trace.attempted());assert_eq!(trace.attempts().len(),1);assert_eq!(trace.attempts()[0].source(),ContentDigest::sha256(REQUEST));assert!(trace.attempts()[0].dispatch_started());
                assert_eq!(inbox.take().ok_or("event source missing")?.source(),REQUEST);
                if allow {
                    if let Err(error)=result {return Err(error.into());}
                    assert!(matches!(trace.attempts_mut()[0].take_written(),Some(ManagementWrite::Written {..})));
                } else {
                    assert_eq!(result.err().as_deref(),Some("conversation stopped: Effect"));assert_eq!(trace.attempts_mut()[0].take_refusal().ok_or("missing refused permit")?.reason,fss_reference::unifi_direct::receive::Error::Denied);
                }
                let retired=session.retire();if !allow {assert_eq!(retired.event_reply,Some((20,ContentDigest::sha256(REQUEST))));}
                peer.join().map_err(|_|"peer panic")??;Ok(())
            }.await;
            let outcome=if output.is_ok(){TaskOutcome::Indeterminate("fixture effects require reconciliation".into())}else{TaskOutcome::Failed("startup event fixture failed".into())};
            TaskCompletion {output,outcome,completed_at:TimestampNs(59_000_000_000)}
        }).await?;result.receipt?;result.output
    })?;
    assert_eq!(effects.journal().operation(&event_ops[0]).ok_or("event operation missing")?.state,fss_core::EffectState::Committed);
    Ok(())
}

fn management_authority_scenario(revoke_during_write: bool) -> Test {
    use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
    use std::{pin::Pin, task::Context};
    struct Partial<IO> { inner: IO, armed: Rc<Cell<bool>>, revoked: Rc<Cell<bool>> }
    impl<IO: AsyncRead + Unpin> AsyncRead for Partial<IO> {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, out)
        }
    }
    impl<IO: AsyncWrite + Unpin> AsyncWrite for Partial<IO> {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
            let first = self.armed.get() && !self.revoked.get();
            let data = if first { &bytes[..bytes.len().min(1)] } else { bytes };
            let result = Pin::new(&mut self.inner).poll_write(cx, data);
            if first && matches!(&result, Poll::Ready(Ok(n)) if *n > 0) { self.revoked.set(true); }
            result
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.inner).poll_flush(cx) }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.inner).poll_shutdown(cx) }
    }
    struct Revocable<'a> { guard: &'a dyn ManagementAuthority, revoked: Rc<Cell<bool>> }
    impl ManagementAuthority for Revocable<'_> {
        fn permits(&self, mac: [u8; 6], intent: Intent, permit: &CommittedEffect) -> bool {
            !self.revoked.get() && self.guard.permits(mac, intent, permit)
        }
    }
    let path = std::fs::canonicalize(std::env::temp_dir())?
        .join(format!("fss-unifi-task-effect-{}-{revoke_during_write}", std::process::id()));
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
                    if revoke_during_write {socket.read_exact(&mut byte)?;if socket.read(&mut byte)? != 0 {return Err(io::Error::other("write continued after revocation"));}return Ok(());}
                    let mut h=[0_u8;2];socket.read_exact(&mut h)?;if h[0]!=0x82||h[1]&0x80!=0{return Err(io::Error::other("not binary"));}
                    let len=match h[1] { n@0..=125=>usize::from(n),126=>{let mut x=[0_u8;2];socket.read_exact(&mut x)?;usize::from(u16::from_be_bytes(x))},_=>return Err(io::Error::other("frame size"))};
                    if len>4096{return Err(io::Error::other("message bound"));}let mut payload=vec![0;len];socket.read_exact(&mut payload)?;
                    if !payload.windows(b"ubnt_avclient_hello".len()).any(|w|w==b"ubnt_avclient_hello"){return Err(io::Error::other("wrong message"));}
                    Ok(())
                });
                let (socket,_)=timeout(cx.now(),Duration::from_secs(5),listener.accept()).await??;
                let armed=Rc::new(Cell::new(false));let revoked=Rc::new(Cell::new(false));
                let clock=MeteredClock::new(task,cx,TimestampNs(4))?;
                let io=MeteredIo::with_clock(Partial {inner:socket,armed:armed.clone(),revoked:revoked.clone()},clock,"fixture:camera",4096)?;
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
                let base_guard=Guard {leases:&leases,clock};
                let guard=Revocable {guard:&base_guard,revoked:revoked.clone()};
                armed.set(revoke_during_write);
                let result=session.dispatch_management(intent,conditions,permit,&guard,Duration::from_secs(3)).await.map_err(|_|"management dispatch refused")?;
                if revoke_during_write {
                    let ManagementWrite::Indeterminate { controller, .. } = result else {return Err("expected indeterminate management write".into());};
                    assert!(revoked.get());
                    assert_eq!(controller.previous_phase,fss_reference::unifi_direct::Phase::Indeterminate);
                } else {assert!(matches!(result,ManagementWrite::Written {..}));}
                peer.join().map_err(|_|"fixture peer panic")??;
                let retirement=session.retire();
                if !revoke_during_write {assert_eq!(retirement.previous_phase,fss_reference::unifi_direct::Phase::AwaitAgreementPreparation);}
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

#[test]
fn quiesce_requires_separate_authority_before_any_wire_write() -> Test {
    quiesce_authority_scenario(false)
}

#[test]
fn quiesce_revoked_after_partial_write_fences_session() -> Test {
    quiesce_authority_scenario(true)
}

fn quiesce_authority_scenario(revoke_during_write: bool) -> Test {
    use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
    use fss_reference::unifi_direct::{AGREEMENT_DELAY_NS, Dispatch, MessageKind};
    use std::{pin::Pin, task::{Context, Poll}};

    struct Counted<IO> { inner: IO, writes: Rc<Cell<usize>>, armed: Rc<Cell<bool>>, revoked: Rc<Cell<bool>> }
    impl<IO: AsyncRead + Unpin> AsyncRead for Counted<IO> {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, out)
        }
    }
    impl<IO: AsyncWrite + Unpin> AsyncWrite for Counted<IO> {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
            let limited = self.armed.get() && !self.revoked.get();
            let data = if limited { &bytes[..bytes.len().min(1)] } else { bytes };
            let result = Pin::new(&mut self.inner).poll_write(cx, data);
            if matches!(&result, Poll::Ready(Ok(n)) if *n > 0) { self.writes.set(self.writes.get() + 1); }
            if limited && matches!(&result, Poll::Ready(Ok(n)) if *n > 0) { self.revoked.set(true); }
            result
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.inner).poll_flush(cx) }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.inner).poll_shutdown(cx) }
    }
    struct ExplicitQuiesce(Rc<Cell<bool>>);
    impl StreamAuthority for ExplicitQuiesce {
        fn permits(&self, _: [u8; 6], _: intent::Intent, _: &CommittedEffect) -> bool { !self.0.get() }
        fn permits_quiesce(&self, _: [u8; 6], intent: intent::Intent, _: &CommittedEffect) -> bool {
            intent.kind() == MessageKind::QuiesceStream(VideoChannel::Video3)
        }
    }
    struct MotionPolicy(bool);
    impl fss_reference::unifi_direct::receive::MotionAuthority for MotionPolicy {
        fn permits(&self, _: [u8; 6], _: fss_reference::unifi_direct::motion::Intent, _: &CommittedEffect) -> bool { self.0 }
    }

    let path = std::fs::canonicalize(std::env::temp_dir())?.join(format!("fss-unifi-quiesce-effect-{}-{revoke_during_write}", std::process::id()));
    std::fs::create_dir(&path)?;
    let temp = Temp(path);
    let store = FileEffectJournal::create(temp.0.join("journal"), EffectJournalLimits::default(), Arc::new(HostSpoolIo))?;
    let mut effects = EffectCoordinator::with_journal(Box::new(store))?;
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 1_000_000;
    budget.bytes = 1_000_000;
    let (mut authority, mut tree) = AuthorityCx::root(RootAuthoritySpec {
        trace_id: "trace:quiesce-fixture".into(), operation_id: OperationId::parse("operation:quiesce-owner")?,
        principal: "principal:fixture".into(), capabilities: vec![RuntimeGrant::AdapterNet.as_str().into(), RuntimeGrant::CameraSettingPrepare.as_str().into(), RuntimeGrant::CameraSettingCommit.as_str().into(), RuntimeGrant::ReadMedia.as_str().into()],
        deadline: Some(TimestampNs(60_000_000_000)), priority: 1, budgets: budget, privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(), anchor_universe: ContentDigest::sha256(b"fixture"), generation: 1,
    }, RegionId::new("region:quiesce")?, RegionKind::Process, budget, TimestampNs(1))?;
    let camera = ContentDigest::sha256(b"verified fixture camera");
    let resource = format!("camera:{}", camera.to_text());
    let mut leases = LeaseRegistry::new();
    let fence = leases.acquire(&resource, authority.region().as_str(), None, TimestampNs(2))?.fence;
    let leases = RefCell::new(leases);
    let conditions = intent::Preconditions { camera, peer_admission: ContentDigest::sha256(b"fixture admission"), stream_generation: 1, previous_settings: Some(ContentDigest::sha256(b"fixture previous")), lease_fence: fence };
    let operation = OperationId::parse("operation:fixture-quiesce")?;
    let retry_operation = OperationId::parse("operation:fixture-quiesce-after-abandon")?;
    let motion_operation = OperationId::parse("operation:fixture-motion")?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(&mut authority, &mut tree, TaskSpec { task_id: TaskId::new("task:quiesce-fixture")?, started_at: TimestampNs(3) }, &cx, async |task, cx| {
            let output: Test = async {
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let address = listener.local_addr()?;
                let (release_tx, release_rx) = std::sync::mpsc::channel();
                let peer = std::thread::spawn(move || -> io::Result<()> {
                    let mut socket = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                    socket.write_all(HEAD.as_bytes())?;
                    let mut header = Vec::new(); let mut byte = [0_u8; 1];
                    while !header.ends_with(b"\r\n\r\n") { socket.read_exact(&mut byte)?; header.push(byte[0]); if header.len() > 4096 { return Err(io::Error::other("upgrade limit")); } }
                    if !header.starts_with(b"HTTP/1.1 101 ") { return Err(io::Error::other("upgrade refused")); }
                    if revoke_during_write {
                        socket.read_exact(&mut byte)?;
                        if socket.read(&mut byte)? != 0 { return Err(io::Error::other("write continued after revocation")); }
                        return Ok(());
                    }
                    let request = receive_binary(&mut socket)?;
                    if !request.windows(b"file:///dev/null".len()).any(|w| w == b"file:///dev/null") || !request.windows(b"video3".len()).any(|w| w == b"video3") || request.windows(b"video2".len()).any(|w| w == b"video2") { return Err(io::Error::other("unexpected quiesce request")); }
                    socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ChangeVideoSettings","messageId":9,"inResponseTo":4,"payload":{}}"#))?;
                    let motion_request = receive_binary(&mut socket)?;
                    if !motion_request.windows(b"ChangeSmartMotionSettings".len()).any(|w| w == b"ChangeSmartMotionSettings")
                        || !motion_request.windows(b"001122AABBCC".len()).any(|w| w == b"001122AABBCC")
                        || !motion_request.windows(b"\"enable\":true".len()).any(|w| w == b"\"enable\":true") {
                        return Err(io::Error::other("unexpected motion request"));
                    }
                    socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ChangeSmartMotionSettings","messageId":10,"inResponseTo":5,"payload":{"success":true}}"#))?;
                    release_rx.recv_timeout(Duration::from_secs(5)).map_err(io::Error::other)?;
                    Ok(())
                });
                let (socket, _) = timeout(cx.now(), Duration::from_secs(5), listener.accept()).await??;
                let writes = Rc::new(Cell::new(0));
                let armed = Rc::new(Cell::new(false));
                let revoked = Rc::new(Cell::new(false));
                let clock = MeteredClock::new(task, cx, TimestampNs(4))?;
                let io = MeteredIo::with_clock(Counted { inner: socket, writes: writes.clone(), armed: armed.clone(), revoked: revoked.clone() }, clock, "fixture:camera", 4096)?;
                let mut controller = Controller::new(Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?, 1)?;
                controller.observe(HELLO)?;
                controller.prepare_hello("2026-11-05T10:00:00.000Z")?;
                controller.finish_dispatch(1, Dispatch::Written)?;
                controller.prepare_agreement("2026-11-05T10:00:00.000Z", AGREEMENT_DELAY_NS)?;
                controller.finish_dispatch(2, Dispatch::Written)?;
                controller.observe(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_paramAgreement","messageId":8,"inResponseTo":2,"payload":{}}"#)?;
                let session = owner::accept(io, ProtocolPolicy::RequireOffer, &FixtureAdmission, controller, Duration::from_secs(5)).await?;
                let media_listener = TcpListener::bind("127.0.0.1:0").await?;
                let media_peer = std::net::TcpStream::connect_timeout(&media_listener.local_addr()?, Duration::from_secs(5))?;
                let (media_socket, _) = timeout(cx.now(), Duration::from_secs(5), media_listener.accept()).await??;
                let ingress = TcpIngress::new(media_socket, "fixture:camera", 4096, 1_000_000)?;
                let framer = Framer::new(FlvLimits::default(), 1024 * 1024)?;
                let recorder = recording::Recorder::new(SourceKey { connection: 1, generation: 1 }, recording::Limits::default())?;
                let pipeline = pipeline::Pipeline::new(DirectIngress::new(ingress, framer), recorder);
                let management = Preconditions { camera, peer_admission: conditions.peer_admission, session_generation: 1, previous_association: None, previous_clock: None, lease_fence: fence };
                let mut supervisor = supervisor::Supervisor::new(session, pipeline, management);
                let guard = Guard { leases: &leases, clock };
                let explicit = ExplicitQuiesce(revoked.clone());
                let policy = FixtureApproval { revoke_stream: None };
                let wall = FixtureClock;
                let mut runner = conversation::Owner { cx, task, clock, effects: &mut effects, leases: &leases, approval: &policy, management_authority: &guard, stream_authority: &guard, wall: &wall };
                let wrong = intent::Preconditions { camera: ContentDigest::sha256(b"wrong camera"), ..conditions };
                assert!(matches!(supervisor.prepare_quiesce(&runner, VideoChannel::Video3, AudioCodec::Aac, "2026-11-05T10:00:00.000Z", wrong), Err(fss_reference::unifi_direct::receive::Error::Denied)));
                let intent = supervisor.prepare_quiesce(&runner, VideoChannel::Video3, AudioCodec::Aac, "2026-11-05T10:00:00.000Z", conditions)?;
                let prepared = task.prepare_effect(cx, &mut *runner.effects, &mut leases.borrow_mut(), PrepareSpec { operation: &operation, idempotency_key: IdempotencyKey::parse(operation.as_str())?, request_digest: intent.request_digest(), precondition_digest: intent.precondition_digest(), resource: &resource, fence, prepare_grant: RuntimeGrant::CameraSettingPrepare, commit_grant: RuntimeGrant::CameraSettingCommit, terminal_predicate: "independent observation or reconciliation" }, clock.now()?)?;
                let approval = CommitApproval { prepared_digest: prepared.digest(), current_precondition_digest: intent.precondition_digest() };
                let permit = task.commit_effect(cx, &mut *runner.effects, &mut leases.borrow_mut(), prepared, clock.now()?, approval)?;
                assert!(StreamAuthority::permits(&guard, [0, 0x11, 0x22, 0xaa, 0xbb, 0xcc], intent, &permit));
                assert!(!StreamAuthority::permits_quiesce(&guard, [0, 0x11, 0x22, 0xaa, 0xbb, 0xcc], intent, &permit));
                let before = writes.get();
                let refusal = supervisor.dispatch_quiesce(&runner, intent, conditions, permit, Duration::from_secs(5)).await.err().ok_or("default quiesce authority unexpectedly allowed")?;
                assert!(matches!(refusal.reason, fss_reference::unifi_direct::receive::Error::Denied));
                assert_eq!(writes.get(), before);
                let _unresolved_first_permit = refusal.permit;
                let abandoned = supervisor.abandon_prepared_stream(&runner, intent)?;
                assert_eq!((abandoned.id, abandoned.kind), (3, MessageKind::QuiesceStream(VideoChannel::Video3)));
                let retry_intent = supervisor.prepare_quiesce(&runner, VideoChannel::Video3, AudioCodec::Aac, "2026-11-05T10:00:00.000Z", conditions)?;
                assert_eq!(retry_intent.message_id(), 4);
                let retry_prepared = task.prepare_effect(cx, &mut *runner.effects, &mut leases.borrow_mut(), PrepareSpec { operation: &retry_operation, idempotency_key: IdempotencyKey::parse(retry_operation.as_str())?, request_digest: retry_intent.request_digest(), precondition_digest: retry_intent.precondition_digest(), resource: &resource, fence, prepare_grant: RuntimeGrant::CameraSettingPrepare, commit_grant: RuntimeGrant::CameraSettingCommit, terminal_predicate: "independent observation or reconciliation" }, clock.now()?)?;
                let retry_approval = CommitApproval { prepared_digest: retry_prepared.digest(), current_precondition_digest: retry_intent.precondition_digest() };
                let retry_permit = task.commit_effect(cx, &mut *runner.effects, &mut leases.borrow_mut(), retry_prepared, clock.now()?, retry_approval)?;
                runner.stream_authority = &explicit;
                armed.set(revoke_during_write);
                let sent = supervisor.dispatch_quiesce(&runner, retry_intent, conditions, retry_permit, Duration::from_secs(5)).await.map_err(|_| "explicit quiesce refused")?;
                if revoke_during_write {
                    assert!(matches!(sent, fss_reference::unifi_direct::receive::StreamWrite::Indeterminate { .. }));
                    assert!(revoked.get());
                    assert_eq!(writes.get(), before + 1);
                    let retirement = supervisor.retire();
                    assert_eq!(retirement.controller.prepared, Some((4, MessageKind::QuiesceStream(VideoChannel::Video3))));
                    peer.join().map_err(|_| "fixture peer panic")??;
                    drop(media_peer);
                    return Ok(());
                }
                assert!(matches!(sent, fss_reference::unifi_direct::receive::StreamWrite::Written { .. }));
                assert!(writes.get() > before);
                let reply = supervisor.step(&mut runner, &operation, Duration::from_secs(5)).await;
                if !matches!(reply, supervisor::Step::Observation(Observation::StreamSettingsReply { kind: MessageKind::QuiesceStream(VideoChannel::Video3), .. })) {
                    return Err(format!("unexpected supervisor quiesce reply: {reply:?}").into());
                }
                let motion_conditions = fss_reference::unifi_direct::motion::Preconditions { camera, peer_admission: conditions.peer_admission, session_generation: 1, previous_motion: None, lease_fence: fence };
                let wrong_motion = fss_reference::unifi_direct::motion::Preconditions { session_generation: 2, ..motion_conditions };
                assert!(matches!(supervisor.prepare_motion(&runner, true, "2026-11-05T10:00:00.000Z", wrong_motion), Err(fss_reference::unifi_direct::receive::Error::Denied)));
                let motion_intent = supervisor.prepare_motion(&runner, true, "2026-11-05T10:00:00.000Z", motion_conditions)?;
                assert_eq!(motion_intent.message_id(), 5);
                let prepared = task.prepare_effect(cx, &mut *runner.effects, &mut leases.borrow_mut(), PrepareSpec { operation: &motion_operation, idempotency_key: IdempotencyKey::parse(motion_operation.as_str())?, request_digest: motion_intent.request_digest(), precondition_digest: motion_intent.precondition_digest(), resource: &resource, fence, prepare_grant: RuntimeGrant::CameraSettingPrepare, commit_grant: RuntimeGrant::CameraSettingCommit, terminal_predicate: "independent motion observation or reconciliation" }, clock.now()?)?;
                let approval = CommitApproval { prepared_digest: prepared.digest(), current_precondition_digest: motion_intent.precondition_digest() };
                let permit = task.commit_effect(cx, &mut *runner.effects, &mut leases.borrow_mut(), prepared, clock.now()?, approval)?;
                let before_motion = writes.get();
                let refusal = supervisor.dispatch_motion(&runner, motion_intent, motion_conditions, permit, &MotionPolicy(false), Duration::from_secs(5)).await.err().ok_or("motion denial missing")?;
                assert!(matches!(refusal.reason, fss_reference::unifi_direct::receive::Error::Denied));
                assert_eq!(writes.get(), before_motion);
                let sent = supervisor.dispatch_motion(&runner, motion_intent, motion_conditions, refusal.permit, &MotionPolicy(true), Duration::from_secs(5)).await.map_err(|_| "motion dispatch refused")?;
                assert!(matches!(sent, fss_reference::unifi_direct::receive::MotionWrite::Written { .. }));
                let reply = supervisor.step(&mut runner, &motion_operation, Duration::from_secs(5)).await;
                if !matches!(reply, supervisor::Step::Observation(Observation::MotionSettingsReply { request_id: 5, enabled: true, success: Some(true), .. })) {
                    return Err(format!("unexpected motion reply: {reply:?}").into());
                }
                release_tx.send(()).map_err(io::Error::other)?;
                peer.join().map_err(|_| "fixture peer panic")??;
                let _retirement = supervisor.retire();
                drop(media_peer);
                Ok(())
            }.await;
            let outcome = if output.is_ok() { TaskOutcome::Indeterminate("fixture effect still needs reconciliation".into()) } else { TaskOutcome::Failed("quiesce fixture failed".into()) };
            TaskCompletion { output, outcome, completed_at: TimestampNs(59_000_000_000) }
        }).await?;
        result.receipt?; result.output
    })?;
    assert_eq!(effects.journal().operation(&operation).ok_or("missing effect")?.state, fss_core::EffectState::Committed);
    assert_eq!(effects.journal().operation(&retry_operation).ok_or("missing retry effect")?.state, fss_core::EffectState::Committed);
    if !revoke_during_write {
        assert_eq!(effects.journal().operation(&motion_operation).ok_or("missing motion effect")?.state, fss_core::EffectState::Committed);
    }
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
    let mut result = b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    result.extend(flv_tag(0, &config));
    for index in 0..7 {
        // Synthetic AAC bodies exercise source custody and muxing only; they
        // are not claimed to be decodable audio or synchronized with video.
        let mut audio=flv_tag(index as u32 * 64,&[0xaf,1,2]);
        audio[0]=8;
        result.extend(audio);
        let nal = pictures[index % 3];
        let mut payload = vec![0x17, 1, 0, 0, 0];
        payload.extend_from_slice(&u32::try_from(nal.len())?.to_be_bytes());
        payload.extend_from_slice(nal);
        result.extend(flv_tag(index as u32 * 40, &payload));
    }
    Ok(result)
}

#[test]
fn startup_motion_is_dispatched_and_reply_is_retained() -> Test { startup_motion_scenario(true) }

#[test]
fn startup_motion_denial_prevents_stream_and_retains_permit() -> Test { startup_motion_scenario(false) }

fn startup_motion_scenario(allow_motion: bool) -> Test {
    use fss_reference::unifi_direct::{motion, receive::{MotionAuthority, MotionWrite}};
    struct Policy(bool);
    impl MotionAuthority for Policy {
        fn permits(&self, _: [u8; 6], _: motion::Intent, _: &CommittedEffect) -> bool { self.0 }
    }
    let path = std::fs::canonicalize(std::env::temp_dir())?.join(format!("fss-motion-startup-{}-{allow_motion}", std::process::id()));
    std::fs::create_dir(&path)?;
    let temp=Temp(path);
    let store=FileEffectJournal::create(temp.0.join("journal"),EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
    let mut effects=EffectCoordinator::with_journal(Box::new(store))?;
    let mut budget=BudgetVector::ZERO;budget.network_bytes=1_000_000;budget.bytes=1_000_000;
    let (mut authority,mut tree)=AuthorityCx::root(RootAuthoritySpec {
        trace_id:"trace:motion-startup".into(),operation_id:OperationId::parse("operation:motion-startup-owner")?,principal:"principal:fixture".into(),
        capabilities:vec![RuntimeGrant::AdapterNet.as_str().into(),RuntimeGrant::CameraManagementPrepare.as_str().into(),RuntimeGrant::CameraManagementCommit.as_str().into(),RuntimeGrant::CameraSettingPrepare.as_str().into(),RuntimeGrant::CameraSettingCommit.as_str().into(),RuntimeGrant::ReadMedia.as_str().into()],
        deadline:Some(TimestampNs(60_000_000_000)),priority:1,budgets:budget,privacy_scope:"privacy:test".into(),retention_scope:"retention:test".into(),anchor_universe:ContentDigest::sha256(b"fixture"),generation:1,
    },RegionId::new("region:motion-startup")?,RegionKind::Process,budget,TimestampNs(1))?;
    let camera=ContentDigest::sha256(b"fixture camera");let resource=format!("camera:{}",camera.to_text());
    let mut leases=LeaseRegistry::new();let fence=leases.acquire(&resource,authority.region().as_str(),None,TimestampNs(2))?.fence;
    let leases=RefCell::new(leases);
    let management=Preconditions {camera,peer_admission:ContentDigest::sha256(b"fixture admission"),session_generation:1,previous_association:None,previous_clock:None,lease_fence:fence};
    let stream_conditions=intent::Preconditions {camera,peer_admission:management.peer_admission,stream_generation:1,previous_settings:None,lease_fence:fence};
    let motion_conditions=motion::Preconditions {camera,peer_admission:management.peer_admission,session_generation:1,previous_motion:None,lease_fence:fence};
    let operations=[OperationId::parse("operation:motion-start-hello")?,OperationId::parse("operation:motion-start-agreement")?,OperationId::parse("operation:motion-start-stream")?,OperationId::parse("operation:motion-start-motion")?];
    let runtime=RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx=asupersync::Cx::current().ok_or("missing runtime")?;
        let result=run_owned_async(&mut authority,&mut tree,TaskSpec {task_id:TaskId::new("task:motion-startup")?,started_at:TimestampNs(3)},&cx,async |task,cx| {
            let output:Test=async {
                let listener=TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;
                let (release_tx,release_rx)=std::sync::mpsc::channel();
                let peer=std::thread::spawn(move || -> io::Result<()> {
                    let mut socket=std::net::TcpStream::connect_timeout(&address,Duration::from_secs(5))?;socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let mut request=HEAD.as_bytes().to_vec();request.extend(frame(HELLO));socket.write_all(&request)?;
                    let mut header=Vec::new();let mut byte=[0_u8;1];while !header.ends_with(b"\r\n\r\n") {socket.read_exact(&mut byte)?;header.push(byte[0]);if header.len()>4096{return Err(io::Error::other("upgrade limit"));}}
                    if !header.starts_with(b"HTTP/1.1 101 "){return Err(io::Error::other("upgrade refused"));}
                    if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_hello".len()).any(|w|w==b"ubnt_avclient_hello"){return Err(io::Error::other("hello missing"));}
                    if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_paramAgreement".len()).any(|w|w==b"ubnt_avclient_paramAgreement"){return Err(io::Error::other("agreement missing"));}
                    socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_paramAgreement","messageId":8,"inResponseTo":2}"#))?;
                    if !allow_motion { return match socket.read(&mut byte) {Ok(0)=>Ok(()),_=>Err(io::Error::other("denied motion wrote bytes"))}; }
                    let motion=receive_binary(&mut socket)?;
                    if !motion.windows(b"ChangeSmartMotionSettings".len()).any(|w|w==b"ChangeSmartMotionSettings"){return Err(io::Error::other("motion missing"));}
                    let stream=receive_binary(&mut socket)?;
                    let message=std::str::from_utf8(&stream).map_err(io::Error::other)?;
                    let destination=message.split_once("tcp://").and_then(|(_,s)|s.split_once('?')).map(|(a,_)|a).ok_or_else(||io::Error::other("missing destination"))?;
                    let destination:SocketAddr=destination.parse().map_err(io::Error::other)?;
                    socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ChangeSmartMotionSettings","messageId":9,"inResponseTo":3,"payload":{"success":true}}"#))?;
                    socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ChangeVideoSettings","messageId":10,"inResponseTo":4}"#))?;
                    let mut media=std::net::TcpStream::connect_timeout(&destination,Duration::from_secs(5))?;
                    media.write_all(b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00")?;
                    release_rx.recv_timeout(Duration::from_secs(5)).map_err(io::Error::other)?;Ok(())
                });
                let (socket,_)=timeout(cx.now(),Duration::from_secs(5),listener.accept()).await??;
                let clock=MeteredClock::new(task,cx,TimestampNs(4))?;let io=MeteredIo::with_clock(socket,clock,"fixture:camera",4096)?;
                let controller=Controller::new(Identity::new("FSS","12345678-1234-4abc-9abc-123456789abc","1.20.0")?,1)?;
                let mut session=owner::accept(io,ProtocolPolicy::RequireOffer,&FixtureAdmission,controller,Duration::from_secs(5)).await?;
                let guard=Guard {leases:&leases,clock};let approval=FixtureApproval {revoke_stream:None};let motion_policy=Policy(allow_motion);
                let mut owner=conversation::Owner {cx,task,clock,effects:&mut effects,leases:&leases,approval:&approval,management_authority:&guard,stream_authority:&guard,wall:&FixtureClock};
                let media_policy=FixtureMediaAdmission {listen:Cell::new(true),peer:Cell::new(true)};
                let start=listener::Start {bind:SocketAddrV4::new(Ipv4Addr::LOCALHOST,0),resource:"fixture:camera",admission:&media_policy,channel:VideoChannel::Video2,video:VideoCodec::H264,audio:AudioCodec::Aac,stream_name:"0123456789abcdef",hello:&operations[0],agreement:&operations[1],stream:&operations[2],time_sync:&[],management,stream_conditions,chunk_bytes:4096,max_bytes:100_000,bind_wait:Duration::from_secs(5),conversation_wait:Duration::from_secs(5),accept_wait:Duration::from_secs(5)};
                let motion=conversation::StartupMotion {operation:&operations[3],conditions:motion_conditions,enabled:true,authority:&motion_policy};
                let mut trace=listener::StartTrace::default();let mut motion_trace=conversation::StartupMotionTrace::default();
                let result=listener::start_before_reply_with_motion_tracked(&mut owner,&mut session,&start,Framer::new(FlvLimits::default(),1024*1024)?,recording::Recorder::new(SourceKey {connection:1,generation:1},recording::Limits::default())?,&mut trace,&motion,&mut motion_trace).await;
                assert!(motion_trace.attempted());assert_eq!(motion_trace.intent().ok_or("motion intent missing")?.message_id(),3);assert!(motion_trace.dispatch_started());
                if !allow_motion {
                    assert!(matches!(result,Err(listener::StartError::Conversation(conversation::Error::Effect))));
                    assert!(motion_trace.refusal().is_some());assert!(trace.dispatched().is_none());
                    let _=session.retire();peer.join().map_err(|_|"peer panic")??;return Ok(());
                }
                let started=result?;assert!(matches!(motion_trace.written(),Some(MotionWrite::Written {..})));
                let mut saw_motion=started.observations_during_accept.iter().any(|o|matches!(o,Observation::MotionSettingsReply {request_id:3,enabled:true,..}));
                let mut saw_stream=started.observations_during_accept.iter().any(|o|matches!(o,Observation::StreamSettingsReply {request_id:4,..}));
                while !saw_motion || !saw_stream {
                    match session.next(Duration::from_secs(5)).await? {
                        Step::Observation(Observation::MotionSettingsReply {request_id:3,enabled:true,..})=>saw_motion=true,
                        Step::Observation(Observation::StreamSettingsReply {request_id:4,..})=>saw_stream=true,
                        other=>return Err(format!("unexpected startup observation: {other:?}").into()),
                    }
                }
                let mut supervisor=supervisor::Supervisor::new(session,started.pipeline,management);
                let mut header_received=false;
                for _ in 0..3 {
                    match supervisor.step(&mut owner,&operations[3],Duration::from_secs(5)).await {
                        supervisor::Step::Media(pipeline::Step::Progress {..})=>(),
                        supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {record,..}))=>{
                            assert_eq!(record.bytes(),b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00");header_received=true;break;
                        }
                        other=>return Err(format!("unexpected initial media step: {other:?}").into()),
                    }
                }
                if !header_received {return Err("media header not received".into());}
                release_tx.send(()).map_err(io::Error::other)?;peer.join().map_err(|_|"peer panic")??;let _=supervisor.retire();Ok(())
            }.await;
            let outcome=if output.is_ok(){TaskOutcome::Indeterminate("startup effects require reconciliation".into())}else{TaskOutcome::Failed("motion startup fixture failed".into())};
            TaskCompletion {output,outcome,completed_at:TimestampNs(59_000_000_000)}
        }).await?;result.receipt?;result.output
    })?;
    assert_eq!(effects.journal().operation(&operations[3]).ok_or("motion effect missing")?.state,fss_core::EffectState::Committed);
    assert_eq!(effects.journal().operation(&operations[2]).is_some(),allow_motion);
    Ok(())
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

fn conversation_scenario(revoke_stream: bool, revoke_after_start: bool, revoke_audio_pending: bool, reply_after_media: bool, never_reply: bool, early_reply: bool) -> Test {
    conversation_scenario_with_stop(revoke_stream, revoke_after_start, revoke_audio_pending, reply_after_media, never_reply, early_reply, 0)
}

fn conversation_scenario_with_stop(revoke_stream: bool, revoke_after_start: bool, revoke_audio_pending: bool, reply_after_media: bool, never_reply: bool, early_reply: bool, stop_mode: u8) -> Test {
    conversation_scenario_with_event(revoke_stream, revoke_after_start, revoke_audio_pending, reply_after_media, never_reply, early_reply, stop_mode, false)
}

fn conversation_scenario_with_event(revoke_stream: bool, revoke_after_start: bool, revoke_audio_pending: bool, reply_after_media: bool, never_reply: bool, early_reply: bool, stop_mode: u8, emit_event: bool) -> Test {
    conversation_scenario_with_archive_guard(revoke_stream, revoke_after_start, revoke_audio_pending, reply_after_media, never_reply, early_reply, stop_mode, emit_event, false)
}

fn conversation_scenario_with_archive_guard(revoke_stream: bool, revoke_after_start: bool, revoke_audio_pending: bool, reply_after_media: bool, never_reply: bool, early_reply: bool, stop_mode: u8, emit_event: bool, archive_guard: bool) -> Test {
    conversation_scenario_with_worker_guard(revoke_stream, revoke_after_start, revoke_audio_pending, reply_after_media, never_reply, early_reply, stop_mode, emit_event, archive_guard, false, false)
}

fn conversation_scenario_with_worker_guard(revoke_stream: bool, revoke_after_start: bool, revoke_audio_pending: bool, reply_after_media: bool, never_reply: bool, early_reply: bool, stop_mode: u8, emit_event: bool, archive_guard: bool, async_archive: bool, cancel_archive: bool) -> Test {
    let path = std::fs::canonicalize(std::env::temp_dir())?.join(format!(
        "fss-unifi-task-conversation-{}-{revoke_stream}-{revoke_after_start}-{revoke_audio_pending}-{reply_after_media}-{never_reply}-{early_reply}",
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
                RuntimeGrant::ObjectStage.as_str().into(),
                RuntimeGrant::ObjectPublish.as_str().into(),
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
        OperationId::parse("operation:conversation-accept-time-sync")?,
        OperationId::parse("operation:conversation-accept-time-sync-2")?,
        OperationId::parse("operation:conversation-later-time-sync")?,
        OperationId::parse("operation:guard-capture-time-sync")?,
        OperationId::parse("operation:guard-archive-time-sync")?,
    ];
    let runtime = RuntimeBuilder::current_thread().blocking_threads(1, 1).build()?;
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
                let mut wire=media_fixture()?;
                if revoke_audio_pending {
                    let mut audio=flv_tag(0,&[0xaf,0,0x14,0x08]);
                    audio[0]=8;
                    drop(wire.splice(13..13,audio));
                }
                let expected=wire.clone();
                let (media_seen_tx,media_seen_rx)=std::sync::mpsc::channel();
                let (ready_to_cancel_tx,ready_to_cancel_rx)=std::sync::mpsc::channel();
                let (control_probe_tx,control_probe_rx)=std::sync::mpsc::channel();
                let peer=std::thread::spawn(move || -> io::Result<()> {
                    let mut socket=std::net::TcpStream::connect_timeout(&address,Duration::from_secs(5))?;
                    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let mut request=HEAD.as_bytes().to_vec();
                    if emit_event {request.extend(frame(EVENT));}
                    request.extend(frame(HELLO)); socket.write_all(&request)?;
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
                    if reply_after_media {
                        socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":12}"#))?;
                        if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_timeSync".len()).any(|w|w==b"ubnt_avclient_timeSync") { return Err(io::Error::other("missing pre-media time-sync reply")); }
                        if early_reply {
                            socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ChangeVideoSettings","messageId":9,"inResponseTo":4}"#))?;
                            socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":13}"#))?;
                            if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_timeSync".len()).any(|w|w==b"ubnt_avclient_timeSync") { return Err(io::Error::other("missing second pre-media time-sync reply")); }
                            if stop_mode == 1 { return Ok(()); }
                            if stop_mode == 2 {
                                ready_to_cancel_tx.send(()).map_err(io::Error::other)?;
                                // Wake a pending controller read after publishing the signal.
                                socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"fixture_notify","messageId":14}"#))?;
                                let mut byte=[0u8;1];
                                return match socket.read(&mut byte) { Ok(0)=>Ok(()), _=>Err(io::Error::other("cancelled controller did not close")) };
                            }
                        }
                    }
                    if !reply_after_media {
                        socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ChangeVideoSettings","messageId":9,"inResponseTo":4}"#))?;
                    }
                    let mut media=std::net::TcpStream::connect_timeout(&destination,Duration::from_secs(5))?;
                    let split=if reply_after_media {1} else {wire.len().min(100)};
                    media.write_all(&wire[..split])?;
                    if reply_after_media {
                        media_seen_rx.recv_timeout(Duration::from_secs(5)).map_err(io::Error::other)?;
                        if !never_reply && !early_reply {
                            socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ChangeVideoSettings","messageId":9,"inResponseTo":4}"#))?;
                        }
                    }
                    if revoke_after_start || revoke_audio_pending {
                        let mut last=[0u8;1];
                        return match socket.read(&mut last) { Ok(0)=>Ok(()), _=>Err(io::Error::other("revoked controller did not retire")) };
                    }
                    if emit_event { socket.write_all(&frame(EVENT))?; }
                    socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":11}"#))?;
                    if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_timeSync".len()).any(|w|w==b"ubnt_avclient_timeSync") { return Err(io::Error::other("missing post-start time-sync reply")); }
                    media.write_all(&wire[split..])?;
                    drop(media);
                    if archive_guard {
                        for id in [14_u32,15] {
                            control_probe_rx.recv_timeout(Duration::from_secs(5)).map_err(io::Error::other)?;
                            let message=format!(r#"{{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":{id}}}"#);
                            socket.write_all(&frame(message.as_bytes()))?;
                            if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_timeSync".len()).any(|w|w==b"ubnt_avclient_timeSync") {
                                return Err(io::Error::other("missing guarded time-sync reply"));
                            }
                        }
                    }
                    let mut last=[0u8;1];
                    match socket.read(&mut last) { Ok(0)=>Ok(()), _=>Err(io::Error::other("controller did not retire")) }
                });
                let startup_events=fss_reference::unifi_direct::events::StartupInbox::new(4,4*fss_reference::unifi_direct::MAX_MESSAGE_BYTES)?;
                let (io,gate)=controller_listener.accept(4096,Duration::from_secs(5)).await?;
                let controller=Controller::new(Identity::new("FSS","12345678-1234-4abc-9abc-123456789abc","1.20.0")?,1)?;
                let mut session=owner::accept_guarded(io,ProtocolPolicy::RequireOffer,&FixtureAdmission,gate,controller,Duration::from_secs(5)).await?;
                if emit_event {session.bind_startup_events(&startup_events)?;}
                let guard=Guard { leases:&leases, clock };
                let request=StreamStart::new(VideoChannel::Video2,SocketAddrV4::new(Ipv4Addr::LOCALHOST,17551),VideoCodec::H264,AudioCodec::Aac,"0123456789abcdef")?;
                let config=conversation::Config { hello:&operations[0], agreement:&operations[1], stream:&operations[2], time_sync:&operations[3..6], management:conditions, stream_conditions, request:&request, wait:Duration::from_secs(5) };
                let approval=FixtureApproval {revoke_stream:revoke_stream.then_some(&policy.listen)};
                let other_clock=MeteredClock::new(task,cx,TimestampNs(5))?;
                let mut wrong_owner=conversation::Owner { cx, task, clock:other_clock, effects:&mut effects, leases:&leases, approval:&approval, management_authority:&guard, stream_authority:&guard, wall:&FixtureClock };
                assert_eq!(wrong_owner.start(&mut session,&config).await,Err(conversation::Error::Configuration));
                let mut owner=conversation::Owner { cx, task, clock, effects:&mut effects, leases:&leases, approval:&approval, management_authority:&guard, stream_authority:&guard, wall:&FixtureClock };
                let duplicate=conversation::Config { agreement:&operations[0], ..config };
                assert_eq!(owner.start(&mut session,&duplicate).await,Err(conversation::Error::Configuration));
                let mismatched=conversation::Config { stream_conditions:intent::Preconditions { lease_fence:fence+1, ..stream_conditions }, ..config };
                assert_eq!(owner.start(&mut session,&mismatched).await,Err(conversation::Error::Configuration));
                let start=listener::Start {bind,resource:"fixture:camera",admission:&policy,channel:VideoChannel::Video2,video:VideoCodec::H264,audio:AudioCodec::Aac,stream_name:"0123456789abcdef",hello:&operations[0],agreement:&operations[1],stream:&operations[2],time_sync:&operations[3..6],management:conditions,stream_conditions,chunk_bytes:4096,max_bytes:u64::try_from(expected.len())?+1,bind_wait:Duration::from_secs(5),conversation_wait:Duration::from_secs(5),accept_wait:Duration::from_secs(5)};
                let invalid=listener::Start {max_bytes:0,..start};
                let framer=Framer::new(FlvLimits::default(),1024*1024)?;
                let recorder=recording::Recorder::new(SourceKey {connection:5,generation:1},recording::Limits::default())?;
                assert!(matches!(listener::start(&mut owner,&mut session,&invalid,framer,recorder).await,Err(listener::StartError::Listener(listener::Error::Configuration))));
                let framer=Framer::new(FlvLimits::default(),1024*1024)?;
                let recorder=recording::Recorder::new(SourceKey {connection:1,generation:1},recording::Limits::default())?;
                let started=if reply_after_media {
                    let mut trace=listener::StartTrace::default();
                    let future=listener::start_before_reply_tracked(&mut owner,&mut session,&start,framer,recorder,&mut trace);
                    let result=if stop_mode==2 {
                        let mut future=Box::pin(future);
                        timeout(cx.now(),Duration::from_secs(5),poll_fn(|context| {
                            if let Poll::Ready(result)=future.as_mut().poll(context) { return Poll::Ready(Some(result)); }
                            match ready_to_cancel_rx.try_recv() {
                                Ok(())=>Poll::Ready(None),
                                Err(std::sync::mpsc::TryRecvError::Empty)=>Poll::Pending,
                                Err(std::sync::mpsc::TryRecvError::Disconnected)=>Poll::Ready(None),
                            }
                        })).await?
                    } else { Some(future.await) };
                    if stop_mode != 0 {
                        if stop_mode == 1 { assert!(matches!(result,Some(Err(listener::StartError::Conversation(conversation::Error::SessionRetired {..}))))); }
                        else { assert!(result.is_none()); }
                        assert!(trace.attempted());
                        assert!(trace.dispatched().is_some());
                        assert_eq!(trace.clock_requests(),2);
                        let locally_written=trace.clock_replies_written();
                        if stop_mode==1 {assert_eq!(locally_written,2);} else {assert!(matches!(locally_written,1|2));}
                        assert!(matches!(trace.observations().first(),Some(Observation::StreamSettingsReply {request_id:4,..})));
                        let retry_framer=Framer::new(FlvLimits::default(),1024*1024)?;
                        let retry_recorder=recording::Recorder::new(SourceKey {connection:9,generation:1},recording::Limits::default())?;
                        assert!(matches!(listener::start_before_reply_tracked(&mut owner,&mut session,&start,retry_framer,retry_recorder,&mut trace).await,Err(listener::StartError::Listener(listener::Error::Configuration))));
                        let retired = session.retire();
                        if stop_mode==2 && locally_written==1 {
                            assert_eq!(retired.previous_phase,fss_reference::unifi_direct::Phase::Indeterminate);
                            assert_eq!(retired.time_sync_request_id,Some(13));
                            assert!(matches!(retired.prepared,Some((_,fss_reference::unifi_direct::MessageKind::TimeSyncReply))));
                        }
                        if emit_event {
                            let event=startup_events.take().ok_or("missing retained startup event")?;
                            assert_eq!(event.source(),EVENT);
                            assert!(startup_events.is_empty());
                        }
                        peer.join().map_err(|_|"fixture peer panic")??;
                        return Ok(());
                    }
                    let started=result.ok_or("unexpected timeout")??;
                    assert!(trace.dispatched().is_some());
                    assert_eq!(trace.clock_requests(),if early_reply {2} else {1});
                    assert_eq!(trace.clock_replies_written(),if early_reply {2} else {1});
                    assert_eq!(started.dispatched.time_syncs,1);
                    assert_eq!(started.time_syncs_during_accept,if early_reply {2} else {1});
                    if early_reply {
                        assert!(matches!(started.observations_during_accept.as_slice(),[Observation::StreamSettingsReply {request_id:4,..}]));
                    } else {
                        assert!(started.observations_during_accept.is_empty());
                    }
                    Ok(started.pipeline)
                } else {
                    listener::start(&mut owner,&mut session,&start,framer,recorder).await.map(|started| {
                        assert_eq!(started.reply,conversation::Reply { status_code:None, success:None, time_syncs:1 });
                        started.pipeline
                    })
                };
                if revoke_stream {
                    assert!(matches!(started,Err(listener::StartError::Conversation(conversation::Error::Effect))));
                    let retired=session.retire();
                    assert!(retired.prepared.is_some());
                    peer.join().map_err(|_|"fixture peer panic")??;
                    return Ok(());
                }
                let pipeline=started?;
                let mut supervisor=supervisor::Supervisor::new(session,pipeline,conditions);
                if reply_after_media {
                    match supervisor.step(&mut owner,&operations[6],Duration::from_secs(5)).await {
                        supervisor::Step::Media(pipeline::Step::Progress {appended:1})=>(),
                        other=>return Err(format!("expected media before the withheld reply: {other:?}").into()),
                    }
                    media_seen_tx.send(()).map_err(io::Error::other)?;
                }
                let audio_bytes=[0x14,0x08];
                let audio_config=fss_packet::extended_flv::aac::Configuration::parse_explicit(&audio_bytes)?;
                assert!(supervisor.av_initialization(&audio_config)?.is_none());
                if revoke_audio_pending {
                    supervisor.enable_audio_tracking()?;
                    let mut retained=Vec::new();
                    let mut pending=false;
                    for _ in 0..64 {
                        match supervisor.step(&mut owner,&operations[6],Duration::from_secs(5)).await {
                            supervisor::Step::Media(pipeline::Step::Progress {..})=>(),
                            supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {record,..}))=>retained.extend_from_slice(record.bytes()),
                            supervisor::Step::Observation(_)=>(),
                            supervisor::Step::AudioPending=>{pending=true;break;},
                            other=>return Err(format!("expected pending audio: {other:?}").into()),
                        }
                    }
                    if !pending {return Err("audio event was not produced".into());}
                    policy.peer.set(false);
                    assert!(supervisor.take_audio_event(&owner).is_none());
                    assert!(matches!(supervisor.step(&mut owner,&operations[6],Duration::from_secs(5)).await,
                        supervisor::Step::ControllerStopped(fss_reference::unifi_direct::receive::Stop::AdmissionRevoked)));
                    let retired=supervisor.retire();
                    assert!(matches!(retired.media.pending_audio,Some(pipeline::AudioEvent::Observed(fss_packet::extended_flv::aac_track::Observation::Configuration {epoch:1,..}))));
                    for record in retired.media.recorder.pending {retained.extend_from_slice(record.bytes());}
                    retained.extend_from_slice(retired.media.ingress.framing.bytes());
                    if let Some(buffered)=retired.media.ingress.buffered {retained.extend_from_slice(&buffered.source.bytes()[buffered.appended..]);}
                    if let Some(pending)=retired.media.ingress.source.pending {retained.extend_from_slice(pending.bytes());}
                    assert_eq!(retained.len() as u64,retired.media.ingress.source.received);
                    assert_eq!(retained,expected[..retained.len()]);
                    peer.join().map_err(|_|"fixture peer panic")??;
                    return Ok(());
                }
                if revoke_after_start {
                    let mut retained=Vec::new();
                    match supervisor.step(&mut owner,&operations[6],Duration::from_secs(5)).await {
                        supervisor::Step::Media(pipeline::Step::Progress {appended}) if appended>0=>(),
                        supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {record,..}))=>retained.extend_from_slice(record.bytes()),
                        other=>return Err(format!("expected buffered media: {other:?}").into()),
                    };
                    policy.peer.set(false);
                    assert!(matches!(supervisor.step(&mut owner,&operations[6],Duration::from_secs(5)).await,
                        supervisor::Step::ControllerStopped(fss_reference::unifi_direct::receive::Stop::AdmissionRevoked)));
                    policy.peer.set(true);
                    assert!(matches!(supervisor.step(&mut owner,&operations[6],Duration::from_secs(5)).await,supervisor::Step::Stopped));
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
                let mut camera_events=0;
                let mut late_replies=0;
                let mut originals=Vec::new();
                let mut segments=0;
                let mut frames=0;
                let mut av_muxer=None;
                loop {
                    match supervisor.step(&mut owner,&operations[6],Duration::from_secs(5)).await {
                        supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {record,disposition})) => {
                            originals.extend_from_slice(record.bytes());
                            if archive_guard && disposition == recording::SourceDisposition::Configuration {
                                use fss_reference::unifi_direct::{av_recording, av_sink, evidence};
                                let av_init=supervisor.av_initialization(&audio_config)?.ok_or("missing A/V initialization")?;
                                if async_archive {
                                    use fss_reference::unifi_direct::{archive, av_owned_sink, av_worker, av_worker_guard};
                                    use std::sync::atomic::{AtomicBool, Ordering};
                                    struct Retention { block: AtomicBool, entered: AtomicBool, allow: AtomicBool }
                                    impl archive::RetainAuthority for Retention {
                                        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
                                            self.entered.store(true, Ordering::Release);
                                            for _ in 0..2500 {
                                                if !self.block.load(Ordering::Acquire) { return self.allow.load(Ordering::Acquire); }
                                                std::thread::sleep(Duration::from_millis(2));
                                            }
                                            false
                                        }
                                    }
                                    struct Unblock(Arc<Retention>);
                                    impl Drop for Unblock { fn drop(&mut self) { self.0.block.store(false, Ordering::Release); } }
                                    let muxer=av_recording::Muxer::new(&av_init,&audio_config,0,0,8,8,fss_container::Mp4Limits::default())?;
                                    let sink=av_owned_sink::OwnedSink::new(av_owned_sink::Inputs {
                                        video_configuration:record, av_initialization:av_init,
                                        audio:av_owned_sink::Audio::SuppliedUnverified(audio_bytes), muxer,
                                        retention:ContentDigest::sha256(b"worker guard retention"), evidence_limits:evidence::Limits::default(),
                                        video_limits:fss_container::Mp4Limits::default(),
                                    }).map_err(|_|"owned sink construction refused")?;
                                    let replay_authority=fss_core::region::ContextAuthority::new_root(RootAuthoritySpec {
                                        trace_id:"trace:worker-guard-replay".into(), operation_id:OperationId::parse("operation:worker-guard-replay")?,
                                        principal:"principal:fixture".into(), capabilities:vec!["ADP-REPLAY-001".into()],
                                        deadline:None, priority:1, budgets:BudgetVector::builder().bytes(64*1024*1024).build()?,
                                        privacy_scope:"privacy:test".into(), retention_scope:"retention:test".into(),
                                        anchor_universe:ContentDigest::sha256(b"site:worker-guard"), generation:1,
                                    })?;
                                    let replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?;
                                    let deployment=fss_reference::ReferenceDeployment::open(&temp.0.join("worker-guard-archive"),"site:worker-guard",&replay)?;
                                    let store=FileEffectJournal::create(temp.0.join("worker-guard-intent"),EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
                                    let journal=archive::journal::Journal::create(Box::new(store),ContentDigest::sha256(b"worker guard scope"),&replay)?;
                                    let store=FileEffectJournal::create(temp.0.join("worker-guard-anchor"),EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
                                    let keeper=archive::journal::AnchorKeeper::create(Box::new(store),&journal,&replay)?;
                                    let access=Arc::new(Retention {block:AtomicBool::new(true), entered:AtomicBool::new(false), allow:AtomicBool::new(false)});
                                    let _unblock=Unblock(Arc::clone(&access));
                                    let authority:Arc<dyn archive::RetainAuthority + Send + Sync>=access.clone();
                                    let worker=av_worker::Worker::new(av_worker::Parts {sink,deployment,journal,keeper,replay,authority,limits:archive::Limits::default(),work_limit:4_000_000_000}).map_err(|_|"worker limits invalid")?;
                                    let mut guard=av_worker_guard::Guard::new(supervisor,worker).map_err(|_|"worker was not idle")?;
                                    let mut captured=false;
                                    for _ in 0..128 {
                                        match guard.step(&mut owner,&operations[6],Duration::from_secs(5)).await {
                                            av_sink::GuardStep::CaptureRequired => {captured=true;break;},
                                            av_sink::GuardStep::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {record,..}))) => originals.extend_from_slice(record.bytes()),
                                            av_sink::GuardStep::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Buffered)|pipeline::Step::Progress {..})) | av_sink::GuardStep::Supervisor(supervisor::Step::TimeSyncWritten) => (),
                                            other => return Err(format!("unexpected async guard source result: {other:?}").into()),
                                        }
                                    }
                                    if !captured {return Err("async guard did not retain a segment".into());}
                                    let segment=guard.awaiting_capture().ok_or("missing source")?;
                                    let source_digest=ContentDigest::sha256(segment.fragment().bytes());
                                    for source in segment.source() { originals.extend_from_slice(source.bytes()); }
                                    control_probe_tx.send(()).map_err(io::Error::other)?;
                                    assert!(matches!(guard.service_control(&mut owner,&operations[7],Duration::from_secs(5)).await,supervisor::Step::TimeSyncWritten));
                                    assert_eq!(ContentDigest::sha256(guard.awaiting_capture().ok_or("control consumed source")?.fragment().bytes()),source_digest);
                                    guard.supply_capture(fss_core::CaptureInterval::new(TimestampNs(1),TimestampNs(2))?).map_err(|_|"capture binding refused")?;
                                    assert_eq!(guard.archive_state(),av_worker_guard::ArchiveState::Pending);
                                    assert!(matches!(guard.drive_archive(&mut owner,&operations[6],Duration::from_millis(100)).await,av_worker_guard::Drive::NotRunning));
                                    assert!(matches!(guard.start_archive(task,cx,other_clock,"fixture:archive",&BudgetVector::ZERO),Err(av_worker::StartError::Context)));
                                    assert_eq!(guard.archive_state(),av_worker_guard::ArchiveState::Pending);
                                    guard.start_archive(task,cx,clock,"fixture:archive",&BudgetVector::ZERO).map_err(|e|format!("archive start refused: {e:?}"))?;
                                    timeout(cx.now(),Duration::from_secs(5),async {
                                        while !access.entered.load(Ordering::Acquire) { asupersync::runtime::yield_now().await; }
                                    }).await.map_err(|_|"archive worker did not enter")?;
                                    assert_eq!(guard.archive_state(),av_worker_guard::ArchiveState::Running);
                                    assert!(matches!(guard.step(&mut owner,&operations[6],Duration::from_secs(5)).await,av_sink::GuardStep::ArchivePending));
                                    control_probe_tx.send(()).map_err(io::Error::other)?;
                                    assert!(matches!(guard.drive_archive(&mut owner,&operations[8],Duration::from_secs(5)).await,av_worker_guard::Drive::Control {step:supervisor::Step::TimeSyncWritten,completion:None}));
                                    if cancel_archive {
                                        guard.abort_archive();
                                        timeout(cx.now(),Duration::from_secs(5),async {
                                            while !guard.cancellation_observed() { asupersync::runtime::yield_now().await; }
                                        }).await.map_err(|_|"archive cancellation was not observed")?;
                                    }
                                    let pending=if cancel_archive {
                                        poll_fn(|context| { let mut wait=std::pin::pin!(guard.cancel_and_join_archive()); Poll::Ready(wait.as_mut().poll(context).is_pending()) }).await
                                    } else {
                                        poll_fn(|context| { let mut wait=std::pin::pin!(guard.join_archive()); Poll::Ready(wait.as_mut().poll(context).is_pending()) }).await
                                    };
                                    assert!(pending,"archive joined before retention released");
                                    guard=match guard.retire() { Err(guard)=>guard, Ok(_)=>return Err("guard retired while work was running".into()) };
                                    access.block.store(false,Ordering::Release);
                                    let completion=timeout(cx.now(),Duration::from_secs(5),async {
                                        loop {
                                            match guard.drive_archive(&mut owner,&operations[6],Duration::from_millis(100)).await {
                                                av_worker_guard::Drive::Archive(completion) => break Ok(completion),
                                                av_worker_guard::Drive::Control {step:supervisor::Step::Idle,completion:Some(completion)} => break Ok(completion),
                                                av_worker_guard::Drive::Control {step:supervisor::Step::Idle,completion:None} => (),
                                                _ => break Err("unexpected archive driver result"),
                                            }
                                        }
                                    }).await??;
                                    assert!(completion.runtime.is_ok());
                                    let reason=if cancel_archive {av_worker::FailureReason::CancelledOrDenied} else {av_worker::FailureReason::Denied};
                                    assert!(matches!(completion.outcome,av_worker::Outcome::Publication(av_worker::Publication::Refused {reason:actual,..}) if actual==reason));
                                    assert_eq!(guard.archive_state(),av_worker_guard::ArchiveState::Pending);
                                    assert!(matches!(guard.step(&mut owner,&operations[6],Duration::from_secs(5)).await,av_sink::GuardStep::ArchivePending));
                                    access.allow.store(true,Ordering::Release);
                                    guard.start_archive(task,cx,clock,"fixture:archive",&BudgetVector::ZERO).map_err(|e|format!("archive retry refused: {e:?}"))?;
                                    let completion=timeout(cx.now(),Duration::from_secs(5),guard.join_archive()).await?.ok_or("missing retry completion")?;
                                    assert!(completion.runtime.is_ok());
                                    assert!(matches!(completion.outcome,av_worker::Outcome::Publication(av_worker::Publication::Published(_))));
                                    assert_eq!(guard.archive_state(),av_worker_guard::ArchiveState::Idle);
                                    let mut next=false;
                                    for _ in 0..128 {
                                        match guard.step(&mut owner,&operations[6],Duration::from_secs(5)).await {
                                            av_sink::GuardStep::CaptureRequired=>{next=true;break;},
                                            av_sink::GuardStep::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {record,..})))=>originals.extend_from_slice(record.bytes()),
                                            av_sink::GuardStep::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Buffered)|pipeline::Step::Progress {..})) | av_sink::GuardStep::Supervisor(supervisor::Step::TimeSyncWritten)=>(),
                                            other=>return Err(format!("async supervisor did not resume: {other:?}").into()),
                                        }
                                    }
                                    if !next {return Err("async guard did not resume".into());}
                                    let retired=guard.retire().map_err(|_|"guard failed to retire")?;
                                    assert!(retired.worker.parts.sink.retire().pending.is_none());
                                    let segment=retired.awaiting_capture.ok_or("async guard lost next source")?;
                                    for source in segment.source() {originals.extend_from_slice(source.bytes());}
                                    for source in retired.supervisor.media.recorder.pending { originals.extend_from_slice(source.bytes()); }
                                    originals.extend_from_slice(retired.supervisor.media.ingress.framing.bytes());
                                    if let Some(buffered)=retired.supervisor.media.ingress.buffered {originals.extend_from_slice(&buffered.source.bytes()[buffered.appended..]);}
                                    if let Some(pending)=retired.supervisor.media.ingress.source.pending {originals.extend_from_slice(pending.bytes());}
                                    assert_eq!(originals,expected[..originals.len()]);
                                    peer.join().map_err(|_|"async guard peer panic")??;
                                    return Ok(());
                                }
                                let muxer=av_recording::Muxer::new(&av_init,&audio_config,0,0,8,8,fss_container::Mp4Limits::default())?;
                                let sink=av_sink::Sink::new(&record,av_init,av_sink::Audio::SuppliedUnverified(&audio_config),muxer,ContentDigest::sha256(b"guard test retention"),evidence::Limits::default());
                                let mut recording_guard=av_sink::Guard::new(supervisor,sink);
                                let mut captured=false;
                                for _ in 0..128 {
                                    match recording_guard.step(&mut owner,&operations[6],Duration::from_secs(5)).await {
                                        av_sink::GuardStep::CaptureRequired => {captured=true;break;},
                                        av_sink::GuardStep::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {record,..}))) => originals.extend_from_slice(record.bytes()),
                                        av_sink::GuardStep::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Buffered)|pipeline::Step::Progress {..})) | av_sink::GuardStep::Supervisor(supervisor::Step::TimeSyncWritten) => (),
                                        other => return Err(format!("unexpected guarded source result: {other:?}").into()),
                                    }
                                }
                                if !captured {return Err("guard did not retain a completed segment".into());}
                                assert!(recording_guard.awaiting_capture().is_some());
                                let source_digest=ContentDigest::sha256(recording_guard.awaiting_capture().ok_or("missing guarded source")?.fragment().bytes());
                                for source in recording_guard.awaiting_capture().ok_or("missing guarded source")?.source() {originals.extend_from_slice(source.bytes());}
                                policy.peer.set(false);
                                assert!(matches!(recording_guard.step(&mut owner,&operations[6],Duration::from_secs(5)).await,av_sink::GuardStep::CaptureRequired));
                                policy.peer.set(true);
                                control_probe_tx.send(()).map_err(io::Error::other)?;
                                assert!(matches!(recording_guard.service_control(&mut owner,&operations[7],Duration::from_secs(5)).await,supervisor::Step::TimeSyncWritten));
                                assert_eq!(ContentDigest::sha256(recording_guard.awaiting_capture().ok_or("control consumed source")?.fragment().bytes()),source_digest);
                                let capture=fss_core::CaptureInterval::new(TimestampNs(1),TimestampNs(2))?;
                                recording_guard.supply_capture(capture).map_err(|_|"capture binding refused")?;
                                assert!(recording_guard.awaiting_capture().is_none());
                                assert!(matches!(recording_guard.step(&mut owner,&operations[6],Duration::from_secs(5)).await,av_sink::GuardStep::ArchivePending));
                                policy.peer.set(true);
                                // Reference-only synchronous archive calls exercise the complete
                                // handoff; production must move this I/O to an owned worker.
                                let replay_authority=fss_core::region::ContextAuthority::new_root(RootAuthoritySpec {
                                    trace_id:"trace:guard-archive".into(), operation_id:OperationId::parse("operation:guard-archive")?,
                                    principal:"principal:fixture".into(), capabilities:vec!["ADP-REPLAY-001".into()],
                                    deadline:None, priority:1, budgets:BudgetVector::builder().bytes(64*1024*1024).build()?,
                                    privacy_scope:"privacy:test".into(), retention_scope:"retention:test".into(),
                                    anchor_universe:ContentDigest::sha256(b"site:guard-fixture"), generation:1,
                                })?;
                                let replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?;
                                let mut deployment=fss_reference::ReferenceDeployment::open(&temp.0.join("guard-archive"),"site:guard-fixture",&replay)?;
                                let store=FileEffectJournal::create(temp.0.join("guard-intent"),EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
                                let mut journal=fss_reference::unifi_direct::archive::journal::Journal::create(Box::new(store),ContentDigest::sha256(b"guard scope"),&replay)?;
                                let store=FileEffectJournal::create(temp.0.join("guard-anchor"),EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
                                let mut anchor=fss_reference::unifi_direct::archive::journal::AnchorKeeper::create(Box::new(store),&journal,&replay)?;
                                struct Retention(bool);
                                impl fss_reference::unifi_direct::archive::RetainAuthority for Retention {
                                    fn permits(&self,_:ContentDigest,_:ContentDigest)->bool {self.0}
                                }
                                let limits=fss_reference::unifi_direct::archive::Limits::default();
                                let denial=recording_guard.flush(&mut deployment,&Retention(false),limits,&mut fss_geometry::WorkBudget::new(4_000_000_000),&replay,&mut journal,&mut anchor);
                                assert!(matches!(denial,Err(av_sink::GuardFlushError::Archive(fss_reference::unifi_direct::archive::AvSegmentPublishError::Archive {source:fss_reference::unifi_direct::archive::Error::Denied,..}))));
                                assert!(matches!(recording_guard.step(&mut owner,&operations[6],Duration::from_secs(5)).await,av_sink::GuardStep::ArchivePending));
                                control_probe_tx.send(()).map_err(io::Error::other)?;
                                assert!(matches!(recording_guard.service_control(&mut owner,&operations[8],Duration::from_secs(5)).await,supervisor::Step::TimeSyncWritten));
                                assert!(matches!(recording_guard.step(&mut owner,&operations[6],Duration::from_secs(5)).await,av_sink::GuardStep::ArchivePending));
                                let receipt=recording_guard.flush(&mut deployment,&Retention(true),limits,&mut fss_geometry::WorkBudget::new(4_000_000_000),&replay,&mut journal,&mut anchor).map_err(|_|"guard publication failed")?.ok_or("guard receipt missing")?;
                                assert_eq!(receipt.receipt.outcome,fss_publication::RootLedgerOutcome::Committed);
                                let mut next=false;
                                for _ in 0..128 {
                                    match recording_guard.step(&mut owner,&operations[6],Duration::from_secs(5)).await {
                                        av_sink::GuardStep::CaptureRequired=>{next=true;break;},
                                        av_sink::GuardStep::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {record,..})))=>originals.extend_from_slice(record.bytes()),
                                        av_sink::GuardStep::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Buffered)|pipeline::Step::Progress {..})) | av_sink::GuardStep::Supervisor(supervisor::Step::TimeSyncWritten)=>(),
                                        other=>return Err(format!("supervisor did not resume: {other:?}").into()),
                                    }
                                }
                                if !next {return Err("guard did not resume to the next segment".into());}
                                let retired=recording_guard.retire();
                                assert!(retired.sink.pending.is_none());
                                let segment=retired.awaiting_capture.ok_or("guard lost next source")?;
                                for source in segment.source() {originals.extend_from_slice(source.bytes());}
                                for source in retired.supervisor.media.recorder.pending { originals.extend_from_slice(source.bytes()); }
                                originals.extend_from_slice(retired.supervisor.media.ingress.framing.bytes());
                                if let Some(buffered)=retired.supervisor.media.ingress.buffered {originals.extend_from_slice(&buffered.source.bytes()[buffered.appended..]);}
                                if let Some(pending)=retired.supervisor.media.ingress.source.pending {originals.extend_from_slice(pending.bytes());}
                                assert_eq!(originals,expected[..originals.len()]);
                                peer.join().map_err(|_|"guard peer panic")??;
                                return Ok(());
                            }
                        },
                        supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Buffered) | pipeline::Step::Progress {..}) => (),
                        supervisor::Step::TimeSyncWritten => later_syncs+=1,
                        supervisor::Step::CameraEvent(event) => {
                            assert_eq!(event.kind(),fss_reference::unifi_direct::events::Kind::SmartDetect);
                            assert_eq!(event.source(),EVENT);
                            assert!(!format!("{event:?}").contains("person"));
                            assert_eq!(event.message_id(),20);
                            assert_eq!(event.digest(),ContentDigest::sha256(EVENT));
                            let parsed=event.interpret()?;
                            assert_eq!(parsed.edge,fss_reference::unifi_direct::events::Edge::Enter);
                            assert_eq!(parsed.descriptors.ok_or("missing descriptors")?.len(),1);
                            camera_events+=1;
                        },
                        supervisor::Step::Observation(Observation::StreamSettingsReply {..}) if reply_after_media => late_replies+=1,
                        supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Segment(segment))) => {
                            for record in segment.source() { originals.extend_from_slice(record.bytes()); }
                            let mut movie=supervisor.initialization().ok_or("missing initialization")?.bytes().to_vec();
                            let av_init=supervisor.av_initialization(&audio_config)?.ok_or("missing A/V initialization")?;
                            assert_eq!(av_init.bytes().get(av_init.audio_configuration_range()),Some(audio_config.bytes()));
                            movie.extend_from_slice(segment.fragment().bytes());
                            if av_muxer.is_none() {
                                av_muxer=Some(fss_reference::unifi_direct::av_recording::Muxer::new(
                                    &av_init,&audio_config,0,0,8,8,fss_container::Mp4Limits::default())?);
                            }
                            let av_fragment=av_muxer.as_mut().ok_or("missing A/V muxer")?.fragment(&av_init,&segment)?;
                            assert!(!av_fragment.audio().is_empty());
                            fss_container::flv_av::verify_archived_initialization(&movie,av_init.bytes(),&audio_config,fss_container::Mp4Limits::default())?;
                            fss_container::flv_av::verify_archived_fragment(segment.fragment().bytes(),av_fragment.bytes(),av_fragment.audio(),fss_container::Mp4Limits::default())?;
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
                assert_eq!(camera_events,if emit_event {2} else {0});
                assert_eq!(late_replies,if reply_after_media && !never_reply && !early_reply {1} else {0});
                let retired=supervisor.retire();
                assert_eq!(retired.controller.previous_phase, fss_reference::unifi_direct::Phase::AgreementReplyObserved);
                assert_eq!(retired.controller.stream_request, if never_reply {Some((4,VideoChannel::Video2))} else {None});
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
    for (index, operation) in operations.iter().enumerate() {
        if index == 4 && !reply_after_media { continue; }
        if index == 5 && !early_reply { continue; }
        if index == 6 && (revoke_stream || revoke_after_start || revoke_audio_pending || stop_mode != 0) { continue; }
        if index >= 7 && !archive_guard { continue; }
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
fn asynchronous_guard_services_control_while_archive_is_blocked() -> Test {
    conversation_scenario_with_worker_guard(false, false, false, false, false, false, 0, false, true, true, false)
}

#[test]
fn asynchronous_guard_cancels_drains_and_retries_source() -> Test {
    conversation_scenario_with_worker_guard(false, false, false, false, false, false, 0, false, true, true, true)
}

#[test]
fn guarded_supervisor_retains_segment_and_stops_polling() -> Test {
    conversation_scenario_with_archive_guard(false, false, false, false, false, false, 0, false, true)
}

#[test]
fn owned_conversation_requests_a_stream_that_reaches_the_recording_pipeline() -> Test {
    conversation_scenario(false, false, false, false, false, false)
}

#[test]
fn media_can_be_processed_before_the_camera_settings_reply() -> Test {
    conversation_scenario(false, false, false, true, false, false)
}

#[test]
fn media_can_be_processed_when_camera_never_replies() -> Test {
    conversation_scenario(false, false, false, true, true, false)
}

#[test]
fn settings_reply_before_media_is_returned_to_the_caller() -> Test {
    conversation_scenario(false, false, false, true, false, true)
}

#[test]
fn supervised_camera_event_preserves_source_and_interprets_claims() -> Test {
    conversation_scenario_with_event(false, false, false, false, false, false, 0, true)
}

#[test]
fn startup_event_remains_owned_after_peer_closes() -> Test {
    conversation_scenario_with_event(false, false, false, true, false, true, 1, true)
}

#[test]
fn startup_event_remains_owned_after_future_is_cancelled() -> Test {
    conversation_scenario_with_event(false, false, false, true, false, true, 2, true)
}

#[test]
fn startup_trace_retains_reply_when_peer_closes_before_media() -> Test {
    conversation_scenario_with_stop(false, false, false, true, false, true, 1)
}

#[test]
fn startup_trace_retains_reply_when_future_is_cancelled() -> Test {
    conversation_scenario_with_stop(false, false, false, true, false, true, 2)
}

#[test]
fn revoked_listener_policy_prevents_stream_setting_dispatch() -> Test {
    conversation_scenario(true, false, false, false, false, false)
}

#[test]
fn revoked_controller_admission_stops_buffered_media_and_retains_it() -> Test {
    conversation_scenario(false, true, false, false, false, false)
}

#[test]
fn revoked_controller_withholds_pending_audio_and_returns_it_at_retirement() -> Test {
    conversation_scenario(false, false, true, false, false, false)
}

#[test]
fn correlated_clock_chain_reaches_hello_and_stream_with_distinct_effects() -> Test {
    clock_requests_reach_stream(false)
}

#[test]
fn mixed_clock_requests_reach_hello_and_stream_with_distinct_effects() -> Test {
    clock_requests_reach_stream(true)
}

/// Exercise clock requests through the owned conversation, local TCP,
/// per-reply effect journal and the camera-shaped peer.
fn clock_requests_reach_stream(mixed: bool) -> Test {
    let path = std::fs::canonicalize(std::env::temp_dir())?
        .join(format!("fss-unifi-clock-chain-{}-{mixed}", std::process::id()));
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
            trace_id: "trace:unifi-clock-chain".into(),
            operation_id: OperationId::parse("operation:unifi-clock-chain")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::CameraManagementPrepare.as_str().into(),
                RuntimeGrant::CameraManagementCommit.as_str().into(),
                RuntimeGrant::CameraSettingPrepare.as_str().into(),
                RuntimeGrant::CameraSettingCommit.as_str().into(),
            ],
            deadline: Some(TimestampNs(60_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"fixture"),
            generation: 1,
        },
        RegionId::new("region:unifi-clock-chain")?,
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
    let management = Preconditions {
        camera,
        peer_admission: ContentDigest::sha256(b"fixture admission"),
        session_generation: 1,
        previous_association: None,
        previous_clock: None,
        lease_fence: fence,
    };
    let stream_conditions = intent::Preconditions {
        camera,
        peer_admission: management.peer_admission,
        stream_generation: 1,
        previous_settings: None,
        lease_fence: fence,
    };
    let hello = OperationId::parse("operation:clock-chain-hello")?;
    let agreement = OperationId::parse("operation:clock-chain-agreement")?;
    let stream = OperationId::parse("operation:clock-chain-stream")?;
    let syncs: Vec<_> = (0..32)
        .map(|i| OperationId::parse(format!("operation:clock-chain-sync-{i:02}")))
        .collect::<Result<_, _>>()?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:unifi-clock-chain")?,
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
                    let listener = controller_listener::Listener::bind(
                        task, cx, clock, &policy,
                        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
                        "fixture:camera", Duration::from_secs(10),
                    ).await?;
                    let address = SocketAddr::V4(listener.local_addr());
                    let peer = std::thread::spawn(move || -> io::Result<()> {
                        fn field(bytes: &[u8], name: &str) -> io::Result<u64> {
                            let text = std::str::from_utf8(bytes).map_err(io::Error::other)?;
                            let value = fss_core::json_input::parse(text).map_err(io::Error::other)?;
                            let number = value.object().and_then(|v| v.get(name))
                                .and_then(fss_core::json_input::Value::integer)
                                .ok_or_else(|| io::Error::other("missing integer field"))?;
                            u64::try_from(number).map_err(io::Error::other)
                        }
                        let mut socket = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        socket.set_read_timeout(Some(Duration::from_secs(15)))?;
                        socket.write_all(HEAD.as_bytes())?;
                        let mut header = Vec::new();
                        let mut byte = [0u8; 1];
                        while !header.ends_with(b"\r\n\r\n") {
                            socket.read_exact(&mut byte)?;
                            header.push(byte[0]);
                            if header.len() > 4096 { return Err(io::Error::other("upgrade limit")); }
                        }
                        if !header.starts_with(b"HTTP/1.1 101 ") { return Err(io::Error::other("upgrade refused")); }
                        let mut correlation = 777u64;
                        for camera_id in 100..112u64 {
                            let response_to = if mixed && camera_id % 2 == 0 { 0 } else { correlation };
                            let message = format!("{{\"from\":\"ubnt_avclient\",\"to\":\"UniFiVideo\",\"functionName\":\"ubnt_avclient_timeSync\",\"messageId\":{camera_id},\"inResponseTo\":{response_to}}}");
                            socket.write_all(&frame(message.as_bytes()))?;
                            let reply = receive_binary(&mut socket)?;
                            if field(&reply, "inResponseTo")? != camera_id { return Err(io::Error::other("clock correlation")); }
                            correlation = field(&reply, "messageId")?;
                        }
                        socket.write_all(&frame(HELLO))?;
                        let reply = receive_binary(&mut socket)?;
                        if !reply.windows(b"ubnt_avclient_hello".len()).any(|w| w == b"ubnt_avclient_hello") { return Err(io::Error::other("hello reply")); }
                        let agreement = receive_binary(&mut socket)?;
                        let agreement_id = field(&agreement, "messageId")?;
                        let reply = format!("{{\"from\":\"ubnt_avclient\",\"to\":\"UniFiVideo\",\"functionName\":\"ubnt_avclient_paramAgreement\",\"messageId\":300,\"inResponseTo\":{agreement_id}}}");
                        socket.write_all(&frame(reply.as_bytes()))?;
                        let stream = receive_binary(&mut socket)?;
                        if !stream.windows(b"ChangeVideoSettings".len()).any(|w| w == b"ChangeVideoSettings") { return Err(io::Error::other("stream request")); }
                        let stream_id = field(&stream, "messageId")?;
                        let reply = format!("{{\"from\":\"ubnt_avclient\",\"to\":\"UniFiVideo\",\"functionName\":\"ChangeVideoSettings\",\"messageId\":301,\"inResponseTo\":{stream_id}}}");
                        socket.write_all(&frame(reply.as_bytes()))?;
                        let mut last = [0u8; 1];
                        match socket.read(&mut last) { Ok(0) => Ok(()), _ => Err(io::Error::other("controller did not retire")) }
                    });
                    let (io, gate) = listener.accept(4096, Duration::from_secs(10)).await?;
                    let controller = Controller::new_with_time_sync_policy(
                        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
                        1,
                        fss_reference::unifi_direct::TimeSyncPolicy::BoundedPreHelloClockExchange,
                    )?;
                    let mut session = owner::accept_guarded(io, ProtocolPolicy::RequireOffer, &FixtureAdmission, gate, controller, Duration::from_secs(10)).await?;
                    let guard = Guard { leases: &leases, clock };
                    let approval = FixtureApproval { revoke_stream: None };
                    let mut owner = conversation::Owner {
                        cx, task, clock, effects: &mut effects, leases: &leases,
                        approval: &approval, management_authority: &guard,
                        stream_authority: &guard, wall: &FixtureClock,
                    };
                    let request = StreamStart::new(
                        VideoChannel::Video2, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 17551),
                        VideoCodec::H264, AudioCodec::Aac, "0123456789abcdef",
                    )?;
                    let cfg = conversation::Config {
                        hello: &hello, agreement: &agreement, stream: &stream, time_sync: &syncs,
                        management, stream_conditions, request: &request, wait: Duration::from_secs(20),
                    };
                    let reply = owner.start(&mut session, &cfg).await?;
                    assert_eq!(reply.time_syncs, 12);
                    drop(session);
                    peer.join().map_err(|_| "fixture peer panic")??;
                    Ok(())
                }.await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Indeterminate("fixture changes require reconciliation".into())
                } else {
                    TaskOutcome::Failed("clock chain fixture failed".into())
                };
                TaskCompletion { output, outcome, completed_at: TimestampNs(59_000_000_000) }
            },
        ).await?;
        result.receipt?;
        result.output
    })?;
    for operation in [&hello, &agreement, &stream].into_iter().chain(syncs[..12].iter()) {
        assert_eq!(effects.journal().operation(operation).ok_or("missing effect")?.state, fss_core::EffectState::Committed);
    }
    for operation in &syncs[12..] {
        assert!(effects.journal().operation(operation).is_none());
    }
    assert!(!authority.finalize_report(&tree)?.is_empty());
    Ok(())
}
