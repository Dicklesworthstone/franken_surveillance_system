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

#[derive(Debug)]
struct SupplyIoGate {
    entered: std::sync::atomic::AtomicBool,
    release: std::sync::atomic::AtomicBool,
}

#[derive(Debug)]
struct BlockingSupplyIo(Arc<SupplyIoGate>);

impl fss_object::SpoolIo for BlockingSupplyIo {
    fn create_dir_all(&self, p:&std::path::Path)->io::Result<()> { fss_object::SpoolIo::create_dir_all(&HostSpoolIo,p) }
    fn metadata(&self, p:&std::path::Path)->io::Result<std::fs::Metadata> { fss_object::SpoolIo::metadata(&HostSpoolIo,p) }
    fn symlink_metadata(&self, p:&std::path::Path)->io::Result<std::fs::Metadata> { fss_object::SpoolIo::symlink_metadata(&HostSpoolIo,p) }
    fn open_lock(&self, p:&std::path::Path)->io::Result<std::fs::File> { fss_object::SpoolIo::open_lock(&HostSpoolIo,p) }
    fn try_lock(&self, f:&std::fs::File)->Result<(),std::fs::TryLockError> { fss_object::SpoolIo::try_lock(&HostSpoolIo,f) }
    fn try_lock_shared(&self, f:&std::fs::File)->Result<(),std::fs::TryLockError> { fss_object::SpoolIo::try_lock_shared(&HostSpoolIo,f) }
    fn unlock(&self, f:&std::fs::File)->io::Result<()> { fss_object::SpoolIo::unlock(&HostSpoolIo,f) }
    fn create_dir(&self, p:&std::path::Path)->io::Result<()> { fss_object::SpoolIo::create_dir(&HostSpoolIo,p) }
    fn read_dir(&self, p:&std::path::Path)->io::Result<std::fs::ReadDir> { fss_object::SpoolIo::read_dir(&HostSpoolIo,p) }
    fn next_dir_entry(&self, d:&mut std::fs::ReadDir)->Option<io::Result<std::fs::DirEntry>> { fss_object::SpoolIo::next_dir_entry(&HostSpoolIo,d) }
    fn entry_file_type(&self, e:&std::fs::DirEntry)->io::Result<std::fs::FileType> { fss_object::SpoolIo::entry_file_type(&HostSpoolIo,e) }
    fn create_new(&self, p:&std::path::Path)->io::Result<std::fs::File> { fss_object::SpoolIo::create_new(&HostSpoolIo,p) }
    fn write(&self, f:&mut std::fs::File, b:&[u8])->io::Result<usize> { fss_object::SpoolIo::write(&HostSpoolIo,f,b) }
    fn sync_file(&self, f:&std::fs::File)->io::Result<()> { fss_object::SpoolIo::sync_file(&HostSpoolIo,f) }
    fn open_read(&self, p:&std::path::Path)->io::Result<std::fs::File> { fss_object::SpoolIo::open_read(&HostSpoolIo,p) }
    fn read_bounded(&self, f:&mut std::fs::File, n:u64)->io::Result<Vec<u8>> { fss_object::SpoolIo::read_bounded(&HostSpoolIo,f,n) }
    fn rename(&self, a:&std::path::Path, b:&std::path::Path)->io::Result<()> { fss_object::SpoolIo::rename(&HostSpoolIo,a,b) }
    fn remove_file(&self, p:&std::path::Path)->io::Result<()> { fss_object::SpoolIo::remove_file(&HostSpoolIo,p) }
    fn sync_directory(&self, p:&std::path::Path)->io::Result<()> {
        use std::sync::atomic::Ordering;
        if !self.0.entered.swap(true,Ordering::AcqRel) {
            for _ in 0..10_000 {
                if self.0.release.load(Ordering::Acquire) { return fss_object::SpoolIo::sync_directory(&HostSpoolIo,p); }
                std::thread::sleep(Duration::from_millis(1));
            }
            return Err(io::Error::new(io::ErrorKind::TimedOut,"supply gate timed out"));
        }
        fss_object::SpoolIo::sync_directory(&HostSpoolIo,p)
    }
    fn hard_link(&self, a:&std::path::Path,b:&std::path::Path)->io::Result<()> { fss_object::SpoolIo::hard_link(&HostSpoolIo,a,b) }
}

#[inline(never)]
fn refuse_guard_pause<'scope, 'task, IO: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin>(
    guard: Box<fss_reference::unifi_direct::av_unknown_worker_guard::Guard<'scope, 'task, IO>>,
) -> Result<Box<fss_reference::unifi_direct::av_unknown_worker_guard::Guard<'scope, 'task, IO>>, Box<dyn Error>> {
    match (*guard).pause_rollover() {
        Err(guard) => Ok(Box::new(guard)),
        Ok(_) => Err("guard unexpectedly allowed rollover".into()),
    }
}

#[inline(never)]
fn exercise_guard_rollover<'scope, 'task, IO: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin>(
    guard: Box<fss_reference::unifi_direct::av_unknown_worker_guard::Guard<'scope, 'task, IO>>,
    directory: &std::path::Path,
    access: &dyn fss_reference::unifi_direct::archive::ReadAuthority,
    expected: Option<fss_reference::unifi_direct::av_worker::RolloverNeed>,
) -> Result<Box<fss_reference::unifi_direct::av_unknown_worker_guard::Guard<'scope, 'task, IO>>, Box<dyn Error>> {
    use fss_reference::unifi_direct::{archive, av_worker_guard::ArchiveState};
    let (paused, previous) = (*guard).pause_rollover().map_err(|_| "settled guard did not pause")?;
    assert_eq!(paused.archive_state(), if expected.is_some() {ArchiveState::Pending} else {ArchiveState::Idle});
    assert_eq!(paused.rollover_need(), expected);
    assert_eq!(paused.worker_has_pending(), expected.is_some());
    let limits = EffectJournalLimits::default();
    let create = |name: &str| -> Result<Box<dyn fss_runtime::effect_journal::EffectJournalStore>, Box<dyn Error>> {
        Ok(Box::new(FileEffectJournal::create(directory.join(name), limits, Arc::new(HostSpoolIo))?))
    };
    let staged = archive::journal::rollover::Staged::begin(previous, create("guard-abort-journal")?, create("guard-abort-keeper")?, paused.replay()).map_err(|_| "guard abort stage refused")?;
    let guard = paused.restore(staged.abort()).map_err(|_| "guard restore refused")?;
    assert_eq!(guard.rollover_need(), expected);
    let (paused, previous) = guard.pause_rollover().map_err(|_| "restored guard did not pause")?;
    assert_eq!(paused.rollover_need(), expected);
    let staged = archive::journal::rollover::Staged::begin(previous, create("guard-next-journal")?, create("guard-next-keeper")?, paused.replay()).map_err(|_| "guard stage refused")?;
    let root = fss_object::effect_journal::FileTrustedRootPinRetainer::create(directory.join("guard-switch-root"), limits, Arc::new(HostSpoolIo), ContentDigest::sha256(b"guard switch root"))?;
    let switch = fss_runtime::effect_journal::PinRetainedEffectJournal::new(create("guard-switch")?, Box::new(root))?;
    let active = staged.commit(switch, paused.replay()).map_err(|_| "guard switch refused")?;
    let refusal = match paused.attach(active) {Err(refusal) => refusal, Ok(_) => return Err("guard accepted unreplayed successor".into())};
    let mut paused = refusal.paused;
    let mut active = refusal.active;
    let objects = archive::StagedAvLimits {max_objects: 8192, max_object_bytes: 1024 * 1024, max_total_bytes: 8 * 1024 * 1024};
    let receipt = paused.replay_confirmed_av(&mut active, access, objects, &mut fss_geometry::WorkBudget::new(100_000_000_000))?;
    assert_eq!(receipt.outcome, fss_publication::RootLedgerOutcome::AlreadyLedgered);
    let mut guard = paused.attach(active).map_err(|_| "guard attach refused")?;
    assert_eq!(guard.archive_state(), if expected.is_some() {ArchiveState::Pending} else {ArchiveState::Idle});
    assert_eq!(guard.rollover_need(), None);
    if expected.is_some() && guard.authorize_retry() {return Err("matching rollover left retry latched".into());}
    Ok(Box::new(guard))
}
const HEAD: &str = "GET / HTTP/1.1\r\nHost: camera.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nCamera-Mac: 001122aabbcc\r\nSec-WebSocket-Protocol: secure_transfer\r\n\r\n";
const HELLO:&[u8]=br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_hello","messageId":7,"payload":{}}"#;
const EVENT:&[u8]=br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventSmartDetect","messageId":20,"payload":{"edgeType":"enter","descriptors":[{"objectType":"person","trackerID":1,"confidenceLevel":80,"coord":[0,1,500,1000]}]}}"#;
const REPLY_EVENT:&[u8]=br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventExample","messageId":20,"responseExpected":true,"payload":{"private":"fixture"}}"#;
const ROLLOVER_REPLY_EVENT:&[u8]=br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventExample","messageId":50,"responseExpected":true,"payload":{"private":"fixture"}}"#;
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
struct EventGuard<'a, 'scope, 'task> { guard: &'a Guard<'a, 'scope, 'task> }
impl ManagementAuthority for EventGuard<'_, '_, '_> {
    fn permits(&self, mac:[u8;6], intent:Intent, permit:&CommittedEffect)->bool {
        ManagementAuthority::permits(self.guard,mac,intent,permit)
    }
    fn permits_event_reply(&self, mac:[u8;6], intent:Intent, permit:&CommittedEffect)->bool {
        ManagementAuthority::permits(self.guard,mac,intent,permit)
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
fn clock_reply_deadline_retains_committed_unwritten_permit() -> Test {
    clock_reply_deadline_scenario(false,false,false,false,false,false,false,false)
}

#[test]
fn supervisor_clock_deadline_returns_committed_unwritten_permit() -> Test {
    clock_reply_deadline_scenario(true,false,false,false,false,false,false,false)
}

#[test]
fn supervisor_clock_poll_budget_refuses_slow_storage_without_reply_override() -> Test {
    clock_reply_deadline_scenario(true,false,false,true,false,false,false,false)
}

#[test]
fn supervisor_separates_clock_reply_budget_from_idle_poll_under_slow_storage() -> Test {
    clock_reply_deadline_scenario(true,false,false,true,true,false,false,false)
}

#[test]
fn startup_hello_deadline_retains_committed_unwritten_permit() -> Test {
    clock_reply_deadline_scenario(false,true,false,false,false,false,false,false)
}

#[test]
fn startup_retains_original_retirement_if_peer_closes_before_hello() -> Test {
    clock_reply_deadline_scenario(false,true,true,false,false,false,false,false)
}

#[test]
fn clock_reply_deadline_before_journaling_leaves_no_effect() -> Test {
    clock_reply_deadline_scenario(false,false,false,false,false,true,false,false)
}

#[test]
fn startup_hello_deadline_before_journaling_leaves_no_effect() -> Test {
    clock_reply_deadline_scenario(false,true,false,false,false,true,false,false)
}

#[test]
fn clock_reply_deadline_during_approval_retains_prepared_without_commit() -> Test {
    clock_reply_deadline_scenario(false,false,false,false,false,false,true,false)
}

#[test]
fn clock_reply_deadline_preparation_can_be_cancelled_with_evidence() -> Test {
    clock_reply_deadline_scenario(false,false,false,false,false,false,true,true)
}

fn clock_reply_deadline_scenario(supervised: bool, startup: bool, close_before_hello: bool, slow_storage: bool, reply_override: bool, slow_wall: bool, slow_approval: bool, cancel_after: bool) -> Test {
    use fss_runtime::effect_journal::{EffectJournalPin, EffectJournalStore, EffectPersistenceError};
    #[derive(Debug)]
    struct SlowStore(FileEffectJournal, Arc<std::sync::atomic::AtomicUsize>, bool);
    impl EffectJournalStore for SlowStore {
        fn head(&self) -> Option<EffectJournalPin> { self.0.head() }
        fn records(&self) -> &[Vec<u8>] { self.0.records() }
        fn contains(&self, pin: EffectJournalPin) -> bool { self.0.contains(pin) }
        fn reserve_capacity(&mut self, records: usize, bytes: usize) -> Result<(), EffectPersistenceError> {
            self.0.reserve_capacity(records, bytes)
        }
        fn append(&mut self, expected: Option<EffectJournalPin>, record: &[u8]) -> Result<EffectJournalPin, EffectPersistenceError> {
            // Delay preparation and commit, or only commit for the late-commit case.
            let index=self.1.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if self.2 || index == 1 {std::thread::sleep(Duration::from_millis(175));}
            self.0.append(expected, record)
        }
    }
    struct SlowApproval;
    impl conversation::Approval for SlowApproval {
        fn approve(&self, prepared: &PreparedEffect) -> Option<CommitApproval> {
            // Deliberate test fault: simulate a slow approval/journal boundary.
            std::thread::sleep(Duration::from_millis(175));
            Some(CommitApproval { prepared_digest: prepared.digest(), current_precondition_digest: prepared.precondition_digest() })
        }
    }
    struct SlowWall;
    impl conversation::WallClock for SlowWall {
        fn observe(&self) -> Option<conversation::WallTime> {
            // Deliberate fault: violate the clock provider's nonblocking contract.
            std::thread::sleep(Duration::from_millis(175));
            Some(conversation::WallTime {unix_ms:1_700_000_000_000,timestamp:"2026-11-05T10:00:00.000Z".into()})
        }
    }
    const SYNC: &[u8] = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":42,"inResponseTo":0}"#;
    let path=std::fs::canonicalize(std::env::temp_dir())?.join(format!("fss-unifi-sync-deadline-{}-{supervised}-{startup}-{close_before_hello}-{slow_storage}-{reply_override}-{slow_wall}-{slow_approval}-{cancel_after}",std::process::id()));
    std::fs::create_dir(&path)?;
    let temp=Temp(path);
    let store=FileEffectJournal::create(temp.0.join("journal"),EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
    let slow_appends=Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let journal: Box<dyn EffectJournalStore> = if slow_wall || slow_approval { Box::new(store) } else { Box::new(SlowStore(store,Arc::clone(&slow_appends),slow_storage)) };
    let mut effects=EffectCoordinator::with_journal(journal)?;
    let mut budget=BudgetVector::ZERO; budget.network_bytes=1_000_000; budget.bytes=1_000_000;
    let (mut authority,mut tree)=AuthorityCx::root(RootAuthoritySpec {
        trace_id:"trace:sync-deadline".into(),operation_id:OperationId::parse("operation:sync-deadline-owner")?,principal:"principal:fixture".into(),
        capabilities:vec![RuntimeGrant::AdapterNet.as_str().into(),RuntimeGrant::CameraManagementPrepare.as_str().into(),RuntimeGrant::CameraManagementCommit.as_str().into(),RuntimeGrant::ReadMedia.as_str().into()],
        deadline:Some(TimestampNs(60_000_000_000)),priority:1,budgets:budget,privacy_scope:"privacy:test".into(),retention_scope:"retention:test".into(),anchor_universe:ContentDigest::sha256(b"sync deadline fixture"),generation:1,
    },RegionId::new("region:sync-deadline")?,RegionKind::Process,budget,TimestampNs(1))?;
    let camera=ContentDigest::sha256(b"fixture camera"); let resource=format!("camera:{}",camera.to_text());
    let mut leases=LeaseRegistry::new(); let fence=leases.acquire(&resource,authority.region().as_str(),None,TimestampNs(2))?.fence; let leases=RefCell::new(leases);
    let conditions=Preconditions {camera,peer_admission:ContentDigest::sha256(b"fixture peer"),session_generation:1,previous_association:None,previous_clock:None,lease_fence:fence};
    let operation=OperationId::parse("operation:sync-deadline")?;
    let runtime=RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx=asupersync::Cx::current().ok_or("missing runtime context")?;
        let result=run_owned_async(&mut authority,&mut tree,TaskSpec {task_id:TaskId::new("task:sync-deadline")?,started_at:TimestampNs(3)},&cx,async |task,cx| {
            let output:Test=async {
                let listener=TcpListener::bind("127.0.0.1:0").await?; let address=listener.local_addr()?;
                let peer=std::thread::spawn(move || -> io::Result<()> {
                    let mut socket=std::net::TcpStream::connect_timeout(&address,Duration::from_secs(5))?;
                    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let mut request=HEAD.as_bytes().to_vec(); if !close_before_hello {request.extend(frame(if startup {HELLO}else{SYNC}));} socket.write_all(&request)?;
                    if close_before_hello {socket.shutdown(std::net::Shutdown::Write)?;}
                    let mut header=Vec::new(); let mut byte=[0u8;1];
                    while !header.ends_with(b"\r\n\r\n") { socket.read_exact(&mut byte)?; header.push(byte[0]); if header.len()>4096 {return Err(io::Error::other("upgrade limit"));} }
                    if !header.starts_with(b"HTTP/1.1 101 ") {return Err(io::Error::other("upgrade refused"));}
                    if reply_override {
                        let response=receive_binary(&mut socket)?;
                        let parsed=fss_core::json_input::parse(std::str::from_utf8(&response).map_err(io::Error::other)?).map_err(io::Error::other)?;
                        let fields=parsed.object().ok_or_else(||io::Error::other("clock reply object"))?;
                        if fields.get("inResponseTo").and_then(|v|v.integer())!=Some(42) {return Err(io::Error::other("clock reply correlation"));}
                        Ok(())
                    } else {
                        socket.set_read_timeout(Some(Duration::from_millis(600)))?;
                        match socket.read(&mut byte) { Ok(0) if close_before_hello=>Ok(()), Err(error) if matches!(error.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::TimedOut)=>Ok(()), _=>Err(io::Error::other("unexpected write or close")) }
                    }
                });
                let (socket,_)=timeout(cx.now(),Duration::from_secs(5),listener.accept()).await??;
                let clock=MeteredClock::new(task,cx,TimestampNs(4))?;
                let io=MeteredIo::with_clock(socket,clock,"fixture:camera",4096)?;
                let controller=Controller::new(Identity::new("FSS","12345678-1234-4abc-9abc-123456789abc","1.20.0")?,1)?;
                let mut session=owner::accept(io,ProtocolPolicy::RequireOffer,&FixtureAdmission,controller,Duration::from_secs(5)).await?;
                let guard=Guard {leases:&leases,clock}; let normal_approval=FixtureApproval {revoke_stream:None};
                let approval: &dyn conversation::Approval=if slow_approval {&SlowApproval} else {&normal_approval};
                let wall: &dyn conversation::WallClock=if slow_wall {&SlowWall} else {&FixtureClock};
                let mut owner=conversation::Owner {cx,task,clock,effects:&mut effects,leases:&leases,approval,management_authority:&guard,stream_authority:&guard,wall};
                let (mut trace,retirement)=if supervised {
                    let media_listener=TcpListener::bind("127.0.0.1:0").await?;
                    let media_peer=std::net::TcpStream::connect_timeout(&media_listener.local_addr()?,Duration::from_secs(5))?;
                    let (media_socket,_)=timeout(cx.now(),Duration::from_secs(5),media_listener.accept()).await??;
                    let ingress=TcpIngress::new(media_socket,"fixture:camera",4096,1_000_000)?;
                    let framer=Framer::new(FlvLimits::default(),1024*1024)?;
                    let recorder=recording::Recorder::new(SourceKey {connection:1,generation:1},recording::Limits::default())?;
                    let pipeline=pipeline::Pipeline::new(DirectIngress::new(ingress,framer),recorder);
                    let mut supervisor=supervisor::Supervisor::new(session,pipeline,conditions);
                    assert_eq!(supervisor.set_time_sync_reply_wait(Some(Duration::ZERO)),Err(conversation::Error::Configuration));
                    assert_eq!(supervisor.set_time_sync_reply_wait(Some(Duration::from_secs(31))),Err(conversation::Error::Configuration));
                    supervisor.set_time_sync_reply_wait(Some(Duration::from_secs(3)))?;
                    if !reply_override {supervisor.set_time_sync_reply_wait(None)?;}
                    let trace=match supervisor.step_control(&mut owner,&operation,Duration::from_millis(100)).await {
                        supervisor::Step::TimeSyncWritten {trace} if reply_override=>trace,
                        supervisor::Step::TimeSyncStopped {error:conversation::Error::Deadline,trace} if !reply_override=>trace,
                        other=>return Err(format!("unexpected supervisor result: {other:?}").into()),
                    };
                    peer.join().map_err(|_|"fixture peer panic")??;
                    let retirement=supervisor.retire(); drop(media_peer);
                    (trace,retirement.controller)
                } else if startup {
                    let agreement=OperationId::parse("operation:startup-deadline-agreement")?;
                    let stream=OperationId::parse("operation:startup-deadline-stream")?;
                    let stream_conditions=intent::Preconditions {camera,peer_admission:conditions.peer_admission,stream_generation:1,previous_settings:None,lease_fence:fence};
                    let request=StreamStart::new(VideoChannel::Video2,SocketAddrV4::new(Ipv4Addr::LOCALHOST,17551),VideoCodec::H264,AudioCodec::Aac,"0123456789abcdef")?;
                    let cfg=conversation::Config {hello:&operation,agreement:&agreement,stream:&stream,time_sync:&[],management:conditions,stream_conditions,request:&request,wait:Duration::from_millis(100)};
                    let mut protocol=conversation::StartupProtocolTrace::default();
                    let result=owner.start_with_protocol_trace(&mut session,&cfg,&mut protocol).await;
                    if close_before_hello {
                        assert!(matches!(result,Err(conversation::Error::SessionRetired {..})));
                        let original=protocol.controller_retirement().ok_or("original startup retirement lost")?;
                        assert_eq!(original.previous_phase,fss_reference::unifi_direct::Phase::AwaitHello);
                        assert!(protocol.hello().operation().is_none());
                        peer.join().map_err(|_|"fixture peer panic")??;
                        let _=session.retire(); return Ok(());
                    }
                    assert_eq!(result,Err(conversation::Error::Deadline));
                    assert!(protocol.attempted()); assert!(protocol.agreement().operation().is_none()); assert!(protocol.stream().operation().is_none());
                    let trace=std::mem::take(protocol.hello_mut());
                    peer.join().map_err(|_|"fixture peer panic")??;
                    (trace,session.retire())
                } else {
                    assert_eq!(session.next(Duration::from_secs(3)).await?,Step::Observation(Observation::TimeSyncRequested));
                    let mut trace=conversation::TimeSyncTrace::default();
                    let result=owner.answer_time_sync_tracked(&mut session,&operation,conditions,Duration::from_millis(100),&mut trace).await;
                    assert_eq!(result,Err(conversation::Error::Deadline));
                    peer.join().map_err(|_|"fixture peer panic")??;
                    (trace,session.retire())
                };
                assert_eq!(trace.operation(),Some(&operation));
                if slow_wall {
                    assert!(!trace.dispatch_started());
                    assert!(trace.intent().is_none());
                    assert!(trace.take_pending_permit().is_none());
                    assert!(trace.take_written().is_none() && trace.take_refusal().is_none());
                } else if slow_approval || (slow_storage && !reply_override) {
                    assert!(!trace.dispatch_started());
                    assert!(trace.intent().is_some());
                    assert!(trace.take_pending_permit().is_none());
                    assert!(trace.take_written().is_none() && trace.take_refusal().is_none());
                } else if reply_override {
                    assert!(trace.dispatch_started());
                    assert!(trace.take_pending_permit().is_none());
                    match trace.take_written() {Some(ManagementWrite::Written {permit}) if permit.journal_backed()=>(),_=>return Err("written clock permit lost".into())}
                    assert!(trace.take_refusal().is_none());
                } else {
                    assert!(!trace.dispatch_started());
                    let permit=trace.take_pending_permit().ok_or("committed permit lost")?;
                    assert!(permit.journal_backed()); assert!(trace.take_written().is_none() && trace.take_refusal().is_none());
                }
                if startup {assert_eq!(retirement.hello_request_id,Some(7));}
                else if reply_override {assert_eq!(retirement.time_sync_request_id,None);}
                else {assert_eq!(retirement.time_sync_request_id,Some(42));}
                if cancel_after {owner.cancel_prepared_effect(&operation,ContentDigest::sha256(b"retained fixture deadline evidence"))?;}
                Ok(())
            }.await;
            let outcome=if output.is_err(){TaskOutcome::Failed("sync deadline fixture failed".into())}else if close_before_hello || slow_wall || cancel_after {TaskOutcome::Success}else{TaskOutcome::Indeterminate("clock reply effect requires reconciliation".into())};
            TaskCompletion {output,outcome,completed_at:TimestampNs(59_000_000_000)}
        }).await?;
        result.receipt?;result.output
    })?;
    if slow_storage {assert!(slow_appends.load(std::sync::atomic::Ordering::Relaxed)>=if reply_override {2} else {1});}
    if slow_wall {assert!(effects.journal().operation(&operation).is_none());}
    if (slow_approval || (slow_storage && !reply_override)) && !cancel_after {
        assert_eq!(effects.journal().operation(&operation).ok_or("prepared effect lost")?.state,fss_core::EffectState::Prepared);
        assert!(effects.prepared(&operation).is_some());
    }
    if cancel_after {
        let receipt=effects.journal().operation(&operation).ok_or("cancelled effect lost")?;
        assert_eq!(receipt.state,fss_core::EffectState::Cancelled);
        assert_eq!(receipt.result_digest,Some(effects.journal().cancellation_proof(&operation,ContentDigest::sha256(b"retained fixture deadline evidence"))?));
    }
    Ok(())
}

#[test]
fn cancelled_clock_dispatch_is_returned_by_the_next_supervisor_step() -> Test {
    cancelled_clock_dispatch_scenario(false, false)
}

#[test]
fn cancelled_clock_dispatch_is_returned_on_supervisor_retirement() -> Test {
    cancelled_clock_dispatch_scenario(true, false)
}

#[test]
fn cancelled_clock_dispatch_with_separate_reply_budget_retains_its_trace() -> Test {
    cancelled_clock_dispatch_scenario(false, true)
}

fn cancelled_clock_dispatch_scenario(retire_directly: bool, separate_budget: bool) -> Test {
    use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
    use std::{pin::Pin, task::Context};
    struct PendingWrite<IO> { inner: IO, armed: Rc<Cell<bool>>, entered: Rc<Cell<bool>> }
    impl<IO: AsyncRead + Unpin> AsyncRead for PendingWrite<IO> {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx,out)
        }
    }
    impl<IO: AsyncWrite + Unpin> AsyncWrite for PendingWrite<IO> {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
            if self.armed.get() {self.entered.set(true);Poll::Pending} else {Pin::new(&mut self.inner).poll_write(cx,bytes)}
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {Pin::new(&mut self.inner).poll_flush(cx)}
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {Pin::new(&mut self.inner).poll_shutdown(cx)}
    }
    const SYNC: &[u8] = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":42,"inResponseTo":0}"#;
    let path=std::fs::canonicalize(std::env::temp_dir())?.join(format!("fss-unifi-sync-cancel-{}-{retire_directly}-{separate_budget}",std::process::id()));
    std::fs::create_dir(&path)?; let temp=Temp(path);
    let store=FileEffectJournal::create(temp.0.join("journal"),EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
    let mut effects=EffectCoordinator::with_journal(Box::new(store))?;
    let mut budget=BudgetVector::ZERO; budget.network_bytes=1_000_000; budget.bytes=1_000_000;
    let (mut authority,mut tree)=AuthorityCx::root(RootAuthoritySpec {
        trace_id:"trace:sync-cancel".into(),operation_id:OperationId::parse("operation:sync-cancel-owner")?,principal:"principal:fixture".into(),
        capabilities:vec![RuntimeGrant::AdapterNet.as_str().into(),RuntimeGrant::CameraManagementPrepare.as_str().into(),RuntimeGrant::CameraManagementCommit.as_str().into(),RuntimeGrant::ReadMedia.as_str().into()],
        deadline:Some(TimestampNs(60_000_000_000)),priority:1,budgets:budget,privacy_scope:"privacy:test".into(),retention_scope:"retention:test".into(),anchor_universe:ContentDigest::sha256(b"sync cancel fixture"),generation:1,
    },RegionId::new("region:sync-cancel")?,RegionKind::Process,budget,TimestampNs(1))?;
    let camera=ContentDigest::sha256(b"fixture camera"); let resource=format!("camera:{}",camera.to_text());
    let mut leases=LeaseRegistry::new(); let fence=leases.acquire(&resource,authority.region().as_str(),None,TimestampNs(2))?.fence; let leases=RefCell::new(leases);
    let conditions=Preconditions {camera,peer_admission:ContentDigest::sha256(b"fixture peer"),session_generation:1,previous_association:None,previous_clock:None,lease_fence:fence};
    let operation=OperationId::parse("operation:sync-cancel")?; let runtime=RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx=asupersync::Cx::current().ok_or("missing runtime context")?;
        let result=run_owned_async(&mut authority,&mut tree,TaskSpec {task_id:TaskId::new("task:sync-cancel")?,started_at:TimestampNs(3)},&cx,async |task,cx| {
            let output:Test=async {
                let listener=TcpListener::bind("127.0.0.1:0").await?; let address=listener.local_addr()?;
                let peer=std::thread::spawn(move || -> io::Result<()> {
                    let mut socket=std::net::TcpStream::connect_timeout(&address,Duration::from_secs(5))?; socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let mut request=HEAD.as_bytes().to_vec(); request.extend(frame(SYNC)); socket.write_all(&request)?;
                    let mut header=Vec::new(); let mut byte=[0u8;1]; while !header.ends_with(b"\r\n\r\n") {socket.read_exact(&mut byte)?;header.push(byte[0]);if header.len()>4096{return Err(io::Error::other("upgrade limit"));}}
                    if !header.starts_with(b"HTTP/1.1 101 "){return Err(io::Error::other("upgrade refused"));}
                    socket.set_read_timeout(Some(Duration::from_millis(500)))?;
                    match socket.read(&mut byte) {Ok(0)=>Ok(()),Err(error) if matches!(error.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::TimedOut)=>Ok(()),_=>Err(io::Error::other("unexpected clock reply bytes"))}
                });
                let (socket,_)=timeout(cx.now(),Duration::from_secs(5),listener.accept()).await??;
                let armed=Rc::new(Cell::new(false)); let entered=Rc::new(Cell::new(false));
                let clock=MeteredClock::new(task,cx,TimestampNs(4))?;
                let io=MeteredIo::with_clock(PendingWrite {inner:socket,armed:armed.clone(),entered:entered.clone()},clock,"fixture:camera",4096)?;
                let controller=Controller::new(Identity::new("FSS","12345678-1234-4abc-9abc-123456789abc","1.20.0")?,1)?;
                let session=owner::accept(io,ProtocolPolicy::RequireOffer,&FixtureAdmission,controller,Duration::from_secs(5)).await?;
                let media_listener=TcpListener::bind("127.0.0.1:0").await?;
                let media_peer=std::net::TcpStream::connect_timeout(&media_listener.local_addr()?,Duration::from_secs(5))?;
                let (media_socket,_)=timeout(cx.now(),Duration::from_secs(5),media_listener.accept()).await??;
                let ingress=TcpIngress::new(media_socket,"fixture:camera",4096,1_000_000)?;
                let framer=Framer::new(FlvLimits::default(),1024*1024)?;
                let recorder=recording::Recorder::new(SourceKey {connection:1,generation:1},recording::Limits::default())?;
                let pipeline=pipeline::Pipeline::new(DirectIngress::new(ingress,framer),recorder);
                let mut supervisor=supervisor::Supervisor::new(session,pipeline,conditions);
                if separate_budget {supervisor.set_time_sync_reply_wait(Some(Duration::from_secs(3)))?;}
                let guard=Guard {leases:&leases,clock}; let approval=FixtureApproval {revoke_stream:None};
                let mut owner=conversation::Owner {cx,task,clock,effects:&mut effects,leases:&leases,approval:&approval,management_authority:&guard,stream_authority:&guard,wall:&FixtureClock};
                armed.set(true);
                let poll_wait=if separate_budget {Duration::from_millis(100)} else {Duration::from_secs(5)};
                let mut future=Box::pin(supervisor.step_control(&mut owner,&operation,poll_wait));
                timeout(cx.now(),Duration::from_secs(3),poll_fn(|context| {
                    let state=future.as_mut().poll(context);
                    if entered.get() {return Poll::Ready(Ok::<(),&'static str>(()));}
                    if state.is_ready() {return Poll::Ready(Err("clock dispatch finished before cancellation"));}
                    context.waker().wake_by_ref(); Poll::Pending
                })).await??;
                drop(future);
                if separate_budget {assert_eq!(supervisor.set_time_sync_reply_wait(None),Err(conversation::Error::Configuration));}
                let (mut trace,retirement)=if retire_directly {
                    let mut retired=supervisor.retire();
                    let trace=retired.time_sync.take().ok_or("retirement lost clock trace")?;
                    (trace,retired)
                } else {
                    let trace=match supervisor.step_control(&mut owner,&operation,Duration::from_secs(1)).await {
                        supervisor::Step::TimeSyncInterrupted {trace}=>trace,
                        _=>return Err("supervisor did not return interrupted trace".into()),
                    };
                    let retired=supervisor.retire();
                    assert!(retired.time_sync.is_none());
                    (trace,retired)
                };
                assert_eq!(trace.operation(),Some(&operation)); assert!(trace.dispatch_started());
                assert!(trace.take_pending_permit().is_none() && trace.take_written().is_none() && trace.take_refusal().is_none());
                assert_eq!(retirement.controller.previous_phase,fss_reference::unifi_direct::Phase::Indeterminate);
                drop(media_peer); peer.join().map_err(|_|"fixture peer panic")??;
                Ok(())
            }.await;
            let outcome=if output.is_ok(){TaskOutcome::Indeterminate("cancelled dispatch requires reconciliation".into())}else{TaskOutcome::Failed("sync cancellation fixture failed".into())};
            TaskCompletion {output,outcome,completed_at:TimestampNs(59_000_000_000)}
        }).await?; result.receipt?;result.output
    })?;
    assert_eq!(effects.journal().operation(&operation).ok_or("missing clock effect")?.state,fss_core::EffectState::Committed);
    Ok(())
}

#[test]
fn cancelled_event_reply_retains_its_operation_and_fences_controller() -> Test {
    event_reply_trace_scenario(true, false)
}

#[test]
fn completed_event_reply_trace_retains_written_permit() -> Test {
    event_reply_trace_scenario(false, false)
}

#[test]
fn journaled_event_reply_denial_retains_intent_and_prepared_obligation() -> Test {
    event_reply_trace_scenario(false, true)
}

fn event_reply_trace_scenario(cancelled: bool, denied: bool) -> Test {
    use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
    use std::{pin::Pin, task::Context};
    struct PendingWrite<IO> { inner: IO, armed: Rc<Cell<bool>>, entered: Rc<Cell<bool>> }
    impl<IO: AsyncRead + Unpin> AsyncRead for PendingWrite<IO> {
        fn poll_read(mut self:Pin<&mut Self>,cx:&mut Context<'_>,out:&mut ReadBuf<'_>)->Poll<io::Result<()>> {Pin::new(&mut self.inner).poll_read(cx,out)}
    }
    impl<IO: AsyncWrite + Unpin> AsyncWrite for PendingWrite<IO> {
        fn poll_write(mut self:Pin<&mut Self>,cx:&mut Context<'_>,bytes:&[u8])->Poll<io::Result<usize>> {
            if self.armed.get(){self.entered.set(true);Poll::Pending}else{Pin::new(&mut self.inner).poll_write(cx,bytes)}
        }
        fn poll_flush(mut self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>> {Pin::new(&mut self.inner).poll_flush(cx)}
        fn poll_shutdown(mut self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>> {Pin::new(&mut self.inner).poll_shutdown(cx)}
    }
    struct DenyApproval;
    impl conversation::Approval for DenyApproval {
        fn approve(&self,_:&PreparedEffect)->Option<CommitApproval>{None}
    }
    let path=std::fs::canonicalize(std::env::temp_dir())?.join(format!("fss-unifi-event-cancel-{}-{cancelled}-{denied}",std::process::id()));
    std::fs::create_dir(&path)?;let temp=Temp(path);
    let store=FileEffectJournal::create(temp.0.join("journal"),EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
    let mut effects=EffectCoordinator::with_journal(Box::new(store))?;
    let mut budget=BudgetVector::ZERO;budget.network_bytes=1_000_000;budget.bytes=1_000_000;
    let (mut authority,mut tree)=AuthorityCx::root(RootAuthoritySpec {
        trace_id:"trace:event-cancel".into(),operation_id:OperationId::parse("operation:event-cancel-owner")?,principal:"principal:fixture".into(),
        capabilities:vec![RuntimeGrant::AdapterNet.as_str().into(),RuntimeGrant::CameraManagementPrepare.as_str().into(),RuntimeGrant::CameraManagementCommit.as_str().into(),RuntimeGrant::ReadMedia.as_str().into()],
        deadline:Some(TimestampNs(60_000_000_000)),priority:1,budgets:budget,privacy_scope:"privacy:test".into(),retention_scope:"retention:test".into(),anchor_universe:ContentDigest::sha256(b"event cancel fixture"),generation:1,
    },RegionId::new("region:event-cancel")?,RegionKind::Process,budget,TimestampNs(1))?;
    let camera=ContentDigest::sha256(b"fixture camera");let resource=format!("camera:{}",camera.to_text());
    let mut leases=LeaseRegistry::new();let fence=leases.acquire(&resource,authority.region().as_str(),None,TimestampNs(2))?.fence;let leases=RefCell::new(leases);
    let conditions=Preconditions {camera,peer_admission:ContentDigest::sha256(b"fixture peer"),session_generation:1,previous_association:None,previous_clock:None,lease_fence:fence};
    let operation=OperationId::parse("operation:event-cancel")?;
    let runtime=RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx=asupersync::Cx::current().ok_or("missing runtime")?;
        let result=run_owned_async(&mut authority,&mut tree,TaskSpec {task_id:TaskId::new("task:event-cancel")?,started_at:TimestampNs(3)},&cx,async |task,cx| {
            let output:Test=async {
                let listener=TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;
                let peer=std::thread::spawn(move || -> io::Result<()> {
                    let mut socket=std::net::TcpStream::connect_timeout(&address,Duration::from_secs(5))?;socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let mut request=HEAD.as_bytes().to_vec();request.extend(frame(REPLY_EVENT));socket.write_all(&request)?;
                    let mut header=Vec::new();let mut byte=[0u8;1];while !header.ends_with(b"\r\n\r\n") {socket.read_exact(&mut byte)?;header.push(byte[0]);if header.len()>4096{return Err(io::Error::other("upgrade limit"));}}
                    if !header.starts_with(b"HTTP/1.1 101 "){return Err(io::Error::other("upgrade refused"));}
                    if cancelled || denied {
                        match socket.read(&mut byte){Ok(0)=>Ok(()),_=>Err(io::Error::other("unexpected event reply bytes"))}
                    } else {
                        let response=receive_binary(&mut socket)?;
                        let parsed=fss_core::json_input::parse(std::str::from_utf8(&response).map_err(io::Error::other)?).map_err(io::Error::other)?;
                        if parsed.object().and_then(|fields|fields.get("inResponseTo")).and_then(|v|v.integer())!=Some(20){return Err(io::Error::other("wrong event correlation"));}
                        Ok(())
                    }
                });
                let (socket,_)=timeout(cx.now(),Duration::from_secs(5),listener.accept()).await??;
                let armed=Rc::new(Cell::new(false));let entered=Rc::new(Cell::new(false));let clock=MeteredClock::new(task,cx,TimestampNs(4))?;
                let io=MeteredIo::with_clock(PendingWrite {inner:socket,armed:armed.clone(),entered:entered.clone()},clock,"fixture:camera",4096)?;
                let controller=Controller::new(Identity::new("FSS","12345678-1234-4abc-9abc-123456789abc","1.20.0")?,1)?;
                let session=owner::accept(io,ProtocolPolicy::RequireOffer,&FixtureAdmission,controller,Duration::from_secs(5)).await?;
                let media_listener=TcpListener::bind("127.0.0.1:0").await?;let media_peer=std::net::TcpStream::connect_timeout(&media_listener.local_addr()?,Duration::from_secs(5))?;
                let (media_socket,_)=timeout(cx.now(),Duration::from_secs(5),media_listener.accept()).await??;
                let ingress=TcpIngress::new(media_socket,"fixture:camera",4096,1_000_000)?;
                let framer=Framer::new(FlvLimits::default(),1024*1024)?;let recorder=recording::Recorder::new(SourceKey {connection:1,generation:1},recording::Limits::default())?;
                let mut supervisor=supervisor::Supervisor::new(session,pipeline::Pipeline::new(DirectIngress::new(ingress,framer),recorder),conditions);
                let guard=Guard {leases:&leases,clock};let event_guard=EventGuard {guard:&guard};let approval=FixtureApproval {revoke_stream:None};
                let deny=DenyApproval;let approval:&dyn conversation::Approval=if denied {&deny}else{&approval};
                let mut owner=conversation::Owner {cx,task,clock,effects:&mut effects,leases:&leases,approval,management_authority:&event_guard,stream_authority:&guard,wall:&FixtureClock};
                let event=match supervisor.step_control(&mut owner,&operation,Duration::from_secs(5)).await {supervisor::Step::CameraEvent(event)=>event,_=>return Err("missing event".into())};
                let prepared=supervisor.prepare_journaled_event_reply(&mut owner,&event,"2026-11-05T10:00:00.000Z",&operation);
                if denied {
                    match prepared {
                        Err(supervisor::EventReplyPreparationError::Commit {operation:actual,intent,error:conversation::Error::Effect})=>{assert_eq!(actual,operation);assert_eq!(intent.source_digest(),Some(event.digest()));},
                        _=>return Err("denied event did not preserve intent".into()),
                    }
                    assert_eq!(owner.effects.journal().operation(&operation).ok_or("prepared effect missing")?.state,fss_core::EffectState::Prepared);
                    supervisor.abandon_event_reply(&owner,&event)?;
                    drop(supervisor);drop(media_peer);peer.join().map_err(|_|"peer panic")??;
                    return Ok(());
                }
                let mut trace=prepared.map_err(|error|format!("event preparation failed: {error:?}"))?;
                let intent=trace.intent();
                supervisor.dispatch_event_reply_tracked(&owner,conditions,Duration::ZERO,&mut trace).await.map_err(|_|"first trace refused")?;
                let refusal=trace.take_outcome().ok_or("refusal missing")?.err().ok_or("zero wait accepted")?;
                assert_eq!(refusal.reason,fss_reference::unifi_direct::receive::Error::WaitLimit);
                assert!(supervisor.dispatch_event_reply_tracked(&owner,conditions,Duration::from_secs(1),&mut trace).await.is_err());
                let mut trace=supervisor::EventReplyTrace::new(intent,refusal.permit);
                if !cancelled {
                    supervisor.dispatch_event_reply_tracked(&owner,conditions,Duration::from_secs(5),&mut trace).await.map_err(|_|"event trace refused")?;
                    assert_eq!(trace.operation(),&operation);assert!(trace.dispatch_started());
                    assert!(matches!(trace.take_outcome(),Some(Ok(ManagementWrite::Written {permit})) if permit.journal_backed()));
                    assert!(supervisor.dispatch_event_reply_tracked(&owner,conditions,Duration::from_secs(1),&mut trace).await.is_err());
                    drop(supervisor);drop(media_peer);peer.join().map_err(|_|"peer panic")??;
                    return Ok(());
                }
                armed.set(true);
                let mut future=Box::pin(supervisor.dispatch_event_reply_tracked(&owner,conditions,Duration::from_secs(5),&mut trace));
                timeout(cx.now(),Duration::from_secs(3),poll_fn(|context| {
                    let state=future.as_mut().poll(context);
                    if entered.get(){return Poll::Ready(Ok::<(),&'static str>(()));}
                    if state.is_ready(){return Poll::Ready(Err("event dispatch finished before cancellation"));}
                    context.waker().wake_by_ref();Poll::Pending
                })).await??;
                drop(future);
                assert_eq!(trace.operation(),&operation);assert_eq!(trace.intent().source_digest(),Some(event.digest()));assert!(trace.dispatch_started());
                assert!(trace.take_pending_permit().is_none() && trace.take_outcome().is_none());
                assert!(supervisor.dispatch_event_reply_tracked(&owner,conditions,Duration::from_secs(1),&mut trace).await.is_err());
                let retired=supervisor.retire();
                assert_eq!(retired.controller.previous_phase,fss_reference::unifi_direct::Phase::Indeterminate);
                drop(media_peer);peer.join().map_err(|_|"peer panic")??;
                Ok(())
            }.await;
            let outcome=if output.is_ok(){TaskOutcome::Indeterminate("cancelled event reply requires reconciliation".into())}else{TaskOutcome::Failed("event cancellation fixture failed".into())};
            TaskCompletion {output,outcome,completed_at:TimestampNs(59_000_000_000)}
        }).await?;result.receipt?;result.output
    })?;
    assert_eq!(effects.journal().operation(&operation).ok_or("event effect missing")?.state,if denied {fss_core::EffectState::Prepared}else{fss_core::EffectState::Committed});
    Ok(())
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
    startup_event_reply_scenario(true, false, false)
}

#[test]
fn startup_event_disclosure_denial_retains_request_and_permit() -> Test {
    startup_event_reply_scenario(false, false, false)
}

#[test]
fn startup_event_reply_is_serviced_while_waiting_for_media() -> Test {
    startup_event_reply_scenario(true, true, false)
}

#[test]
fn unknown_startup_request_reply_continues_handshake_with_custody() -> Test {
    startup_event_reply_scenario(true, false, true)
}

#[test]
fn unknown_startup_request_requires_separate_disclosure_authority() -> Test {
    startup_event_reply_scenario(false, false, true)
}

#[test]
fn unknown_startup_request_remains_distinct_through_supervisor() -> Test {
    startup_event_reply_scenario(true, true, true)
}

fn startup_event_reply_scenario(allow: bool, during_accept: bool, unknown: bool) -> Test {
    struct EchoGuard<'a, 'scope, 'task> { guard: &'a Guard<'a, 'scope, 'task>, allow: bool, unknown: bool }
    impl ManagementAuthority for EchoGuard<'_, '_, '_> {
        fn permits(&self, mac:[u8;6], intent:Intent, permit:&CommittedEffect)->bool {
            ManagementAuthority::permits(self.guard,mac,intent,permit)
        }
        fn permits_event_reply(&self, mac:[u8;6], intent:Intent, permit:&CommittedEffect)->bool {
            (self.allow || self.unknown) && ManagementAuthority::permits(self.guard,mac,intent,permit)
        }
        fn permits_startup_request_reply(&self, mac:[u8;6], intent:Intent, permit:&CommittedEffect)->bool {
            self.allow && ManagementAuthority::permits(self.guard,mac,intent,permit)
        }
    }
    const EVENT:&[u8]=br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventExample","messageId":20,"responseExpected":true,"payload":{"private":"fixture"}}"#;
    const UNKNOWN:&[u8]=br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"FutureCameraRequest","messageId":20,"responseExpected":true,"payload":{"private":"fixture"}}"#;
    let source = if unknown { UNKNOWN } else { EVENT };
    let expected_function = if unknown { "FutureCameraRequest" } else { "EventExample" };
    let path=std::fs::canonicalize(std::env::temp_dir())?.join(format!("fss-startup-event-{}-{allow}-{during_accept}-{unknown}",std::process::id()));
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
                    let mut request=HEAD.as_bytes().to_vec();if !during_accept || unknown {request.extend(frame(source));}request.extend(frame(HELLO));socket.write_all(&request)?;
                    let mut header=Vec::new();let mut byte=[0u8;1];while !header.ends_with(b"\r\n\r\n") {socket.read_exact(&mut byte)?;header.push(byte[0]);if header.len()>4096{return Err(io::Error::other("upgrade limit"));}}
                    if !header.starts_with(b"HTTP/1.1 101 "){return Err(io::Error::other("upgrade refused"));}
                    if !allow {return match socket.read(&mut byte) {Ok(0)=>Ok(()),_=>Err(io::Error::other("denied reply reached peer"))};}
                    let check_event=|bytes:&[u8]| -> io::Result<()> {
                        let parsed=fss_core::json_input::parse(std::str::from_utf8(bytes).map_err(io::Error::other)?).map_err(io::Error::other)?;
                        let fields=parsed.object().ok_or_else(||io::Error::other("reply object"))?;
                        if fields.get("functionName").and_then(|v|v.text())!=Some(expected_function) || fields.get("inResponseTo").and_then(|v|v.integer())!=Some(20) || fields.get("payload").and_then(|v|v.object()).and_then(|v|v.get("private")).and_then(|v|v.text())!=Some("fixture") {return Err(io::Error::other("wrong startup event reply"));} Ok(())
                    };
                    if !during_accept || unknown {check_event(&receive_binary(&mut socket)?)?;}
                    if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_hello".len()).any(|v|v==b"ubnt_avclient_hello") {return Err(io::Error::other("missing hello"));}
                    if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_paramAgreement".len()).any(|v|v==b"ubnt_avclient_paramAgreement") {return Err(io::Error::other("missing agreement"));}
                    let agreement_id=if during_accept && !unknown {2} else {3};
                    socket.write_all(&frame(format!("{{\"from\":\"ubnt_avclient\",\"to\":\"UniFiVideo\",\"functionName\":\"ubnt_avclient_paramAgreement\",\"messageId\":8,\"inResponseTo\":{agreement_id}}}").as_bytes()))?;
                    let stream=receive_binary(&mut socket)?;
                    if !stream.windows(b"ChangeVideoSettings".len()).any(|v|v==b"ChangeVideoSettings") {return Err(io::Error::other("missing stream request"));}
                    if during_accept {
                        let message=std::str::from_utf8(&stream).map_err(io::Error::other)?;
                        let destination=message.split_once("tcp://").and_then(|(_,s)|s.split_once('?')).map(|(a,_)|a).ok_or_else(||io::Error::other("missing destination"))?.parse::<SocketAddr>().map_err(io::Error::other)?;
                        if !matches!(destination,SocketAddr::V4(a) if a.ip().is_loopback() && a.port()!=0) {return Err(io::Error::other("invalid destination"));}
                        if !unknown {socket.write_all(&frame(source))?;check_event(&receive_binary(&mut socket)?)?;}
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
                let mut session=owner::accept(io,ProtocolPolicy::RequireOffer,&FixtureAdmission,controller,Duration::from_secs(5)).await?;if unknown { session.bind_startup_events_and_requests(&inbox)?; } else { session.bind_startup_events(&inbox)?; }
                let guard=Guard {leases:&leases,clock};let echo=EchoGuard {guard:&guard,allow,unknown};let approval=FixtureApproval {revoke_stream:None};
                let mut owner=conversation::Owner {cx,task,clock,effects:&mut effects,leases:&leases,approval:&approval,management_authority:&echo,stream_authority:&guard,wall:&FixtureClock};
                let request=StreamStart::new(VideoChannel::Video2,SocketAddrV4::new(Ipv4Addr::LOCALHOST,17551),VideoCodec::H264,AudioCodec::Aac,"0123456789abcdef")?;
                let cfg=conversation::Config {hello:&hello,agreement:&agreement,stream:&stream,time_sync:&[],management:conditions,stream_conditions,request:&request,wait:Duration::from_secs(5)};
                let options=conversation::StartupEventReplies {operations:&event_ops};let mut trace=conversation::StartupEventTrace::default();
                let result=if during_accept {
                    let policy=FixtureMediaAdmission {listen:Cell::new(true),peer:Cell::new(true)};
                    let start=listener::Start {bind:SocketAddrV4::new(Ipv4Addr::LOCALHOST,0),resource:"fixture:camera",admission:&policy,channel:VideoChannel::Video2,video:VideoCodec::H264,audio:AudioCodec::Aac,stream_name:"0123456789abcdef",hello:&hello,agreement:&agreement,stream:&stream,time_sync:&[],management:conditions,stream_conditions,chunk_bytes:4096,max_bytes:100_000,bind_wait:Duration::from_secs(5),conversation_wait:Duration::from_secs(5),accept_wait:Duration::from_secs(5)};
                    let mut start_trace=listener::StartTrace::default();
                    listener::start_before_reply_with_events_tracked(&mut owner,&mut session,&start,Framer::new(FlvLimits::default(),1024*1024)?,recording::Recorder::new(SourceKey {connection:1,generation:1},recording::Limits::default())?,&mut start_trace,None,&options,&mut trace).await.map(|started| Some(started.pipeline)).map_err(|e|format!("listener startup stopped: {e:?}"))
                } else {
                    owner.start_dispatched_with_options(&mut session,&cfg,None,Some((&options,&mut trace))).await.map(|_|None).map_err(|e|format!("conversation stopped: {e:?}"))
                };
                if during_accept {startup_done_tx.send(()).map_err(io::Error::other)?;}
                if during_accept {if let Err(error)=&result {return Err(error.clone().into());}}
                assert!(trace.attempted());assert_eq!(trace.attempts().len(),1);assert_eq!(trace.attempts()[0].source(),ContentDigest::sha256(source));assert!(trace.attempts()[0].dispatch_started());
                assert_eq!(trace.attempts()[0].intent().ok_or("reply intent missing")?.kind(), if unknown {fss_reference::unifi_direct::MessageKind::StartupRequestReply} else {fss_reference::unifi_direct::MessageKind::EventReply});
                if unknown && during_accept {
                    let pipeline=result.map_err(|e|->Box<dyn Error>{e.into()})?.ok_or("pipeline missing")?;
                    let mut supervisor=supervisor::Supervisor::new(session,pipeline,conditions);
                    match supervisor.step(&mut owner,&event_ops[0],Duration::from_secs(5)).await {
                        supervisor::Step::StartupRequest(frame)=>{assert_eq!(frame.source(),source);assert!(frame.interpret().is_err());}
                        _=>return Err("startup request was not preserved distinctly".into()),
                    }
                    let _retired=supervisor.retire();
                    peer.join().map_err(|_|"peer panic")??;
                    return Ok(());
                }
                let retained=inbox.take().ok_or("event source missing")?;assert_eq!(retained.source(),source);if unknown {assert_eq!(retained.kind(),fss_reference::unifi_direct::events::Kind::StartupRequest);assert!(retained.interpret().is_err());}
                if allow {
                    if let Some(pipeline)=result.map_err(|e|->Box<dyn Error>{e.into()})? {let _=pipeline.retire();}
                    assert!(matches!(trace.attempts_mut()[0].take_written(),Some(ManagementWrite::Written {..})));
                } else {
                    assert_eq!(result.err().as_deref(),Some("conversation stopped: Effect"));assert_eq!(trace.attempts_mut()[0].take_refusal().ok_or("missing refused permit")?.reason,fss_reference::unifi_direct::receive::Error::Denied);
                }
                let retired=session.retire();if !allow {assert_eq!(retired.event_reply,Some((20,ContentDigest::sha256(source))));assert_eq!(retired.event_reply_is_startup_request,unknown);}
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
    media_fixture_with_pictures(include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264"), 3)
}

fn video_only_media_fixture() -> Result<Vec<u8>, Box<dyn Error>> {
    video_only_media_fixture_from(media_fixture()?)
}

fn video_only_media_fixture_from(wire: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut result = wire[..13].to_vec();
    result[4] = 1;
    let mut offset = 13;
    while offset < wire.len() {
        if offset + 15 > wire.len() { return Err("fixture tag truncated".into()); }
        let size = (usize::from(wire[offset + 1]) << 16) | (usize::from(wire[offset + 2]) << 8) | usize::from(wire[offset + 3]);
        let end = offset.checked_add(11 + size + 4).ok_or("fixture size overflow")?;
        if end > wire.len() { return Err("fixture tag length".into()); }
        if wire[offset] != 8 { result.extend_from_slice(&wire[offset..end]); }
        offset = end;
    }
    // An incomplete non-tag suffix must remain unframed when the source stops.
    result.extend_from_slice(&[0x7f, 0x01, 0x02]);
    Ok(result)
}

fn media_fixture_with_pictures(input: &[u8], picture_cycle: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    media_fixture_with_count(input, picture_cycle, 7)
}

fn media_fixture_with_count(input: &[u8], picture_cycle: usize, count: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let nals: Vec<_> = fss_codec_h264::annex_b_nal_units(input).collect();
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
    for index in 0..count {
        // Synthetic AAC bodies exercise source custody and muxing only; they
        // are not claimed to be decodable audio or synchronized with video.
        let mut audio=flv_tag(index as u32 * 64,&[0xaf,1,2]);
        audio[0]=8;
        result.extend(audio);
        let nal = pictures[index % picture_cycle];
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
    conversation_scenario_with_worker_guard(revoke_stream, revoke_after_start, revoke_audio_pending, reply_after_media, never_reply, early_reply, stop_mode, emit_event, archive_guard, false, false, false)
}

fn conversation_scenario_with_worker_guard(revoke_stream: bool, revoke_after_start: bool, revoke_audio_pending: bool, reply_after_media: bool, never_reply: bool, early_reply: bool, stop_mode: u8, emit_event: bool, archive_guard: bool, async_archive: bool, cancel_archive: bool, audio_change: bool) -> Test {
    conversation_scenario_with_worker_guard_mode(revoke_stream, revoke_after_start, revoke_audio_pending, reply_after_media, never_reply, early_reply, stop_mode, emit_event, archive_guard, async_archive, cancel_archive, audio_change, false, None, 0)
}

fn bootstrap_av_transition<'run, 'owner, 'scope, 'task, IO>(
    coordinator: &'run mut fss_reference::unifi_direct::source_coordinator::Coordinator,
    driver: Box<fss_reference::unifi_direct::av_bootstrap_driver::Driver<'scope, 'task, IO>>,
    resources: Box<fss_reference::unifi_direct::av_unknown_worker_guard::BootstrapResources>,
    owner: &'run mut conversation::Owner<'owner, 'scope, 'task>,
    operations: &'run [OperationId],
    task: &'scope fss_runtime::execution::TaskCx<'task>,
    cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
    source_admission: fss_reference::unifi_direct::source_coordinator::ArchiveAdmission<'run>,
) -> std::pin::Pin<Box<dyn Future<Output = Test> + 'run>>
where
    IO: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin + 'run,
    'owner: 'run,
    'scope: 'run,
    'task: 'run,
{
    Box::pin(async move {
        let prepared=coordinator.prepare_recording_guard(driver,resources).map_err(|_|"coordinated A/V preparation refused")?;
        let prepared=prepared.prepare_guard().map_err(|_|"coordinated sink conversion refused")?;
        let started=prepared.finish().map_err(|_|"coordinated A/V transition refused")?;
        assert_eq!(started.origin.audio_ticks,1024);
        drive_bootstrap_guard(coordinator,Box::new(started.guard),owner,operations,task,cx,clock,source_admission).await
    })
}

fn drive_bootstrap_guard<'run, 'owner, 'scope, 'task, IO>(
    coordinator: &'run mut fss_reference::unifi_direct::source_coordinator::Coordinator,
    mut guard: Box<fss_reference::unifi_direct::av_unknown_worker_guard::Guard<'scope, 'task, IO>>,
    owner: &'run mut conversation::Owner<'owner, 'scope, 'task>,
    operations: &'run [OperationId],
    task: &'scope fss_runtime::execution::TaskCx<'task>,
    cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
    source_admission: fss_reference::unifi_direct::source_coordinator::ArchiveAdmission<'run>,
) -> std::pin::Pin<Box<dyn Future<Output = Test> + 'run>>
where
    IO: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin + 'run,
    'owner: 'run,
    'scope: 'run,
    'task: 'run,
{
    use fss_reference::unifi_direct::{av_unknown_worker_guard as unknown, av_worker, source_coordinator};
    Box::pin(async move {
        struct GuardObserver {operation:OperationId,event:Option<source_coordinator::Step>}
        impl source_coordinator::Observer for GuardObserver {
            fn next_operation(&mut self)->Option<OperationId>{Some(self.operation.clone())}
            fn observe(&mut self,event:source_coordinator::Step)->Result<source_coordinator::Decision,source_coordinator::Step>{
                if matches!(&event,source_coordinator::Step::Session(unknown::SessionEvent::Advance(unknown::Advance::Archive(unknown::Drive::Control {step:supervisor::Step::Idle,completion:None})))) {return Ok(source_coordinator::Decision::Continue);}
                if self.event.is_some(){return Err(event);}
                self.event=Some(event);Ok(source_coordinator::Decision::Yield)
            }
        }
        let mut observer=GuardObserver {operation:operations[6].clone(),event:None};
        let av_admission=source_coordinator::ArchiveAdmission {resource:"fixture:bootstrap-av",cost:&BudgetVector::ZERO};
        assert!(matches!(Box::pin(coordinator.run_slice(&mut guard,owner,Duration::from_secs(5),1,task,cx,clock,av_admission,source_admission,&mut observer)).await,source_coordinator::SliceStop::ObserverYielded));
        assert!(matches!(observer.event.take(),Some(source_coordinator::Step::Session(unknown::SessionEvent::Advance(unknown::Advance::Source(unknown::Step::SourceQueued))))));
        assert!(matches!(Box::pin(coordinator.run_slice(&mut guard,owner,Duration::from_secs(5),1,task,cx,clock,av_admission,source_admission,&mut observer)).await,source_coordinator::SliceStop::ObserverYielded));
        assert!(matches!(observer.event.take(),Some(source_coordinator::Step::Session(unknown::SessionEvent::Advance(unknown::Advance::ArchiveStarted)))));
        let completion=timeout(cx.now(),Duration::from_secs(10),async {
            loop {
                match Box::pin(coordinator.run_slice(&mut guard,owner,Duration::from_millis(100),32,task,cx,clock,av_admission,source_admission,&mut observer)).await {
                    source_coordinator::SliceStop::ObserverYielded=>match observer.event.take(){
                        Some(source_coordinator::Step::Session(unknown::SessionEvent::Advance(unknown::Advance::Archive(unknown::Drive::Archive(completion))))) | Some(source_coordinator::Step::Session(unknown::SessionEvent::Advance(unknown::Advance::Archive(unknown::Drive::Control {completion:Some(completion),..}))))=>break Ok(completion),
                        _=>break Err("unexpected A/V archive event"),
                    },
                    source_coordinator::SliceStop::Yielded=>(),
                    _=>break Err("A/V archive slice stopped"),
                }
            }
        }).await??;
        if completion.runtime.is_err() || !matches!(completion.outcome,av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(_))) {return Err("bootstrap A/V publication failed".into());}
        let retired=(*guard).retire().map_err(|_|"bootstrap A/V guard did not retire")?;
        if retired.held.is_some() || retired.worker.parts.sink.retire().pending.is_some(){return Err("bootstrap A/V source remained pending".into());}
        drop(retired.supervisor);
        Ok(())
    })
}

struct OwnedEventProbe<'a> {
    signal: &'a std::sync::mpsc::Sender<()>,
    source_block: &'a std::sync::atomic::AtomicBool,
    conditions: Preconditions,
    operation: &'a OperationId,
}

fn drive_owned_recording<'run, 'owner, 'scope, 'task, IO>(
    session: fss_reference::unifi_direct::recording_session::Session<'scope, 'task, IO>,
    owner: &'run mut conversation::Owner<'owner, 'scope, 'task>,
    operation: &'run OperationId,
    stream_conditions: intent::Preconditions,
    probe: Option<OwnedEventProbe<'run>>,
    camera_replay: bool,
    expect_video_only: bool,
    expect_rollover_custody: bool,
    minimum_av_segments: usize,
    read_authority: &'run dyn fss_reference::unifi_direct::archive::ReadAuthority,
    task: &'scope fss_runtime::execution::TaskCx<'task>,
    cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(fss_reference::unifi_direct::source_coordinator::Coordinator,Vec<fss_reference::unifi_direct::archive::UnknownTimePin>,fss_reference::unifi_direct::recording_storage::HistoryMinimum,fss_reference::unifi_direct::archive::UnknownTimePin),Box<dyn std::error::Error>>> + 'run>>
where
    IO: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin + 'run,
    'owner: 'run,
    'scope: 'run,
    'task: 'run,
{
    use fss_reference::unifi_direct::{av_bootstrap_driver, av_unknown_worker_guard as unknown, av_worker, recording_session, source_coordinator, source_handoff, source_worker};
    Box::pin(async move {
        struct SessionObserver {
            prefix: OperationId,
            sequence: u64,
            enabled: bool,
            refuse: bool,
            event: Option<Box<recording_session::Step>>,
        }
        impl recording_session::Observer for SessionObserver {
            fn next_operation(&mut self) -> Option<OperationId> {
                if !self.enabled { return None; }
                let operation=OperationId::parse(format!("{}:owned-{:016x}",self.prefix.as_str(),self.sequence)).ok()?;
                self.sequence=self.sequence.checked_add(1)?;
                Some(operation)
            }
            fn observe(&mut self,event:Box<recording_session::Step>)->Result<source_coordinator::Decision,Box<recording_session::Step>> {
                if self.refuse {self.refuse=false;return Err(event);}
                assert!(self.event.is_none());
                self.event=Some(event);
                Ok(source_coordinator::Decision::Yield)
            }
        }
        let mut bootstrap=match session.stop() {recording_session::Stop::Bootstrap(shutdown)=>shutdown,_=>return Err("wrong bootstrap stop phase".into())};
        if bootstrap.join_source().await.is_some(){return Err("unexpected bootstrap source attempt".into());}
        let (coordinator,driver,resources)=bootstrap.finish().map_err(|_|"bootstrap stop did not finish")?;
        let session=recording_session::Session::new(coordinator,driver,resources);
        let mut session=Box::new(session);
        {
            let mut control=session.control().ok_or("bootstrap control unavailable")?;
            let intent=control.prepare_quiesce(owner,VideoChannel::Video2,AudioCodec::Aac,"2026-11-05T10:00:00.000Z",stream_conditions)?;
            let id=intent.message_id();
            let abandoned=control.abandon_prepared_stream(owner,intent)?;
            assert_eq!((abandoned.id,abandoned.kind),(id,fss_reference::unifi_direct::MessageKind::QuiesceStream(VideoChannel::Video2)));
        }
        let av=source_coordinator::ArchiveAdmission {resource:"fixture:bootstrap-av",cost:&BudgetVector::ZERO};
        let source=source_coordinator::ArchiveAdmission {resource:"fixture:bootstrap-source",cost:&BudgetVector::ZERO};
        let mut observer=SessionObserver {prefix:operation.clone(),sequence:0,enabled:false,refuse:true,event:None};
        assert!(matches!(Box::pin(session.run_slice(owner,Duration::ZERO,1,task,cx,clock,av,source,&mut observer)).await,recording_session::SliceStop::Configuration));
        assert_eq!(observer.sequence,0);
        assert!(matches!(Box::pin(session.run_slice(owner,Duration::from_millis(100),1,task,cx,clock,av,source,&mut observer)).await,recording_session::SliceStop::OperationUnavailable));
        assert_eq!(observer.sequence,0);
        observer.enabled=true;
        let mut refused=false;
        let mut pins=Vec::new();let mut av_pin=None;let mut av_published=0;let mut offered=0;let mut paired=0;let mut syncs=0;let mut started=false;let mut queued=false;let mut archive_started=false;let mut event_replied=false;
        fn accept_sync(mut trace:conversation::TimeSyncTrace,effects:&EffectCoordinator)->Result<(),&'static str> {
            let operation=trace.operation().ok_or("owned recorder sync operation missing")?;
            if !trace.dispatch_started() || effects.journal().operation(operation).map(|entry|entry.state)!=Some(fss_core::EffectState::Committed){return Err("owned recorder sync trace or journal missing");}
            match trace.take_written() {
                Some(ManagementWrite::Written {permit}) if permit.journal_backed()=>Ok(()),
                _=>Err("owned recorder sync permit missing"),
            }
        }
        fn accept_source(completion:source_worker::Completion,pins:&mut Vec<fss_reference::unifi_direct::archive::UnknownTimePin>)->Result<(),&'static str> {
            if completion.runtime.is_err(){return Err("owned bootstrap source runtime failed");}
            match completion.outcome {source_worker::Outcome::Publication(source_worker::Publication::Published {pin,..})=>{pins.push(pin);Ok(())},_=>Err("owned bootstrap source publication failed")}
        }
        fn accept_av(completion:av_worker::UnknownTimeCompletion)->Result<fss_reference::unifi_direct::archive::UnknownTimePin,&'static str> {
            if completion.runtime.is_err(){return Err("owned A/V runtime failed");}
            match completion.outcome {av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(published))=>Ok(published.pin),_=>Err("owned A/V publication failed")}
        }
        timeout(cx.now(),Duration::from_secs(if camera_replay {45}else{15}),async {
            loop {
                let stop=Box::pin(session.run_slice(owner,Duration::from_millis(100),1,task,cx,clock,av,source,&mut observer)).await;
                let step=match stop {
                    recording_session::SliceStop::ObserverRefused(step) if !refused=>{refused=true;*step},
                    recording_session::SliceStop::ObserverYielded=>*observer.event.take().ok_or("owned observer lost an accepted event")?,
                    recording_session::SliceStop::Halted(step)=>{
                        match &*step {
                            recording_session::Step::Bootstrap(source_coordinator::BootstrapStep::SourceStartRefused(error))=>eprintln!("owned recorder source start refused {error:?}"),
                            recording_session::Step::Bootstrap(source_coordinator::BootstrapStep::Driver(av_bootstrap_driver::Step::Supervisor(event)))=>eprintln!("owned recorder halted supervisor {:?}",std::mem::discriminant(event)),
                            recording_session::Step::Bootstrap(source_coordinator::BootstrapStep::Driver(event))=>eprintln!("owned recorder halted driver {:?}",std::mem::discriminant(event)),
                            recording_session::Step::Bootstrap(event)=>eprintln!("owned recorder halted bootstrap {:?}",std::mem::discriminant(event)),
                            recording_session::Step::Recording(event)=>eprintln!("owned recorder halted recording {:?}",std::mem::discriminant(event)),
                            _=>eprintln!("owned recorder halted session {:?}",std::mem::discriminant(&*step)),
                        }
                        return Err("owned recorder halted");
                    },
                    _=>return Err("owned recorder slice stopped unexpectedly"),
                };
                match step {
                    recording_session::Step::Bootstrap(source_coordinator::BootstrapStep::SourceOffered(source_handoff::BootstrapResult::Accepted {audio,..}))=>{
                        offered+=1;
                        if matches!(audio,Some(pipeline::AudioEvent::Observed(fss_packet::extended_flv::aac_track::Observation::UnconfiguredSample {..}))){paired+=1;}
                    },
                    recording_session::Step::Bootstrap(source_coordinator::BootstrapStep::SourceStarted)=>{
                        if let Some(probe)=&probe {probe.signal.send(()).map_err(|_|"owned event signal failed")?;}
                    },
                    recording_session::Step::Bootstrap(source_coordinator::BootstrapStep::Driver(av_bootstrap_driver::Step::Retained) | source_coordinator::BootstrapStep::Driver(av_bootstrap_driver::Step::Supervisor(supervisor::Step::Media(pipeline::Step::Progress {..}) | supervisor::Step::Idle)))=>(),
                    recording_session::Step::Bootstrap(source_coordinator::BootstrapStep::Driver(av_bootstrap_driver::Step::Supervisor(supervisor::Step::TimeSyncWritten {trace})))=>{accept_sync(trace,owner.effects)?;syncs+=1;},
                    recording_session::Step::Bootstrap(source_coordinator::BootstrapStep::Driver(av_bootstrap_driver::Step::Forward {push:recording::Push::Buffered,..}))=>(),
                    recording_session::Step::Bootstrap(source_coordinator::BootstrapStep::SourceArchive(source_handoff::Drive::Completed(completion)))=>accept_source(completion,&mut pins)?,
                    recording_session::Step::Bootstrap(source_coordinator::BootstrapStep::SourceArchive(source_handoff::Drive::Control {step,completion}))=>{
                        if let Some(completion)=completion {accept_source(completion,&mut pins)?;}
                        match step {
                            supervisor::Step::Idle=>(),
                            supervisor::Step::TimeSyncWritten {trace}=>{accept_sync(trace,owner.effects)?;syncs+=1;},
                            supervisor::Step::CameraEvent(frame)=>{
                                let probe=probe.as_ref().ok_or("unexpected owned camera event")?;
                                if event_replied || frame.source()!=REPLY_EVENT || !frame.response_expected(){return Err("wrong owned camera event");}
                                let mut trace=session.control().ok_or("event control unavailable")?.prepare_journaled_event_reply(owner,&frame,"2026-11-05T10:00:00.000Z",probe.operation).map_err(|_|"event journal preparation refused")?;
                                let mut control=session.control().ok_or("event control disappeared")?;
                                Box::pin(control.dispatch_event_reply_tracked(owner,probe.conditions,Duration::from_secs(5),&mut trace)).await.map_err(|_|"event trace unavailable")?;
                                match trace.take_outcome() {
                                    Some(Ok(ManagementWrite::Written {permit})) if permit.journal_backed()=>(),
                                    _=>return Err("owned event dispatch did not complete"),
                                }
                                event_replied=true;
                                probe.source_block.store(false,std::sync::atomic::Ordering::Release);
                            },
                            _=>return Err("owned bootstrap control stopped"),
                        }
                    },
                    recording_session::Step::RecordingStarted(origin)=>{
                        if started || (!camera_replay && origin.audio_ticks!=1024){return Err("owned recording started incorrectly");}
                        let mut control=session.control().ok_or("recording control unavailable")?;
                        let intent=control.prepare_quiesce(owner,VideoChannel::Video2,AudioCodec::Aac,"2026-11-05T10:00:00.000Z",stream_conditions).map_err(|_|"recording quiesce preparation refused")?;
                        let id=intent.message_id();
                        let abandoned=control.abandon_prepared_stream(owner,intent).map_err(|_|"recording quiesce abandonment refused")?;
                        assert_eq!((abandoned.id,abandoned.kind),(id,fss_reference::unifi_direct::MessageKind::QuiesceStream(VideoChannel::Video2)));
                        started=true;
                    },
                    recording_session::Step::Recording(source_coordinator::Step::Session(unknown::SessionEvent::Advance(unknown::Advance::Source(unknown::Step::SourceQueued))))=>queued=true,
                    recording_session::Step::Recording(source_coordinator::Step::Session(unknown::SessionEvent::Advance(unknown::Advance::Source(unknown::Step::Supervisor(supervisor::Step::Media(pipeline::Step::Progress {..}) | supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Buffered)) | supervisor::Step::Idle)))))=>(),
                    recording_session::Step::Recording(source_coordinator::Step::Session(unknown::SessionEvent::Audio(pipeline::AudioEvent::Observed(fss_packet::extended_flv::aac_track::Observation::UnconfiguredSample {..}))))=>(),
                    recording_session::Step::Recording(source_coordinator::Step::Session(unknown::SessionEvent::Advance(unknown::Advance::ArchiveStarted)))=>archive_started=true,
                    recording_session::Step::Recording(source_coordinator::Step::Session(unknown::SessionEvent::Advance(unknown::Advance::Archive(unknown::Drive::Archive(completion)))))=>{
                        av_pin=Some(accept_av(completion)?);
                        av_published+=1;
                        if av_published>=minimum_av_segments { break Ok(()); }
                    },
                    recording_session::Step::Recording(source_coordinator::Step::Session(unknown::SessionEvent::Advance(unknown::Advance::Archive(unknown::Drive::Control {step,completion}))))=>{
                        match step {supervisor::Step::Idle=>(),supervisor::Step::TimeSyncWritten {trace}=>{accept_sync(trace,owner.effects)?;syncs+=1;},_=>return Err("owned recording control stopped")}
                        if let Some(completion)=completion {
                            av_pin=Some(accept_av(completion)?);
                            av_published+=1;
                            if av_published>=minimum_av_segments { break Ok(()); }
                        }
                    },
                    other=>{
                        match &other {
                            recording_session::Step::Bootstrap(source_coordinator::BootstrapStep::Driver(event))=>eprintln!("owned recorder unexpected driver {:?}",std::mem::discriminant(event)),
                            recording_session::Step::Bootstrap(source_coordinator::BootstrapStep::SourceArchive(source_handoff::Drive::Control {step,..}))=>eprintln!("owned recorder unexpected control {:?}",std::mem::discriminant(step)),
                            recording_session::Step::Bootstrap(event)=>eprintln!("owned recorder unexpected bootstrap {:?}",std::mem::discriminant(event)),
                            recording_session::Step::Recording(source_coordinator::Step::Session(unknown::SessionEvent::Advance(unknown::Advance::Source(unknown::Step::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(push)))))))=>eprintln!("owned recorder unexpected recording push {:?}",std::mem::discriminant(push)),
                            recording_session::Step::Recording(source_coordinator::Step::Session(unknown::SessionEvent::Advance(unknown::Advance::Source(unknown::Step::Supervisor(supervisor::Step::Media(media))))))=>eprintln!("owned recorder unexpected media {:?}",std::mem::discriminant(media)),
                            recording_session::Step::Recording(source_coordinator::Step::Session(unknown::SessionEvent::Advance(unknown::Advance::Source(unknown::Step::Supervisor(event)))))=>eprintln!("owned recorder unexpected supervisor {:?}",std::mem::discriminant(event)),
                            recording_session::Step::Recording(source_coordinator::Step::Session(unknown::SessionEvent::Advance(unknown::Advance::Source(event))))=>eprintln!("owned recorder unexpected source {:?}",std::mem::discriminant(event)),
                            recording_session::Step::Recording(source_coordinator::Step::Session(unknown::SessionEvent::Advance(event)))=>eprintln!("owned recorder unexpected advance {:?}",std::mem::discriminant(event)),
                            recording_session::Step::Recording(event)=>eprintln!("owned recorder unexpected recording {:?}",std::mem::discriminant(event)),
                            _=>eprintln!("owned recorder unexpected session phase"),
                        }
                        return Err("owned recorder returned an unexpected step");
                    },
                }
            }
        }).await??;
        let prior_sync=owner.effects.journal().operation(operation).is_some_and(|entry|entry.state==fss_core::EffectState::Committed);
        if !refused || observer.sequence<2 || (syncs==0 && !(camera_replay && prior_sync)) || !started || !queued || !archive_started || (!camera_replay && (offered==0 || paired==0)) || paired>offered || pins.len()!=offered || (probe.is_some() && !event_replied) {
            eprintln!("owned_accounting refused={refused} steps={} syncs={syncs} prior_sync={prior_sync} started={started} queued={queued} archive_started={archive_started} offered={offered} paired={paired} pins={} event_required={} event_replied={event_replied}",observer.sequence,pins.len(),probe.is_some());
            return Err("owned recorder did not account for source, A/V or event".into());
        }
        let mut shutdown=match (*session).stop() {recording_session::Stop::Recording(shutdown)=>shutdown,_=>return Err("wrong recording stop phase".into())};
        if shutdown.join_source().await.is_some() || shutdown.join_av().await.is_some(){return Err("owned recorder had an unexpected running archive".into());}
        let (coordinator,guard)=shutdown.finish().map_err(|_|"owned recorder shutdown did not finish")?;
        let retired=(*guard).retire().map_err(|_|"owned recorder guard retirement refused")?;
        if retired.worker.rollover_custody.is_some() != expect_rollover_custody { return Err("owned recorder rollover custody mismatch".into()); }
        let mut parts=retired.worker.parts;
        if retired.held.is_some() || parts.sink.retire().pending.is_some(){return Err("owned recorder left an A/V source pending".into());}
        let av_pin=av_pin.ok_or("owned A/V pin missing")?;
        use fss_reference::unifi_direct::archive::{read_unknown_time_av_any, RecoveredUnknownTimeAv};
        let clip=read_unknown_time_av_any(&mut parts.deployment,av_pin,read_authority,fss_reference::unifi_direct::archive::Limits::default(),&mut fss_geometry::WorkBudget::new(4_000_000_000),&parts.replay)?;
        match clip {
            RecoveredUnknownTimeAv::AudioVideo(clip) if !expect_video_only && clip.video_samples()>0 && clip.audio().frames>0 => {
                if camera_replay {println!("owned_av_readback video_samples={} audio_frames={} capture_bounds=unknown",clip.video_samples(),clip.audio().frames);}
            },
            RecoveredUnknownTimeAv::VideoOnly(clip) if expect_video_only && clip.video_samples()>0 => {
                println!("owned_av_readback video_samples={} audio_coverage=unknown capture_bounds=unknown",clip.video_samples());
            },
            _=>return Err("owned recording profile or readback was incorrect".into()),
        }
        drop(retired.supervisor);
        let av_minimum=fss_reference::unifi_direct::recording_storage::HistoryMinimum {journal:parts.journal.anchor(),keeper:parts.keeper.anchor()};
        Ok((coordinator,pins,av_minimum,av_pin))
    })
}

fn conversation_scenario_with_worker_guard_mode(revoke_stream: bool, revoke_after_start: bool, revoke_audio_pending: bool, reply_after_media: bool, never_reply: bool, early_reply: bool, stop_mode: u8, emit_event: bool, archive_guard: bool, async_archive: bool, cancel_archive: bool, audio_change: bool, unknown_archive: bool, replay_wire: Option<Vec<u8>>, late_audio_change: u8) -> Test {
    let camera_replay = replay_wire.is_some();
    static NEXT_SCENARIO: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let scenario = NEXT_SCENARIO.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::fs::canonicalize(std::env::temp_dir())?.join(format!(
        "fss-unifi-task-conversation-{}-{scenario}-{revoke_stream}-{revoke_after_start}-{revoke_audio_pending}-{reply_after_media}-{never_reply}-{early_reply}",
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
    budget.network_bytes = if camera_replay { 32_000_000 } else { 1_000_000 };
    budget.bytes = if camera_replay { 32_000_000 } else { 1_000_000 };
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
        OperationId::parse("operation:owned-event-reply")?,
        OperationId::parse("operation:rollover-background-time-sync")?,
        OperationId::parse("operation:rollover-attachment-time-sync")?,
        OperationId::parse("operation:rollover-prior-custody-time-sync")?,
        OperationId::parse("operation:audio-budget-time-sync")?,
        OperationId::parse("operation:rollover-supplies-time-sync")?,
        OperationId::parse("operation:provisioning-time-sync")?,
        OperationId::parse("operation:third-rollover-time-sync")?,
        OperationId::parse("operation:rollover-event-reply")?,
    ];
    let blocking_workers=if late_audio_change==11 {2} else {1};
    let runtime = RuntimeBuilder::current_thread().blocking_threads(blocking_workers, blocking_workers).build()?;
    runtime.block_on(async {
        let cx=asupersync::Cx::current().ok_or("missing runtime")?;
        let result=run_owned_async(&mut authority,&mut tree,TaskSpec { task_id:TaskId::new("task:conversation")?, started_at:TimestampNs(3) },&cx,async |task,cx| {
            let output: Test = Box::pin(async {
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
                let mut wire=match replay_wire {
                    Some(wire)=>wire,
                    None if late_audio_change==31=>media_fixture_with_count(include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264"),3,25)?,
                    None if matches!(late_audio_change,29|30|32|33)=>media_fixture_with_count(include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264"),3,16)?,
                    None if matches!(late_audio_change,15|16|17|18|19|20|21|22|23|24|25|26|27|28)=>media_fixture_with_count(include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264"),3,10)?,
                    None=>media_fixture()?,
                };
                if revoke_audio_pending {
                    let mut audio=flv_tag(0,&[0xaf,0,0x14,0x08]);
                    audio[0]=8;
                    drop(wire.splice(13..13,audio));
                }
                if audio_change {
                    let config_length=(usize::from(wire[14])<<16)|(usize::from(wire[15])<<8)|usize::from(wire[16]);
                    let mut audio=flv_tag(0,&[0xaf,0,0x14,0x08]);
                    audio[0]=8;
                    drop(wire.splice(13+11+config_length+4..13+11+config_length+4,audio));
                }
                if late_audio_change==1 {
                    let mut offset=13;
                    let mut pictures=0;
                    while offset<wire.len() {
                        let n=(usize::from(wire[offset+1])<<16)|(usize::from(wire[offset+2])<<8)|usize::from(wire[offset+3]);
                        let video=wire[offset]==9 && wire[offset+12]==1;
                        offset+=11+n+4;
                        if video {pictures+=1;}
                        if pictures==5 {break;}
                    }
                    if pictures!=5 {return Err("missing late audio insertion point".into());}
                    let mut audio=flv_tag(256,&[0xaf,0,0x14,0x08]);
                    audio[0]=8;
                    drop(wire.splice(offset..offset,audio));
                }
                let expected=wire.clone();
                let (media_seen_tx,media_seen_rx)=std::sync::mpsc::channel();
                let (selection_started_tx,selection_started_rx)=std::sync::mpsc::channel();
                let (ready_to_cancel_tx,ready_to_cancel_rx)=std::sync::mpsc::channel();
                let (control_probe_tx,control_probe_rx)=std::sync::mpsc::channel();
                let (control_sent_tx,control_sent_rx)=std::sync::mpsc::channel();
                let peer=std::thread::spawn(move || -> io::Result<()> {
                    let mut socket=std::net::TcpStream::connect_timeout(&address,Duration::from_secs(5))?;
                    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let mut request=HEAD.as_bytes().to_vec();
                    if emit_event {request.extend(frame(EVENT));}
                    request.extend(frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"FixtureChallenge","messageId":19,"responseExpected":true,"payload":{"private":"not-for-output"}}"#));
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
                    if reply_after_media {
                        // Model a camera's short-lived preliminary media connection.
                            drop(std::net::TcpStream::connect_timeout(&destination,Duration::from_secs(5))?);
                            selection_started_rx.recv_timeout(Duration::from_secs(5)).map_err(io::Error::other)?;
                        if !early_reply {
                            socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":14}"#))?;
                            if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_timeSync".len()).any(|w|w==b"ubnt_avclient_timeSync") { return Err(io::Error::other("selection-time clock reply missing")); }
                        }
                    }
                    let mut media=std::net::TcpStream::connect_timeout(&destination,Duration::from_secs(5))?;
                    let split=if reply_after_media {13} else if audio_change {
                        let length=(usize::from(wire[14])<<16)|(usize::from(wire[15])<<8)|usize::from(wire[16]);
                        13+11+length+4
                    } else {wire.len().min(100)};
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
                    if !receive_binary(&mut socket).map_err(|e|io::Error::new(e.kind(),format!("post-start time-sync reply: {e}")))?.windows(b"ubnt_avclient_timeSync".len()).any(|w|w==b"ubnt_avclient_timeSync") { return Err(io::Error::other("missing post-start time-sync reply")); }
                    let writer=if camera_replay {
                        media.set_write_timeout(Some(Duration::from_secs(10)))?;
                        Some(std::thread::spawn(move || media.write_all(&wire[split..])))
                    } else {
                        media.write_all(&wire[split..])?;
                        drop(media);
                        None
                    };
                    if late_audio_change==13 {
                        control_probe_rx.recv_timeout(Duration::from_secs(5)).map_err(io::Error::other)?;
                        socket.write_all(&frame(REPLY_EVENT))?;
                        let response=receive_binary(&mut socket)?;
                        let parsed=fss_core::json_input::parse(std::str::from_utf8(&response).map_err(io::Error::other)?).map_err(io::Error::other)?;
                        let fields=parsed.object().ok_or_else(||io::Error::other("event response object"))?;
                        if fields.get("functionName").and_then(|v|v.text())!=Some("EventExample") || fields.get("inResponseTo").and_then(|v|v.integer())!=Some(20) {return Err(io::Error::other("wrong event response"));}
                    }
                    if archive_guard && !audio_change {
                        for id in [14_u32,15,16,17,18,19,20,21,22] {
                            if matches!(late_audio_change,10|11|12|13|14) || (late_audio_change==5 && id==15) || (id>=16 && !matches!(late_audio_change,15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33)) || (id==18 && !matches!(late_audio_change,15|18|19|20|21|22|23|24|25|27|28|29|30|31|32|33)) || (id==19 && !matches!(late_audio_change,20|21|22|23|24|29|30|31|32|33)) || (id>=20 && !matches!(late_audio_change,29|30|31|32|33)) || (id>=21 && late_audio_change==30) || (id>=20 && matches!(late_audio_change,32|33)) || (id>=23 && late_audio_change!=31) {break;}
                            control_probe_rx.recv_timeout(Duration::from_secs(if matches!(late_audio_change,15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33) {30} else {5})).map_err(io::Error::other)?;
                            let message=format!(r#"{{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":{id}}}"#);
                            socket.write_all(&frame(message.as_bytes()))?;
                            if matches!(late_audio_change,15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33) && id==15 {control_sent_tx.send(()).map_err(io::Error::other)?;}
                            if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_timeSync".len()).any(|w|w==b"ubnt_avclient_timeSync") {
                                return Err(io::Error::other("missing guarded time-sync reply"));
                            }
                            if late_audio_change==31 && id==21 {
                                control_probe_rx.recv_timeout(Duration::from_secs(30)).map_err(io::Error::other)?;
                                socket.write_all(&frame(ROLLOVER_REPLY_EVENT))?;
                                let response=receive_binary(&mut socket)?;
                                let parsed=fss_core::json_input::parse(std::str::from_utf8(&response).map_err(io::Error::other)?).map_err(io::Error::other)?;
                                let fields=parsed.object().ok_or_else(||io::Error::other("rollover event response object"))?;
                                if fields.get("functionName").and_then(|v|v.text())!=Some("EventExample") || fields.get("inResponseTo").and_then(|v|v.integer())!=Some(50) {return Err(io::Error::other("wrong rollover event response"));}
                            }
                        }
                    }
                    let mut last=[0u8;1];
                    let closed=matches!(socket.read(&mut last),Ok(0));
                    if let Some(writer)=writer {
                        match writer.join().map_err(|_|io::Error::other("media writer panic"))? {
                            Ok(())=>(),
                            Err(error) if closed && matches!(error.kind(),io::ErrorKind::BrokenPipe|io::ErrorKind::ConnectionReset)=>(),
                            Err(error)=>return Err(error),
                        }
                    }
                    if closed {Ok(())} else {Err(io::Error::other("controller did not retire"))}
                });
                let startup_events=fss_reference::unifi_direct::events::StartupInbox::new(4,4*fss_reference::unifi_direct::MAX_MESSAGE_BYTES)?;
                let (io,gate)=controller_listener.accept(4096,Duration::from_secs(5)).await?;
                let controller=Controller::new(Identity::new("FSS","12345678-1234-4abc-9abc-123456789abc","1.20.0")?,1)?;
                let mut session=owner::accept_guarded(io,ProtocolPolicy::RequireOffer,&FixtureAdmission,gate,controller,Duration::from_secs(5)).await?;
                if emit_event {session.bind_startup_events(&startup_events)?;}
                let guard=Guard { leases:&leases, clock };
                let event_guard=EventGuard {guard:&guard};
                let request=StreamStart::new(VideoChannel::Video2,SocketAddrV4::new(Ipv4Addr::LOCALHOST,17551),VideoCodec::H264,AudioCodec::Aac,"0123456789abcdef")?;
                let config=conversation::Config { hello:&operations[0], agreement:&operations[1], stream:&operations[2], time_sync:&operations[3..6], management:conditions, stream_conditions, request:&request, wait:Duration::from_secs(5) };
                let approval=FixtureApproval {revoke_stream:revoke_stream.then_some(&policy.listen)};
                let other_clock=MeteredClock::new(task,cx,TimestampNs(5))?;
                let mut wrong_owner=conversation::Owner { cx, task, clock:other_clock, effects:&mut effects, leases:&leases, approval:&approval, management_authority:&guard, stream_authority:&guard, wall:&FixtureClock };
                assert_eq!(wrong_owner.start(&mut session,&config).await,Err(conversation::Error::Configuration));
                let management_authority:&dyn ManagementAuthority=if matches!(late_audio_change,13|31) {&event_guard} else {&guard};
                let mut owner=conversation::Owner { cx, task, clock, effects:&mut effects, leases:&leases, approval:&approval, management_authority, stream_authority:&guard, wall:&FixtureClock };
                let duplicate=conversation::Config { agreement:&operations[0], ..config };
                assert_eq!(owner.start(&mut session,&duplicate).await,Err(conversation::Error::Configuration));
                let mismatched=conversation::Config { stream_conditions:intent::Preconditions { lease_fence:fence+1, ..stream_conditions }, ..config };
                assert_eq!(owner.start(&mut session,&mismatched).await,Err(conversation::Error::Configuration));
                let start=listener::Start {bind,resource:"fixture:camera",admission:&policy,channel:VideoChannel::Video2,video:VideoCodec::H264,audio:AudioCodec::Aac,stream_name:"0123456789abcdef",hello:&operations[0],agreement:&operations[1],stream:&operations[2],time_sync:&operations[3..6],management:conditions,stream_conditions,chunk_bytes:4096,max_bytes:u64::try_from(expected.len())?+1,bind_wait:Duration::from_secs(5),conversation_wait:Duration::from_secs(5),accept_wait:Duration::from_secs(5)};
                let invalid=listener::Start {max_bytes:0,..start};
                let framer=Framer::new(FlvLimits::default(),1024*1024)?;
                let recorder=recording::Recorder::new(SourceKey {connection:5,generation:1},recording::Limits::default())?;
                assert!(matches!(listener::start(&mut owner,&mut session,&invalid,framer,recorder).await,Err(listener::StartError::Listener(listener::Error::Configuration))));
                let framer=if camera_replay {Framer::with_mode(FlvLimits::default(),fss_packet::extended_flv::stream::MAX_BUFFER_BYTES,fss_packet::extended_flv::stream::SearchMode::ZeroStreamId)?} else {Framer::new(FlvLimits::default(),1024*1024)?};
                let recorder=recording::Recorder::new(SourceKey {connection:1,generation:1},recording::Limits::default())?;
                let started=if reply_after_media {
                    let mut trace=listener::StartTrace::default();
                    let future=listener::start_before_reply_retaining_listener(&mut owner,&mut session,&start,framer,recorder,&mut trace);
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
                        if let Some(Err(listener::StartError::Conversation(conversation::Error::SessionRetired {phase,rejected_message,..})))=&result {
                            let original=trace.protocol().controller_retirement().ok_or("original controller retirement lost")?;
                            assert_eq!(original.previous_phase,*phase); assert_eq!(original.rejected_message,*rejected_message);
                            assert_ne!(original.previous_phase,fss_reference::unifi_direct::Phase::Closed);
                        }
                        let protocol=trace.protocol_mut();
                        assert!(matches!(protocol.hello_mut().take_written(),Some(ManagementWrite::Written {..})));
                        assert!(matches!(protocol.agreement_mut().take_written(),Some(ManagementWrite::Written {..})));
                        assert!(matches!(protocol.stream_mut().take_written(),Some(fss_reference::unifi_direct::receive::StreamWrite::Written {..})));
                        assert!(protocol.clocks().len()>=1+locally_written);
                        for clock in protocol.clocks_mut().iter_mut().take(1+locally_written) {
                            assert!(matches!(clock.take_written(),Some(ManagementWrite::Written {..})));
                        }
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
                    if matches!(&result,Some(Err(_))) {
                        eprintln!("fixture_startup_failure dispatched={} clock_requests={} clock_replies={} observations={} hello={:?} agreement={:?} stream={:?} clock_attempts={}",trace.dispatched().is_some(),trace.clock_requests(),trace.clock_replies_written(),trace.observations().len(),trace.protocol().hello(),trace.protocol().agreement(),trace.protocol().stream(),trace.protocol().clocks().len());
                    }
                    let retained=result.ok_or("unexpected timeout")?.map_err(|error|format!("initial startup: {error:?}"))?;
                    let mut selection=listener::ValidatedMediaSelection::new(retained,3,4096,1_000_000,Duration::from_secs(5)).map_err(|_|"candidate configuration refused")?;
                    let mut fresh=|index:usize| -> io::Result<_> {
                        let framer=Framer::new(FlvLimits::default(),1024*1024).map_err(io::Error::other)?;
                        let recorder=recording::Recorder::new(SourceKey {connection:10+index as u64,generation:1},recording::Limits::default()).map_err(io::Error::other)?;
                        Ok((framer,recorder))
                    };
                    let mut interrupted=Box::pin(selection.select(&mut owner,&mut session,&start,&mut trace,None,&mut fresh));
                    poll_fn(|context| match interrupted.as_mut().poll(context) {
                        Poll::Pending=>Poll::Ready(()),
                        Poll::Ready(_)=>panic!("selection unexpectedly finished before fixture release"),
                    }).await;
                    drop(interrupted);
                    selection_started_tx.send(())?;
                    selection.select(&mut owner,&mut session,&start,&mut trace,None,&mut fresh).await.map_err(|error|format!("resumed selection: {error:?}"))?;
                    assert_eq!(selection.attempts(),2);
                    let pipeline=selection.take_ready().ok_or("no selected media")?;
                    let (evidence,candidates)=selection.into_parts();
                    let (_listener,remaining,additional)=candidates.into_parts();
                    assert!(additional.iter().all(Option::is_none));
                    assert!(remaining.is_none());
                    let started=listener::StartedBeforeReply {dispatched:evidence.dispatched,time_syncs_during_accept:evidence.time_syncs_during_accept,observations_during_accept:evidence.observations_during_accept,pipeline};
                    assert!(trace.dispatched().is_some());
                    assert_eq!(trace.clock_requests(),2);
                    assert_eq!(trace.clock_replies_written(),2);
                    assert_eq!(started.dispatched.time_syncs,1);
                    assert_eq!(started.time_syncs_during_accept,if early_reply {2} else {1});
                    let protocol=trace.protocol_mut();
                    assert!(matches!(protocol.hello_mut().take_written(),Some(ManagementWrite::Written {..})));
                    assert!(matches!(protocol.agreement_mut().take_written(),Some(ManagementWrite::Written {..})));
                    assert!(matches!(protocol.stream_mut().take_written(),Some(fss_reference::unifi_direct::receive::StreamWrite::Written {..})));
                    assert_eq!(protocol.clocks().len(),3);
                    for clock in protocol.clocks_mut() {
                        assert!(matches!(clock.take_written(),Some(ManagementWrite::Written {..})));
                    }
                    if early_reply {
                        assert!(matches!(started.observations_during_accept.as_slice(),[Observation::StreamSettingsReply {request_id:4,..}]));
                    } else {
                        assert!(started.observations_during_accept.is_empty());
                    }
                    Ok(started.pipeline)
                } else if revoke_stream {
                    let mut trace=listener::StartTrace::default();
                    let result=listener::start_before_reply_tracked(&mut owner,&mut session,&start,framer,recorder,&mut trace).await;
                    assert!(matches!(&result,Err(listener::StartError::Conversation(conversation::Error::Effect))));
                    let protocol=trace.protocol_mut();
                    assert!(matches!(protocol.hello_mut().take_written(),Some(ManagementWrite::Written {..})));
                    assert!(matches!(protocol.agreement_mut().take_written(),Some(ManagementWrite::Written {..})));
                    let refusal=protocol.stream_mut().take_refusal().ok_or("stream refusal lost its permit")?;
                    assert!(refusal.permit.journal_backed());
                    result.map(|started|started.pipeline)
                } else {
                    let mut trace=listener::StartTrace::default();
                    listener::start_tracked(&mut owner,&mut session,&start,framer,recorder,&mut trace).await.map(|started| {
                        assert_eq!(started.reply,conversation::Reply { status_code:None, success:None, time_syncs:1 });
                        let protocol=trace.protocol_mut();
                        assert!(matches!(protocol.hello_mut().take_written(),Some(ManagementWrite::Written {..})));
                        assert!(matches!(protocol.agreement_mut().take_written(),Some(ManagementWrite::Written {..})));
                        assert!(matches!(protocol.stream_mut().take_written(),Some(fss_reference::unifi_direct::receive::StreamWrite::Written {..})));
                        assert_eq!(protocol.clocks().len(),1);
                        assert!(matches!(protocol.clocks_mut()[0].take_written(),Some(ManagementWrite::Written {..})));
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
                assert_eq!(session.unhandled_request_counts().pre_hello,1);
                let mut supervisor=supervisor::Supervisor::new(session,pipeline,conditions);
                if async_archive { supervisor.enable_audio_tracking()?; }
                if reply_after_media {
                    // Selection retained the complete FLV header in the framer;
                    // release the synthetic peer before consuming the rest.
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
                    assert!(supervisor.has_pending_audio());
                    let collector=fss_reference::unifi_direct::av_bootstrap::Collector::new(None,ContentDigest::sha256(b"pending audio test"),
                        fss_reference::unifi_direct::av_owned_sink::BootstrapPolicy {allow_initial_video_only: false, max_separation_ms:5_000,jitter_ms:0,max_epoch_frames:8,max_audio_frames:8,
                            media_limits:fss_container::Mp4Limits::default(),evidence_limits:fss_reference::unifi_direct::evidence::Limits::default()});
                    let parts=match fss_reference::unifi_direct::av_bootstrap_driver::Driver::attach(supervisor,collector) {
                        Err(parts)=>parts, Ok(_)=>return Err("driver accepted unmatched audio".into()),
                    };
                    assert!(parts.pending.is_none());
                    supervisor=parts.supervisor;
                    assert!(supervisor.has_pending_audio());
                    policy.peer.set(false);
                    assert!(supervisor.take_audio_event(&owner).is_none());
                    assert!(supervisor.has_pending_audio());
                    assert!(matches!(supervisor.step(&mut owner,&operations[6],Duration::from_secs(5)).await,
                        supervisor::Step::ControllerStopped(fss_reference::unifi_direct::receive::Stop::AdmissionRevoked)));
                    let retired=supervisor.retire();
                    assert_eq!(retired.controller.unhandled_requests.pre_hello,1);
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
                                    use fss_reference::unifi_direct::{archive, av_bootstrap, av_bootstrap_driver, av_owned_sink, av_worker, av_worker_guard};
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
                                    impl archive::ReadAuthority for Retention {
                                        fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
                                            self.allow.load(Ordering::Acquire)
                                        }
                                    }
                                    struct Unblock(Arc<Retention>);
                                    impl Drop for Unblock { fn drop(&mut self) { self.0.block.store(false, Ordering::Release); } }
                                    let mut collector=av_bootstrap::Collector::new(Some(audio_bytes),
                                        ContentDigest::sha256(b"worker guard retention"),
                                        av_owned_sink::BootstrapPolicy { allow_initial_video_only: false, max_separation_ms:5_000, jitter_ms:if camera_replay {5} else {0}, max_epoch_frames:if camera_replay {1_000_000} else {8}, max_audio_frames:if camera_replay {fss_container::Mp4Limits::default().max_samples} else {8},
                                            media_limits:fss_container::Mp4Limits::default(), evidence_limits:evidence::Limits::default() });
                                    assert!(matches!(collector.collect(recording::Push::Source {record,disposition},None),av_bootstrap::Collected::Retained));
                                    let mut driver=av_bootstrap_driver::Driver::attach(supervisor,collector).map_err(|_|"bootstrap driver attachment refused")?;
                                    if matches!(late_audio_change,10|12|13|14) {
                                        return Box::pin(async {
                                        use fss_reference::unifi_direct::{av_unknown_worker_guard as unknown,source_coordinator,source_handoff,source_worker};
                                        let mut driver=Box::new(driver);
                                        let authority=fss_core::region::ContextAuthority::new_root(RootAuthoritySpec {
                                            trace_id:"trace:bootstrap-source-replay".into(), operation_id:OperationId::parse("operation:bootstrap-source-replay")?,
                                            principal:"principal:fixture".into(), capabilities:vec!["ADP-REPLAY-001".into()], deadline:None, priority:1,
                                            budgets:BudgetVector::builder().bytes(64*1024*1024).build()?, privacy_scope:"privacy:test".into(),
                                            retention_scope:"retention:test".into(),anchor_universe:ContentDigest::sha256(b"site:bootstrap-source"),generation:1,
                                        })?;
                                        let replay=fss_reference::ReplayCx::from_context_authority(&authority,temp.0.clone())?;
                                        let deployment=fss_reference::ReferenceDeployment::open(&temp.0.join("bootstrap-source-archive"),"site:bootstrap-source",&replay)?;
                                        let store=FileEffectJournal::create(temp.0.join("bootstrap-source-intent"),EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
                                        let journal=archive::journal::UnknownTimeJournal::create(Box::new(store),ContentDigest::sha256(b"bootstrap source scope"),&replay)?;
                                        let store=FileEffectJournal::create(temp.0.join("bootstrap-source-anchor"),EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
                                        let keeper=archive::journal::UnknownTimeAnchorKeeper::create(Box::new(store),&journal,&replay)?;
                                        let source_access=Arc::new(Retention {block:AtomicBool::new(matches!(late_audio_change,13|14)),entered:AtomicBool::new(false),allow:AtomicBool::new(true)});
                                        let _unblock_owned=Unblock(source_access.clone());
                                        let worker=source_worker::Worker::new(source_worker::Parts {deployment,journal,keeper,replay,authority:source_access.clone(),retention:ContentDigest::sha256(b"bootstrap source retention"),limits:archive::Limits::default(),max_source_bytes:1024*1024,work_limit:4_000_000_000}).map_err(|_|"bootstrap source worker configuration")?;
                                        let mut coordinator=source_coordinator::Coordinator::new(worker,SourceKey {connection:1,generation:1},ContentDigest::sha256(b"fixture camera"));
                                        let av_replay=fss_reference::ReplayCx::from_context_authority(&authority,temp.0.clone())?;
                                        let av_deployment=fss_reference::ReferenceDeployment::open(&temp.0.join("bootstrap-av-archive"),"site:bootstrap-source",&av_replay)?;
                                        let store=FileEffectJournal::create(temp.0.join("bootstrap-av-intent"),EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
                                        let av_journal=archive::journal::UnknownTimeJournal::create(Box::new(store),ContentDigest::sha256(b"bootstrap av scope"),&av_replay)?;
                                        let store=FileEffectJournal::create(temp.0.join("bootstrap-av-anchor"),EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
                                        let av_keeper=archive::journal::UnknownTimeAnchorKeeper::create(Box::new(store),&av_journal,&av_replay)?;
                                        let mut av_resources=Box::new(unknown::BootstrapResources {deployment:av_deployment,journal:av_journal,keeper:av_keeper,replay:av_replay,authority:source_access.clone(),limits:archive::Limits::default(),work_limit:4_000_000_000,rollover_custody:None});
                                        if late_audio_change==14 {
                                            use fss_reference::unifi_direct::recording_session;
                                            let mut session=Box::new(recording_session::Session::new(coordinator,driver,av_resources));
                                            let av=source_coordinator::ArchiveAdmission {resource:"fixture:bootstrap-av",cost:&BudgetVector::ZERO};
                                            let source=source_coordinator::ArchiveAdmission {resource:"fixture:bootstrap-source",cost:&BudgetVector::ZERO};
                                            let mut offered=false;
                                            timeout(cx.now(),Duration::from_secs(10),async {
                                                loop {
                                                    match Box::pin(session.step(&mut owner,&operations[6],Duration::from_millis(100),task,cx,clock,av,source)).await {
                                                        recording_session::Step::Bootstrap(source_coordinator::BootstrapStep::SourceOffered(source_handoff::BootstrapResult::Accepted {..}))=>offered=true,
                                                        recording_session::Step::Bootstrap(source_coordinator::BootstrapStep::SourceStarted)=>break Ok(()),
                                                        recording_session::Step::Bootstrap(source_coordinator::BootstrapStep::Driver(av_bootstrap_driver::Step::Retained | av_bootstrap_driver::Step::Forward {..} | av_bootstrap_driver::Step::Audio(_) | av_bootstrap_driver::Step::Supervisor(supervisor::Step::Media(pipeline::Step::Progress {..}) | supervisor::Step::Idle)))=>(),
                                                        recording_session::Step::Bootstrap(source_coordinator::BootstrapStep::Driver(av_bootstrap_driver::Step::Supervisor(supervisor::Step::TimeSyncWritten {mut trace})))=>{
                                                            if !matches!(trace.take_written(),Some(ManagementWrite::Written {permit}) if permit.journal_backed()){return Err("bootstrap shutdown clock permit missing");}
                                                        },
                                                        _=>return Err("bootstrap shutdown did not reach source start"),
                                                    }
                                                }
                                            }).await??;
                                            if !offered {return Err("bootstrap shutdown source not offered".into());}
                                            timeout(cx.now(),Duration::from_secs(5),async {while !source_access.entered.load(Ordering::Acquire) {asupersync::runtime::yield_now().await;}}).await?;
                                            if owner.effects.journal().operation(&operations[6]).is_none() {
                                                timeout(cx.now(),Duration::from_secs(5),async {
                                                    loop {
                                                        match Box::pin(session.step(&mut owner,&operations[6],Duration::from_millis(100),task,cx,clock,av,source)).await {
                                                            recording_session::Step::Bootstrap(source_coordinator::BootstrapStep::SourceArchive(source_handoff::Drive::Control {step:supervisor::Step::TimeSyncWritten {mut trace},completion:None}))=>{
                                                                if !matches!(trace.take_written(),Some(ManagementWrite::Written {permit}) if permit.journal_backed()){return Err("bootstrap shutdown clock permit missing");}
                                                                break Ok(());
                                                            },
                                                            recording_session::Step::Bootstrap(source_coordinator::BootstrapStep::SourceArchive(source_handoff::Drive::Control {step:supervisor::Step::Idle,completion:None}))=>(),
                                                            _=>return Err("bootstrap shutdown clock was not serviced"),
                                                        }
                                                    }
                                                }).await??;
                                            }
                                            let mut shutdown=(*session).request_bootstrap_shutdown().map_err(|_|"bootstrap shutdown refused")?;
                                            timeout(cx.now(),Duration::from_secs(5),async {while !shutdown.cancellation_observed() {asupersync::runtime::yield_now().await;}}).await?;
                                            shutdown=match shutdown.finish(){Err(shutdown)=>shutdown,Ok(_)=>return Err("bootstrap shutdown released running source".into())};
                                            assert!(poll_fn(|context| {let mut join=std::pin::pin!(shutdown.join_source()); Poll::Ready(join.as_mut().poll(context).is_pending())}).await);
                                            shutdown=match shutdown.finish(){Err(shutdown)=>shutdown,Ok(_)=>return Err("dropped join released running source".into())};
                                            source_access.block.store(false,Ordering::Release);
                                            let completion=timeout(cx.now(),Duration::from_secs(5),shutdown.join_source()).await?.ok_or("bootstrap shutdown completion missing")?;
                                            assert!(completion.runtime.is_ok());
                                            assert!(matches!(completion.outcome,source_worker::Outcome::Publication(source_worker::Publication::Refused {..})));
                                            assert!(shutdown.join_source().await.is_none());
                                            let (coordinator,driver,resources)=shutdown.finish().map_err(|_|"bootstrap shutdown did not drain")?;
                                            let retired=coordinator.into_worker().retire().map_err(|_|"bootstrap source did not retire")?;
                                            let Some(source_worker::Input::Original {record,..})=retired.pending else {return Err("bootstrap shutdown lost original source".into());};
                                            let start=usize::try_from(record.offset())?;let end=start.checked_add(record.bytes().len()).ok_or("source offset overflow")?;
                                            if expected.get(start..end)!=Some(record.bytes()){return Err("bootstrap shutdown changed original source".into());}
                                            let parts=(*driver).into_parts();drop(parts.supervisor);drop(parts.collector);drop(resources);
                                            peer.join().map_err(|_|"bootstrap shutdown peer panic")??;
                                            return Ok::<(),Box<dyn std::error::Error>>(());
                                        }
                                        if matches!(late_audio_change,12|13) {
                                            let probe=(late_audio_change==13).then_some(OwnedEventProbe {signal:&control_probe_tx,source_block:&source_access.block,conditions,operation:&operations[9]});
                                            let session=fss_reference::unifi_direct::recording_session::Session::new(coordinator,driver,av_resources);
                                            let (coordinator,pins,_,_)=drive_owned_recording(session,&mut owner,&operations[6],stream_conditions,probe,camera_replay,false,false,1,source_access.as_ref(),task,cx,clock).await?;
                                            let retired=coordinator.into_worker().retire().map_err(|_|"owned source worker retirement refused")?;
                                            if retired.fenced || retired.pending.is_some(){return Err("owned source custody remained unresolved".into());}
                                            let mut parts=retired.parts;
                                            for pin in pins {
                                                let recovered=archive::read_unknown_time_source(&mut parts.deployment,pin,source_access.as_ref(),archive::Limits::default(),&mut fss_geometry::WorkBudget::new(4_000_000_000),&parts.replay)?;
                                                let start=usize::try_from(recovered.offset())?;let end=start.checked_add(recovered.bytes().len()).ok_or("owned source offset overflow")?;
                                                if expected.get(start..end)!=Some(recovered.bytes()){return Err("owned source bytes differ from input".into());}
                                            }
                                            peer.join().map_err(|_|"owned recorder peer panic")??;
                                            return Ok::<(),Box<dyn std::error::Error>>(());
                                        }
                                        (driver,av_resources)=match coordinator.prepare_recording_guard(driver,av_resources) {
                                            Err(source_coordinator::TransitionRefusal::NotReady {driver,resources})=>(driver,resources),
                                            _=>return Err("incomplete bootstrap transition was not retained".into()),
                                        };
                                        let source_admission=source_coordinator::ArchiveAdmission {resource:"fixture:bootstrap-source",cost:&BudgetVector::ZERO};
                                        fn accept_bootstrap_sync(mut trace:conversation::TimeSyncTrace)->Test {
                                            if trace.operation().is_none() || !trace.dispatch_started(){return Err("bootstrap sync trace missing".into());}
                                            let Some(ManagementWrite::Written {permit})=trace.take_written() else {return Err("bootstrap sync outcome missing".into())};
                                            if !permit.journal_backed(){return Err("bootstrap sync permit not journaled".into());}
                                            Ok(())
                                        }
                                        struct BootstrapObserver {operation:OperationId,event:Option<source_coordinator::BootstrapStep>,refused:usize}
                                        impl source_coordinator::BootstrapObserver for BootstrapObserver {
                                            fn next_operation(&mut self)->Option<OperationId>{Some(self.operation.clone())}
                                            fn observe(&mut self,event:source_coordinator::BootstrapStep)->Result<source_coordinator::Decision,source_coordinator::BootstrapStep>{
                                                if self.refused==0 && matches!(&event,source_coordinator::BootstrapStep::SourceOffered(source_handoff::BootstrapResult::Accepted {..})){self.refused+=1;return Err(event);}
                                                if matches!(&event,source_coordinator::BootstrapStep::SourceStarted | source_coordinator::BootstrapStep::Driver(av_bootstrap_driver::Step::Retained) | source_coordinator::BootstrapStep::Driver(av_bootstrap_driver::Step::Supervisor(supervisor::Step::Media(pipeline::Step::Progress {..}) | supervisor::Step::Idle)) | source_coordinator::BootstrapStep::SourceArchive(source_handoff::Drive::Control {step:supervisor::Step::Idle,completion:None})) {return Ok(source_coordinator::Decision::Continue);}
                                                if self.event.is_some(){return Err(event);}
                                                self.event=Some(event);Ok(source_coordinator::Decision::Yield)
                                            }
                                        }
                                        let mut observer=BootstrapObserver {operation:operations[6].clone(),event:None,refused:0};
                                        assert!(matches!(Box::pin(coordinator.run_bootstrap_slice(&mut driver,&mut owner,Duration::ZERO,1,task,cx,clock,source_admission,&mut observer)).await,source_coordinator::BootstrapStop::Configuration));
                                        let mut pins=Vec::new();let mut offered=0;let mut paired_audio=0;let mut ready=false;
                                        for _ in 0..8192 {
                                            let event=match Box::pin(coordinator.run_bootstrap_slice(&mut driver,&mut owner,Duration::from_millis(100),32,task,cx,clock,source_admission,&mut observer)).await {
                                                source_coordinator::BootstrapStop::ObserverYielded=>observer.event.take().ok_or("bootstrap observer lost event")?,
                                                source_coordinator::BootstrapStop::ObserverRefused(event)=>event,
                                                source_coordinator::BootstrapStop::Halted(event)=>event,
                                                source_coordinator::BootstrapStop::Yielded=>continue,
                                                _=>return Err("bootstrap slice stopped unexpectedly".into()),
                                            };
                                            match event {
                                                source_coordinator::BootstrapStep::SourceOffered(source_handoff::BootstrapResult::Accepted {audio,..})=>{
                                                    offered+=1;
                                                    if matches!(audio,Some(pipeline::AudioEvent::Observed(fss_packet::extended_flv::aac_track::Observation::UnconfiguredSample {..}))){paired_audio+=1;}
                                                    (driver,av_resources)=match coordinator.prepare_recording_guard(driver,av_resources) {
                                                        Err(source_coordinator::TransitionRefusal::Source {status:source_worker::Status::Pending,driver,resources})=>(driver,resources),
                                                        _=>return Err("pending bootstrap source did not block transition".into()),
                                                    };
                                                },
                                                source_coordinator::BootstrapStep::SourceStarted | source_coordinator::BootstrapStep::Driver(av_bootstrap_driver::Step::Retained) | source_coordinator::BootstrapStep::Driver(av_bootstrap_driver::Step::Supervisor(supervisor::Step::Media(pipeline::Step::Progress {..}) | supervisor::Step::Idle))=>(),
                                                source_coordinator::BootstrapStep::Driver(av_bootstrap_driver::Step::Supervisor(supervisor::Step::TimeSyncWritten {trace}))=>accept_bootstrap_sync(trace)?,
                                                source_coordinator::BootstrapStep::Driver(av_bootstrap_driver::Step::Forward {push:recording::Push::Buffered,audio})=>drop(audio),
                                                source_coordinator::BootstrapStep::SourceArchive(source_handoff::Drive::Control {step,completion})=>{
                                                    match step {supervisor::Step::Idle=>(),supervisor::Step::TimeSyncWritten {trace}=>accept_bootstrap_sync(trace)?,other=>return Err(format!("unexpected bootstrap control {:?}",std::mem::discriminant(&other)).into())}
                                                    if let Some(completion)=completion {
                                                        if completion.runtime.is_err(){return Err("bootstrap source runtime failed".into());}
                                                        match completion.outcome {source_worker::Outcome::Publication(source_worker::Publication::Published {pin,..})=>pins.push(pin),_=>return Err("bootstrap source publication refused".into())}
                                                    }
                                                },
                                                source_coordinator::BootstrapStep::SourceArchive(source_handoff::Drive::Completed(completion))=>{
                                                    if completion.runtime.is_err(){return Err("bootstrap source runtime failed".into());}
                                                    match completion.outcome {source_worker::Outcome::Publication(source_worker::Publication::Published {pin,..})=>pins.push(pin),_=>return Err("bootstrap source publication refused".into())}
                                                },
                                                source_coordinator::BootstrapStep::Driver(av_bootstrap_driver::Step::Ready)=>{ready=true;break;},
                                                other=>{
                                                    let detail=match other {
                                                        source_coordinator::BootstrapStep::Driver(av_bootstrap_driver::Step::Supervisor(step))=>format!("supervisor {:?}",std::mem::discriminant(&step)),
                                                        source_coordinator::BootstrapStep::Driver(event)=>format!("driver {:?}",std::mem::discriminant(&event)),
                                                        source_coordinator::BootstrapStep::SourceOffered(source_handoff::BootstrapResult::Refused {refusal,..})=>format!("source refusal {}",match refusal {source_worker::OfferRefusal::Busy(_)=>"busy",source_worker::OfferRefusal::Invalid(_)=>"invalid",source_worker::OfferRefusal::Fenced(_)=>"fenced"}),
                                                        source_coordinator::BootstrapStep::SourceOffered(source_handoff::BootstrapResult::Unhandled(_))=>"unhandled source".into(),
                                                        source_coordinator::BootstrapStep::SourceArchive(source_handoff::Drive::Control {step,..})=>format!("control {:?}",std::mem::discriminant(&step)),
                                                        source_coordinator::BootstrapStep::SourceArchive(source_handoff::Drive::NotRunning)=>"source not running".into(),
                                                        source_coordinator::BootstrapStep::SourceStartRefused(error)=>format!("source start {error:?}"),
                                                        source_coordinator::BootstrapStep::SourceRetryRequired=>"source retry required".into(),
                                                        source_coordinator::BootstrapStep::SourceFenced=>"source fenced".into(),
                                                        source_coordinator::BootstrapStep::SourceUnavailable=>"source unavailable".into(),
                                                        source_coordinator::BootstrapStep::Context=>"context mismatch".into(),
                                                        source_coordinator::BootstrapStep::Cancelled(_)=>"cancelled".into(),
                                                        _=>"unexpected state".into(),
                                                    };
                                                    return Err(format!("unexpected coordinated bootstrap result: {detail}").into());
                                                },
                                            }
                                        }
                                        if !ready || offered==0 || paired_audio==0 || observer.refused!=1 || pins.len()!=offered {return Err("bootstrap source or paired audio was not fully accounted".into());}
                                        bootstrap_av_transition(&mut coordinator,driver,av_resources,&mut owner,&operations,task,cx,clock,source_admission).await?;
                                        let retired=coordinator.into_worker().retire().map_err(|_|"bootstrap worker retirement refused")?;
                                        if retired.fenced || retired.pending.is_some(){return Err("bootstrap source custody remained unresolved".into());}
                                        let mut parts=retired.parts;
                                        for pin in pins {
                                            let recovered=archive::read_unknown_time_source(&mut parts.deployment,pin,source_access.as_ref(),archive::Limits::default(),&mut fss_geometry::WorkBudget::new(4_000_000_000),&parts.replay)?;
                                            let start=usize::try_from(recovered.offset())?;let end=start.checked_add(recovered.bytes().len()).ok_or("source offset overflow")?;
                                            if expected.get(start..end)!=Some(recovered.bytes()){return Err("recovered bootstrap source differs from input".into());}
                                        }
                                        peer.join().map_err(|_|"bootstrap source peer panic")??;
                                        Ok::<(),Box<dyn std::error::Error>>(())
                                        }).await;
                                    }
                                    let mut audio_events=0;
                                    let mut ready=false;
                                    let mut saw_audio_change=false;
                                    for _ in 0..if camera_replay {8192} else {128} {
                                        match driver.step(&mut owner,&operations[6],Duration::from_secs(5)).await {
                                            av_bootstrap_driver::Step::Forward {push,audio} => {
                                                if let recording::Push::Source {record,..}=&push { originals.extend_from_slice(record.bytes()); }
                                                if matches!(audio,Some(pipeline::AudioEvent::Observed(fss_packet::extended_flv::aac_track::Observation::Configuration {..}))) {saw_audio_change=true;}
                                                if audio.is_some() {audio_events+=1;}
                                                match push {
                                                    recording::Push::Source {..}|recording::Push::Buffered => (),
                                                    _ => return Err("unexpected uncollected bootstrap result".into()),
                                                }
                                            },
                                            av_bootstrap_driver::Step::Retained | av_bootstrap_driver::Step::Supervisor(supervisor::Step::Media(pipeline::Step::Progress {..}) | supervisor::Step::TimeSyncWritten { .. }) => (),
                                            av_bootstrap_driver::Step::Ready => {ready=true;break;},
                                            av_bootstrap_driver::Step::Fenced if audio_change && saw_audio_change => break,
                                            other => return Err(format!("unexpected bootstrap source result: {other:?}").into()),
                                        }
                                    }
                                    if audio_change {
                                        assert!(saw_audio_change && !ready);
                                        assert!(matches!(driver.step(&mut owner,&operations[6],Duration::from_secs(5)).await,av_bootstrap_driver::Step::Fenced));
                                        let driver=match driver.bootstrap() {
                                            Err(av_bootstrap_driver::HandoffRefusal::NotReady(driver))=>driver,
                                            _=>return Err("fenced driver allowed bootstrap".into()),
                                        };
                                        let parts=driver.into_parts();
                                        assert!(parts.fenced && parts.pending.is_none());
                                        let retired=parts.supervisor.retire();
                                        for record in retired.media.recorder.pending {originals.extend_from_slice(record.bytes());}
                                        originals.extend_from_slice(retired.media.ingress.framing.bytes());
                                        if let Some(buffered)=retired.media.ingress.buffered {originals.extend_from_slice(&buffered.source.bytes()[buffered.appended..]);}
                                        if let Some(pending)=retired.media.ingress.source.pending {originals.extend_from_slice(pending.bytes());}
                                        assert_eq!(originals,expected[..originals.len()]);
                                        peer.join().map_err(|_|"audio change peer panic")??;
                                        return Ok(());
                                    }
                                    assert!(ready && audio_events>0);
                                    let handoff=driver.bootstrap().map_err(|_|"owned sink bootstrap refused")?;
                                    if !camera_replay {assert_eq!(handoff.bootstrap.origin.audio_ticks,1024);}
                                    let first_digest=ContentDigest::sha256(handoff.bootstrap.first_segment.fragment().bytes());
                                    let replay_authority=fss_core::region::ContextAuthority::new_root(RootAuthoritySpec {
                                        trace_id:"trace:worker-guard-replay".into(), operation_id:OperationId::parse("operation:worker-guard-replay")?,
                                        principal:"principal:fixture".into(), capabilities:vec!["ADP-REPLAY-001".into()],
                                        deadline:None, priority:1, budgets:BudgetVector::builder().bytes(64*1024*1024).build()?,
                                        privacy_scope:"privacy:test".into(), retention_scope:"retention:test".into(),
                                        anchor_universe:ContentDigest::sha256(b"site:worker-guard"), generation:1,
                                    })?;
                                    let replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?;
                                    let deployment=fss_reference::ReferenceDeployment::open(&temp.0.join("worker-guard-archive"),"site:worker-guard",&replay)?;
                                    if unknown_archive {
                                        use fss_reference::unifi_direct::av_unknown_worker_guard as unknown;
                                        let store=FileEffectJournal::create(temp.0.join("unknown-guard-intent"),EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
                                        let journal=archive::journal::UnknownTimeJournal::create(Box::new(store),ContentDigest::sha256(b"unknown worker guard scope"),&replay)?;
                                        let keeper_limits=if matches!(late_audio_change,15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33) {EffectJournalLimits {max_records:5,..EffectJournalLimits::default()}} else {EffectJournalLimits::default()};
                                        let store=FileEffectJournal::create(temp.0.join("unknown-guard-anchor"),keeper_limits,Arc::new(HostSpoolIo))?;
                                        let keeper=archive::journal::UnknownTimeAnchorKeeper::create(Box::new(store),&journal,&replay)?;
                                        let access=Arc::new(Retention {block:AtomicBool::new(!matches!(late_audio_change,15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33)), entered:AtomicBool::new(false), allow:AtomicBool::new(matches!(late_audio_change,15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33))});
                                        let _unblock=Unblock(Arc::clone(&access));
                                        let authority:Arc<dyn archive::RetainAuthority + Send + Sync>=access.clone();
                                        let resources=unknown::BootstrapResources {deployment,journal,keeper,replay,authority,limits:archive::Limits::default(),work_limit:if cancel_archive {0} else {4_000_000_000},rollover_custody:None};
                                        let mut guard=if cancel_archive {
                                            let (supervisor,mut parts,first_segment,origin)=match unknown::Guard::from_bootstrap(handoff,resources) {
                                                Err(unknown::BootstrapRefusal::Worker {supervisor,parts,first_segment,origin})=>(supervisor,parts,first_segment,origin),
                                                _=>return Err("invalid unknown worker limit accepted".into()),
                                            };
                                            assert_eq!(origin.audio_ticks,1024);
                                            assert_eq!(ContentDigest::sha256(first_segment.fragment().bytes()),first_digest);
                                            parts.work_limit=4_000_000_000;
                                            let worker=av_worker::UnknownTimeWorker::new(parts).map_err(|_|"unknown worker retry refused")?;
                                            let mut guard=unknown::Guard::new(supervisor,worker).map_err(|_|"unknown guard attachment refused")?;
                                            guard.hold_segment(first_segment).map_err(|_|"unknown held source refused")?;
                                            guard
                                        } else {
                                            let started=unknown::Guard::from_bootstrap(handoff,resources).map_err(|_|"unknown bootstrap refused")?;
                                            if !camera_replay {assert_eq!(started.origin.audio_ticks,1024);}
                                            started.guard
                                        };
                                        // A fresh empty archive cannot roll over; refusal must
                                        // preserve the live guard and its held first segment.
                                        guard=*refuse_guard_pause(Box::new(guard))?;
                                        let segment=guard.held_segment().ok_or("missing unknown held source")?;
                                        assert_eq!(ContentDigest::sha256(segment.fragment().bytes()),first_digest);
                                        for source in segment.source() { originals.extend_from_slice(source.bytes()); }
                                        if matches!(late_audio_change,8|9|11) {
                                            use fss_reference::unifi_direct::{source_coordinator,source_handoff,source_worker};
                                            use fss_packet::extended_flv::stream::Next;
                                            let source_replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?;
                                            let source_deployment=fss_reference::ReferenceDeployment::open(&temp.0.join("separate-source-archive"),"site:worker-guard",&source_replay)?;
                                            let store=FileEffectJournal::create(temp.0.join("separate-source-intent"),EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
                                            let journal=archive::journal::UnknownTimeJournal::create(Box::new(store),ContentDigest::sha256(b"separate source scope"),&source_replay)?;
                                            let store=FileEffectJournal::create(temp.0.join("separate-source-anchor"),EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
                                            let keeper=archive::journal::UnknownTimeAnchorKeeper::create(Box::new(store),&journal,&source_replay)?;
                                            let source_access=Arc::new(Retention {block:AtomicBool::new(true),entered:AtomicBool::new(false),allow:AtomicBool::new(false)});
                                            let _unblock_source=Unblock(Arc::clone(&source_access));
                                            let mut source=source_worker::Worker::new(source_worker::Parts {deployment:source_deployment,journal,keeper,replay:source_replay,authority:source_access.clone(),retention:ContentDigest::sha256(b"separate source retention"),limits:archive::Limits::default(),max_source_bytes:1024,work_limit:4_000_000_000}).map_err(|_|"separate source worker configuration")?;
                                            let mut framer=Framer::new(FlvLimits::default(),1024)?;
                                            framer.append(0,b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00")?;
                                            let record=match framer.take()? {Next::Record(record)=>record,Next::NeedMore=>return Err("source header missing".into())};
                                            let key=SourceKey {connection:1,generation:1};
                                            let claim=ContentDigest::sha256(b"fixture camera");
                                            if late_audio_change==11 {
                                                guard.start_archive(task,cx,clock,"fixture:archive",&BudgetVector::ZERO).map_err(|e|format!("A/V shutdown start: {e:?}"))?;
                                                timeout(cx.now(),Duration::from_secs(5),async {while !access.entered.load(Ordering::Acquire) {asupersync::runtime::yield_now().await;}}).await.map_err(|_|"A/V shutdown worker did not enter")?;
                                                let mut coordinator=source_coordinator::Coordinator::new(source,key,claim);
                                                let event=unknown::SessionEvent::Advance(unknown::Advance::Source(unknown::Step::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {record,disposition:recording::SourceDisposition::Header})))));
                                                assert!(matches!(coordinator.offer(event),source_handoff::Result::Accepted { .. }));
                                                let av=source_coordinator::ArchiveAdmission {resource:"fixture:archive",cost:&BudgetVector::ZERO};
                                                let separate=source_coordinator::ArchiveAdmission {resource:"fixture:source",cost:&BudgetVector::ZERO};
                                                assert!(matches!(Box::pin(coordinator.step(&mut guard,&mut owner,&operations[7],Duration::from_secs(1),task,cx,clock,av,separate)).await,source_coordinator::Step::SourceStarted));
                                                timeout(cx.now(),Duration::from_secs(5),async {while !source_access.entered.load(Ordering::Acquire) {asupersync::runtime::yield_now().await;}}).await.map_err(|_|"source shutdown worker did not enter")?;
                                                let mut shutdown=source_coordinator::Shutdown::request(coordinator,Box::new(guard));
                                                timeout(cx.now(),Duration::from_secs(5),async {while shutdown.cancellation_observed()!=(true,true) {asupersync::runtime::yield_now().await;}}).await.map_err(|_|"both cancellations were not observed")?;
                                                shutdown=match shutdown.finish(){Err(shutdown)=>shutdown,Ok(_)=>return Err("shutdown released running archives".into())};
                                                assert!(poll_fn(|context| {let mut join=std::pin::pin!(shutdown.join_source()); Poll::Ready(join.as_mut().poll(context).is_pending())}).await);
                                                assert!(poll_fn(|context| {let mut join=std::pin::pin!(shutdown.join_av()); Poll::Ready(join.as_mut().poll(context).is_pending())}).await);
                                                source_access.block.store(false,Ordering::Release);
                                                let source_result=timeout(cx.now(),Duration::from_secs(5),shutdown.join_source()).await?.ok_or("source shutdown completion missing")?;
                                                shutdown=match shutdown.finish(){Err(shutdown)=>shutdown,Ok(_)=>return Err("shutdown released the running A/V archive".into())};
                                                access.block.store(false,Ordering::Release);
                                                let av_result=timeout(cx.now(),Duration::from_secs(5),shutdown.join_av()).await?.ok_or("A/V shutdown completion missing")?;
                                                assert!(source_result.runtime.is_ok() && av_result.runtime.is_ok());
                                                assert!(matches!(source_result.outcome,source_worker::Outcome::Publication(source_worker::Publication::Refused {..})));
                                                assert!(matches!(av_result.outcome,av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Refused {..})));
                                                let (coordinator,guard)=shutdown.finish().map_err(|_|"drained shutdown refused")?;
                                                let source=coordinator.into_worker().retire().map_err(|_|"shutdown source retirement refused")?;
                                                match source.pending {Some(source_worker::Input::Original {record,..})=>assert_eq!(record.bytes(),b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00"),_=>return Err("shutdown lost separate original".into())}
                                                let retired=(*guard).retire().map_err(|_|"shutdown A/V retirement refused")?;
                                                let segment=retired.worker.parts.sink.retire().pending.ok_or("shutdown lost A/V segment")?;
                                                assert_eq!(ContentDigest::sha256(segment.fragment().bytes()),first_digest);
                                                drop(retired.supervisor);
                                                peer.join().map_err(|_|"shutdown peer panic")??;
                                                return Ok(());
                                            }
                                            let completion=if late_audio_change==8 {
                                                source.offer(source_worker::Input::Original {record,key,disposition:recording::SourceDisposition::Header,camera_claim:claim}).map_err(|_|"source offer refused")?;
                                                assert!(matches!(guard.advance_with_source(&mut source,&mut owner,&operations[7],Duration::from_secs(5),task,cx,clock,"fixture:source",&BudgetVector::ZERO).await,unknown::SourceAdvance::SourcePending));
                                                assert_eq!(ContentDigest::sha256(guard.held_segment().ok_or("pending source consumed segment")?.fragment().bytes()),first_digest);
                                                source.start(task,cx,clock,"fixture:source",&BudgetVector::ZERO).map_err(|e|format!("source start: {e:?}"))?;
                                                timeout(cx.now(),Duration::from_secs(5),async {while !source_access.entered.load(Ordering::Acquire) {asupersync::runtime::yield_now().await;}}).await.map_err(|_|"separate source worker did not enter")?;
                                                control_probe_tx.send(()).map_err(io::Error::other)?;
                                                assert!(matches!(guard.advance_with_source(&mut source,&mut owner,&operations[7],Duration::from_secs(5),task,cx,clock,"fixture:source",&BudgetVector::ZERO).await,unknown::SourceAdvance::SourceArchive(source_handoff::Drive::Control {step:supervisor::Step::TimeSyncWritten { .. },completion:None})));
                                                source_access.allow.store(true,Ordering::Release);
                                                source_access.block.store(false,Ordering::Release);
                                                timeout(cx.now(),Duration::from_secs(10),source.join()).await?.ok_or("separate source completion missing")?
                                            } else {
                                                let mut coordinator=source_coordinator::Coordinator::new(source,key,claim);
                                                let event=unknown::SessionEvent::Advance(unknown::Advance::Source(unknown::Step::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {record,disposition:recording::SourceDisposition::Header})))));
                                                assert!(matches!(coordinator.offer(event),source_handoff::Result::Accepted { .. }));
                                                assert!(coordinator.authorize_retry().is_err());
                                                let mut excessive=BudgetVector::ZERO; excessive.bytes=u64::MAX;
                                                let av=source_coordinator::ArchiveAdmission {resource:"fixture:archive",cost:&BudgetVector::ZERO};
                                                let denied=source_coordinator::ArchiveAdmission {resource:"fixture:source",cost:&excessive};
                                                let allowed=source_coordinator::ArchiveAdmission {resource:"fixture:source",cost:&BudgetVector::ZERO};
                                                struct SliceObserver {operation:OperationId,event:Option<source_coordinator::Step>,reject:bool}
                                                impl source_coordinator::Observer for SliceObserver {
                                                    fn next_operation(&mut self)->Option<OperationId>{Some(self.operation.clone())}
                                                    fn observe(&mut self,event:source_coordinator::Step)->Result<source_coordinator::Decision,source_coordinator::Step>{
                                                        if self.reject {self.reject=false;return Err(event);}
                                                        if matches!(&event,source_coordinator::Step::SourceArchive(source_handoff::Drive::Control {step:supervisor::Step::Idle,completion:None})){return Ok(source_coordinator::Decision::Continue);}
                                                        if self.event.is_some(){return Err(event);}
                                                        self.event=Some(event);Ok(source_coordinator::Decision::Yield)
                                                    }
                                                }
                                                let mut observer=SliceObserver {operation:operations[7].clone(),event:None,reject:false};
                                                assert!(matches!(Box::pin(coordinator.run_slice(&mut guard,&mut owner,Duration::ZERO,1,task,cx,clock,av,denied,&mut observer)).await,source_coordinator::SliceStop::Configuration));
                                                assert!(matches!(Box::pin(coordinator.run_slice(&mut guard,&mut owner,Duration::from_secs(5),1,task,cx,clock,av,denied,&mut observer)).await,source_coordinator::SliceStop::Halted(source_coordinator::Step::SourceStartRefused(_))));
                                                assert!(matches!(Box::pin(coordinator.run_slice(&mut guard,&mut owner,Duration::from_secs(5),1,task,cx,clock,av,allowed,&mut observer)).await,source_coordinator::SliceStop::Halted(source_coordinator::Step::SourceRetryRequired)));
                                                coordinator.authorize_retry().map_err(|_|"source retry was not retained")?;
                                                observer.reject=true;
                                                assert!(matches!(Box::pin(coordinator.run_slice(&mut guard,&mut owner,Duration::from_secs(5),1,task,cx,clock,av,allowed,&mut observer)).await,source_coordinator::SliceStop::ObserverRefused(source_coordinator::Step::SourceStarted)));
                                                timeout(cx.now(),Duration::from_secs(5),async {while !source_access.entered.load(Ordering::Acquire) {asupersync::runtime::yield_now().await;}}).await.map_err(|_|"coordinated source worker did not enter")?;
                                                control_probe_tx.send(()).map_err(io::Error::other)?;
                                                assert!(matches!(Box::pin(coordinator.run_slice(&mut guard,&mut owner,Duration::from_secs(5),1,task,cx,clock,av,allowed,&mut observer)).await,source_coordinator::SliceStop::ObserverYielded));
                                                assert!(matches!(observer.event.take(),Some(source_coordinator::Step::SourceArchive(source_handoff::Drive::Control {step:supervisor::Step::TimeSyncWritten { .. },completion:None}))));
                                                assert_eq!(ContentDigest::sha256(guard.held_segment().ok_or("coordinator control consumed segment")?.fragment().bytes()),first_digest);
                                                source_access.allow.store(true,Ordering::Release);
                                                source_access.block.store(false,Ordering::Release);
                                                let completion=timeout(cx.now(),Duration::from_secs(10),async {
                                                    loop {
                                                        match Box::pin(coordinator.run_slice(&mut guard,&mut owner,Duration::from_millis(100),32,task,cx,clock,av,allowed,&mut observer)).await {
                                                            source_coordinator::SliceStop::ObserverYielded=>match observer.event.take(){
                                                                Some(source_coordinator::Step::SourceArchive(source_handoff::Drive::Completed(completion))) | Some(source_coordinator::Step::SourceArchive(source_handoff::Drive::Control {completion:Some(completion),..}))=>break Ok(completion),
                                                                _=>break Err("coordinator returned an unexpected source event"),
                                                            },
                                                            source_coordinator::SliceStop::Yielded=>(),
                                                            _=>break Err("coordinator lost source or controller result"),
                                                        }
                                                    }
                                                }).await??;
                                                observer.operation=operations[6].clone();
                                                assert!(matches!(Box::pin(coordinator.run_slice(&mut guard,&mut owner,Duration::from_secs(5),1,task,cx,clock,av,allowed,&mut observer)).await,source_coordinator::SliceStop::ObserverYielded));
                                                assert!(matches!(observer.event.take(),Some(source_coordinator::Step::Session(unknown::SessionEvent::Advance(unknown::Advance::Source(unknown::Step::SourceQueued))))));
                                                assert!(matches!(Box::pin(coordinator.run_slice(&mut guard,&mut owner,Duration::from_secs(5),1,task,cx,clock,av,allowed,&mut observer)).await,source_coordinator::SliceStop::ObserverYielded));
                                                assert!(matches!(observer.event.take(),Some(source_coordinator::Step::Session(unknown::SessionEvent::Advance(unknown::Advance::ArchiveStarted)))));
                                                source=coordinator.into_worker();
                                                completion
                                            };
                                            assert!(completion.runtime.is_ok() && matches!(completion.outcome,source_worker::Outcome::Publication(source_worker::Publication::Published { .. })));
                                            let retired=source.retire().map_err(|_|"separate source retirement refused")?;
                                            assert!(!retired.fenced && retired.pending.is_none());
                                        } else {
                                            control_probe_tx.send(()).map_err(io::Error::other)?;
                                            assert!(matches!(guard.service_control(&mut owner,&operations[7],Duration::from_secs(5)).await,supervisor::Step::TimeSyncWritten { .. }));
                                        }
                                        if late_audio_change!=9 {
                                            assert_eq!(ContentDigest::sha256(guard.held_segment().ok_or("unknown control consumed source")?.fragment().bytes()),first_digest);
                                        }
                                        if late_audio_change==7 {
                                            use fss_reference::unifi_direct::av_session_inbox::Inbox;
                                            use unknown::{Advance, Drive, SessionEvent, SessionStop};
                                            let mut inbox=Inbox::new("operation:session-inbox",0,8,8*1024*1024).map_err(|_|"session inbox configuration")?;
                                            let mut probe_sent=false;
                                            let mut controls=0;
                                            let mut published=0;
                                            let mut sources=Vec::new();
                                            for _ in 0..8192 {
                                                let result=guard.run_slice(&mut owner,Duration::from_millis(100),128,task,cx,clock,"fixture:archive",&BudgetVector::ZERO,&mut inbox).await;
                                                if !matches!(result,SessionStop::ObserverYielded|SessionStop::Yielded) {
                                                    let detail=match &result {
                                                        SessionStop::Halted {event:Advance::Source(unknown::Step::Supervisor(supervisor::Step::ConversationError(error))),..} => format!("source conversation {error:?}"),
                                                        SessionStop::Halted {event:Advance::Archive(Drive::Control {step:supervisor::Step::ConversationError(error),..}),..} => format!("archive control conversation {error:?}"),
                                                        SessionStop::Halted {event:Advance::Source(unknown::Step::Supervisor(supervisor::Step::TimeSyncStopped {error,..})),..} => format!("source time sync {error:?}"),
                                                        SessionStop::Halted {event:Advance::Archive(Drive::Control {step:supervisor::Step::TimeSyncStopped {error,..},..}),..} => format!("archive control time sync {error:?}"),
                                                        SessionStop::Halted {event:Advance::Source(unknown::Step::Supervisor(step)),..} => format!("source supervisor {:?}",std::mem::discriminant(step)),
                                                        SessionStop::Halted {event:Advance::Archive(Drive::Control {step,..}),..} => format!("archive control {:?}",std::mem::discriminant(step)),
                                                        SessionStop::Halted {event,..} => format!("advance {:?}",std::mem::discriminant(event)),
                                                        _=>format!("stop {:?}",std::mem::discriminant(&result)),
                                                    };
                                                    return Err(format!("session inbox stopped unexpectedly: {detail}").into());
                                                }
                                                while let Some(event)=inbox.take() {
                                                    let completion=match event {
                                                        SessionEvent::Advance(Advance::ArchiveStarted) => {
                                                            if !probe_sent {control_probe_tx.send(()).map_err(io::Error::other)?;probe_sent=true;}
                                                            None
                                                        }
                                                        SessionEvent::Advance(Advance::Archive(Drive::Control {step:supervisor::Step::TimeSyncWritten { mut trace },completion})) => {
                                                            assert!(trace.operation().is_some());
                                                            assert!(trace.dispatch_started());
                                                            let Some(ManagementWrite::Written { permit })=trace.take_written() else {return Err("time-sync outcome was not retained".into())};
                                                            assert!(permit.journal_backed());
                                                            controls+=1;
                                                            access.allow.store(true,Ordering::Release);
                                                            access.block.store(false,Ordering::Release);
                                                            completion
                                                        }
                                                        SessionEvent::Advance(Advance::Archive(Drive::Archive(completion)))=>Some(completion),
                                                        SessionEvent::Advance(Advance::Archive(Drive::Control {completion,..}))=>completion,
                                                        SessionEvent::Advance(Advance::Source(unknown::Step::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {record,..})))))=>{sources.push(record);None},
                                                        _=>None,
                                                    };
                                                    if let Some(completion)=completion {
                                                        assert!(completion.runtime.is_ok());
                                                        if matches!(completion.outcome,av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(_))) {published+=1;}
                                                        else {return Err("session inbox publication refused".into());}
                                                    }
                                                }
                                                if published==2 {break;}
                                            }
                                            assert_eq!((controls,published),(1,2));
                                            assert!(inbox.is_empty());
                                            let retired=guard.retire().map_err(|_|"session inbox retirement refused")?;
                                            assert!(retired.worker.parts.sink.retire().pending.is_none());
                                            peer.join().map_err(|_|"session inbox peer panic")??;
                                            if camera_replay {println!("unknown_inbox_camera_replay=passed published_segments=2 source_handoffs={} capture_bounds=unknown controller=simulated",sources.len());}
                                            return Ok(());
                                        }
                                        if late_audio_change==5 {
                                            use unknown::{Advance, SessionDecision, SessionEvent, SessionObserver, SessionStop};
                                            struct Reject {operation:OperationId,access:Arc<Retention>}
                                            impl SessionObserver for Reject {
                                                fn next_operation(&mut self)->Option<OperationId> {Some(self.operation.clone())}
                                                fn observe(&mut self,event:SessionEvent)->Result<SessionDecision,SessionEvent> {
                                                    if matches!(event,SessionEvent::Advance(Advance::ArchiveStarted)) {
                                                        self.access.block.store(false,Ordering::Release);
                                                        Err(event)
                                                    } else {Ok(SessionDecision::Continue)}
                                                }
                                            }
                                            let mut observer=Reject {operation:operations[8].clone(),access:access.clone()};
                                            assert!(matches!(guard.run_slice(&mut owner,Duration::ZERO,1,task,cx,clock,"fixture:archive",&BudgetVector::ZERO,&mut observer).await,SessionStop::Configuration));
                                            assert!(matches!(guard.run_slice(&mut owner,Duration::from_secs(1),1,task,cx,clock,"fixture:archive",&BudgetVector::ZERO,&mut observer).await,SessionStop::Yielded));
                                            let refused=guard.run_slice(&mut owner,Duration::from_secs(1),10,task,cx,clock,"fixture:archive",&BudgetVector::ZERO,&mut observer).await;
                                            assert!(matches!(refused,SessionStop::ObserverRefused {event:SessionEvent::Advance(Advance::ArchiveStarted),drained:Some(_)}));
                                            let retired=guard.retire().map_err(|_|"refused session did not drain")?;
                                            assert!(retired.retry_required);
                                            let segment=retired.worker.parts.sink.retire().pending.ok_or("refused session lost original")?;
                                            assert_eq!(ContentDigest::sha256(segment.fragment().bytes()),first_digest);
                                            peer.join().map_err(|_|"refused session peer panic")??;
                                            return Ok(());
                                        }
                                        if late_audio_change==4 || late_audio_change==6 {
                                            use unknown::{Advance, Drive, SessionDecision, SessionEvent, SessionObserver, SessionStop};
                                            struct Observer {
                                                operation: OperationId,
                                                probe: std::sync::mpsc::Sender<()>,
                                                access: Arc<Retention>,
                                                controls: usize,
                                                published: usize,
                                                yield_started: bool,
                                                sources: Vec<fss_packet::extended_flv::stream::SourceRecord>,
                                            }
                                            impl SessionObserver for Observer {
                                                fn next_operation(&mut self)->Option<OperationId> {
                                                    if self.controls==0 {Some(self.operation.clone())}
                                                    else {OperationId::parse("operation:session-control-2").ok()}
                                                }
                                                fn observe(&mut self,event:SessionEvent)->Result<SessionDecision,SessionEvent> {
                                                    match event {
                                                        SessionEvent::Advance(Advance::ArchiveStarted) if self.controls==0 => {
                                                            self.probe.send(()).expect("first control probe");
                                                            if self.yield_started {self.yield_started=false;return Ok(SessionDecision::Yield);}
                                                        },
                                                        SessionEvent::Advance(Advance::Archive(Drive::Control {step:supervisor::Step::TimeSyncWritten { .. },completion})) => {
                                                            self.controls+=1;
                                                            self.access.allow.store(true,Ordering::Release);
                                                            self.access.block.store(false,Ordering::Release);
                                                            if let Some(completion)=completion {
                                                                if matches!(completion.outcome,av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(_))) {self.published+=1;}
                                                            }
                                                        }
                                                        SessionEvent::Advance(Advance::Archive(Drive::Archive(completion))) | SessionEvent::Advance(Advance::Archive(Drive::Control {completion:Some(completion),..})) => {
                                                            if matches!(completion.outcome,av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(_))) {self.published+=1;}
                                                        }
                                                        SessionEvent::Advance(Advance::Source(unknown::Step::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {record,..}))))) => self.sources.push(record),
                                                        _=>(),
                                                    }
                                                    if self.published>=2 {Ok(SessionDecision::Stop)} else {Ok(SessionDecision::Continue)}
                                                }
                                            }
                                            let mut observer=Observer {operation:operations[8].clone(),probe:control_probe_tx,access:access.clone(),controls:0,published:0,yield_started:late_audio_change==6,sources:Vec::new()};
                                            let result=guard.run_slice(&mut owner,Duration::from_millis(200),4096,task,cx,clock,"fixture:archive",&BudgetVector::ZERO,&mut observer).await;
                                            let result=if late_audio_change==6 {
                                                assert!(matches!(result,SessionStop::ObserverYielded));
                                                assert_eq!(guard.archive_state(),av_worker_guard::ArchiveState::Running);
                                                guard=match guard.retire() {Err(guard)=>guard,Ok(_)=>return Err("yielded worker retired without drain".into())};
                                                guard.run_slice(&mut owner,Duration::from_millis(200),4096,task,cx,clock,"fixture:archive",&BudgetVector::ZERO,&mut observer).await
                                            } else {result};
                                            match result {
                                                SessionStop::ObserverStopped {drained:None}=>(),
                                                SessionStop::ObserverStopped {drained:Some(_)}=>return Err("session stopped with drained worker".into()),
                                                SessionStop::Halted {event,..}=>{
                                                    let reason=match event {
                                                        Advance::Source(unknown::Step::Supervisor(supervisor::Step::ConversationError(_)))=>"session conversation error",
                                                        Advance::Source(unknown::Step::Supervisor(supervisor::Step::ControllerStopped(_)))=>"session controller stopped",
                                                        Advance::Source(unknown::Step::Supervisor(supervisor::Step::Media(pipeline::Step::Eof)))=>"session media eof",
                                                        Advance::Archive(Drive::Control {step:supervisor::Step::ConversationError(_),..})=>"session archive control conversation error",
                                                        Advance::Archive(Drive::Control {step:supervisor::Step::ControllerStopped(reason),..})=>return Err(format!("session archive controller stopped: {reason:?}; controls={}, published={}",observer.controls,observer.published).into()),
                                                        Advance::RetryRequired=>"session retry required",
                                                        Advance::RecoveryRequired=>"session recovery required",
                                                        Advance::StartRefused(_)=>"session archive start refused",
                                                        Advance::Source(unknown::Step::AudioFenced)=>"session audio fenced",
                                                        _=>"session other halt",
                                                    };
                                                    return Err(reason.into());
                                                },
                                                SessionStop::Yielded=>return Err("session step limit".into()),
                                                SessionStop::ObserverYielded=>return Err("unexpected session observer yield".into()),
                                                SessionStop::AudioWithheld=>return Err("session audio withheld".into()),
                                                SessionStop::OperationUnavailable {..}=>return Err("session operation unavailable".into()),
                                                SessionStop::ObserverRefused {..}=>return Err("session observer refused".into()),
                                                SessionStop::Configuration=>return Err("session invalid configuration".into()),
                                            }
                                            assert_eq!((observer.controls,observer.published),(1,2));
                                            let retired=guard.retire().map_err(|_|"session slice retirement refused")?;
                                            assert!(!retired.retry_required && !retired.audio_fenced);
                                            assert!(retired.worker.parts.sink.retire().pending.is_none());
                                            peer.join().map_err(|_|"session slice peer panic")??;
                                            if camera_replay {println!("unknown_session_camera_replay=passed published_segments=2 capture_bounds=unknown controller=simulated");}
                                            return Ok(());
                                        }
                                        if matches!(late_audio_change,15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33) {
                                            use unknown::{Advance, Drive};
                                            let mut published=0;
                                            let mut originals=Vec::new();
                                            let mut needed=None;
                                            for _ in 0..8192 {
                                                match guard.advance(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,"fixture:archive",&BudgetVector::ZERO).await {
                                                    Advance::Source(unknown::Step::Supervisor(supervisor::Step::AudioPending))=>{
                                                        let event=guard.take_audio_event(&owner).ok_or("rollover audio withheld")?;
                                                        if matches!(event,pipeline::AudioEvent::Fenced(_)|pipeline::AudioEvent::Observed(fss_packet::extended_flv::aac_track::Observation::Configuration {..})) {return Err("rollover audio fenced".into());}
                                                    },
                                                    Advance::Source(unknown::Step::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {record,..}))))=>originals.push(record),
                                                    Advance::Source(unknown::Step::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Buffered)|pipeline::Step::Progress {..})|supervisor::Step::TimeSyncWritten { .. }|supervisor::Step::Idle)) | Advance::Source(unknown::Step::SourceQueued) | Advance::ArchiveStarted | Advance::Archive(Drive::Control {step:supervisor::Step::Idle|supervisor::Step::TimeSyncWritten {..},completion:None})=>(),
                                                    Advance::Archive(Drive::Archive(done)) | Advance::Archive(Drive::Control {step:supervisor::Step::Idle|supervisor::Step::TimeSyncWritten {..},completion:Some(done)})=>{
                                                        if done.runtime.is_err(){return Err("rollover archive task failed".into());}
                                                        match done.outcome {
                                                            av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(_))=>published+=1,
                                                            av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Refused {rollover:Some(need),..})=>{needed=Some(need);break;},
                                                            _=>return Err("rollover archive outcome unexpected".into()),
                                                        }
                                                    },
                                                    _=>return Err("rollover scheduler stopped early".into()),
                                                }
                                            }
                                            let need=needed.ok_or("rollover signal missing")?;
                                            assert_eq!(published,2);
                                            assert_eq!(guard.rollover_need(),Some(need));
                                            assert!(matches!(guard.advance(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,"fixture:archive",&BudgetVector::ZERO).await,Advance::RolloverRequired(observed) if observed==need));
                                            let (mut paused,previous)=guard.pause_rollover().map_err(|_|"capacity pause refused")?;
                                            assert_eq!(paused.rollover_need(),Some(need));
                                            control_probe_tx.send(()).map_err(io::Error::other)?;
                                            control_sent_rx.recv_timeout(Duration::from_secs(5)).map_err(io::Error::other)?;
                                            match paused.service_control(&mut owner,&operations[8],Duration::from_secs(5)).await {
                                                supervisor::Step::TimeSyncWritten {..}=>(),
                                                other=>return Err(format!("paused control failed: {other:?}").into()),
                                            }
                                            // Force a pending poll before the peer writes its next
                                            // frame; this exercises wakeup as well as prebuffered input.
                                            let mut control=Box::pin(paused.service_control(&mut owner,&operations[9],Duration::from_secs(5)));
                                            let mut signalled=false;
                                            let delayed=poll_fn(|cx| {
                                                if !signalled {
                                                    if control.as_mut().poll(cx).is_ready() {return Poll::Ready(Err("control read did not wait"));}
                                                    if control_probe_tx.send(()).is_err() {return Poll::Ready(Err("control probe closed"));}
                                                    signalled=true;
                                                    return Poll::Pending;
                                                }
                                                control.as_mut().poll(cx).map(Ok)
                                            }).await?;
                                            if !matches!(delayed,supervisor::Step::TimeSyncWritten {..}) {return Err(format!("delayed paused control failed: {delayed:?}").into());}
                                            drop(control);
                                            guard=paused.restore(previous).map_err(|_|"capacity restore refused")?;
                                            assert_eq!(guard.rollover_need(),Some(need));
                                            let (paused,previous)=guard.pause_rollover().map_err(|_|"background pause refused")?;
                                            let limits=EffectJournalLimits::default();
                                            let create=|name:&str| -> Result<Box<dyn fss_runtime::effect_journal::EffectJournalStore>,Box<dyn Error>> {
                                                Ok(Box::new(FileEffectJournal::create(temp.0.join(name),limits,Arc::new(HostSpoolIo))?))
                                            };
                                            let staged=archive::journal::rollover::Staged::begin(previous,create("background-abort-journal")?,create("background-abort-keeper")?,paused.replay()).map_err(|_|"background abort stage refused")?;
                                            if late_audio_change==18 {paused.replay().set_cancel_at_checkpoint("unifi-av-prepared-attach");}
                                            guard=paused.restore(staged.abort()).map_err(|_|"background abort restore refused")?;
                                            let source_replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?;
                                            let source_deployment=fss_reference::ReferenceDeployment::open(&temp.0.join("rollover-session-source"),"site:worker-guard",&source_replay)?;
                                            let source_journal=archive::journal::UnknownTimeJournal::create(create("rollover-session-intent")?,ContentDigest::sha256(b"rollover session source scope"),&source_replay)?;
                                            let source_keeper=archive::journal::UnknownTimeAnchorKeeper::create(create("rollover-session-keeper")?,&source_journal,&source_replay)?;
                                            let mut source=fss_reference::unifi_direct::source_worker::Worker::new(fss_reference::unifi_direct::source_worker::Parts {deployment:source_deployment,journal:source_journal,keeper:source_keeper,replay:source_replay,authority:access.clone(),retention:ContentDigest::sha256(b"rollover session source retention"),limits:archive::Limits::default(),max_source_bytes:1024*1024,work_limit:4_000_000_000}).map_err(|_|"rollover source worker refused")?;
                                            let mut source_framer=Framer::new(FlvLimits::default(),1024)?;
                                            source_framer.append(0,b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00")?;
                                            let source_record=match source_framer.take()? {fss_packet::extended_flv::stream::Next::Record(record)=>record,_=>return Err("separate source header missing".into())};
                                            let source_key=SourceKey {connection:1,generation:1};
                                            let source_claim=ContentDigest::sha256(b"fixture camera");
                                            if source.offer(fss_reference::unifi_direct::source_worker::Input::Original {record:source_record,key:source_key,disposition:recording::SourceDisposition::Header,camera_claim:source_claim}).is_err() {return Err("separate source offer refused".into());}
                                            let coordinator=fss_reference::unifi_direct::source_coordinator::Coordinator::new(source,source_key,source_claim);
                                            let session=fss_reference::unifi_direct::recording_session::Session::from_recording(coordinator,Box::new(guard));
                                            #[derive(Debug)]
                                            struct PinGate {armed:AtomicBool,entered:AtomicBool,release:AtomicBool,fail_after_release:AtomicBool,panic_after_release:AtomicBool,reads:std::sync::atomic::AtomicUsize}
                                            #[derive(Debug)]
                                            struct GatedRetainer {inner:Box<dyn fss_runtime::effect_journal::EffectPinRetainer>,gate:Arc<PinGate>}
                                            impl fss_runtime::effect_journal::EffectPinRetainer for GatedRetainer {
                                                fn retained_pin(&mut self)->Result<Option<fss_runtime::effect_journal::EffectJournalPin>,fss_runtime::effect_journal::EffectPersistenceError> {
                                                    self.gate.reads.fetch_add(1,Ordering::AcqRel);
                                                    if self.gate.armed.load(Ordering::Acquire) {
                                                        self.gate.entered.store(true,Ordering::Release);
                                                        for _ in 0..2500 {if self.gate.release.load(Ordering::Acquire) {assert!(!self.gate.panic_after_release.load(Ordering::Acquire),"synthetic prior custody panic"); if self.gate.fail_after_release.load(Ordering::Acquire) {return Err(fss_runtime::effect_journal::EffectPersistenceError::PinMismatch);} return self.inner.retained_pin();} std::thread::sleep(Duration::from_millis(2));}
                                                        return Err(fss_runtime::effect_journal::EffectPersistenceError::Storage("synthetic custody gate timed out".into()));
                                                    }
                                                    self.inner.retained_pin()
                                                }
                                                fn reserve_capacity(&mut self,n:usize)->Result<(),fss_runtime::effect_journal::EffectPersistenceError>{self.inner.reserve_capacity(n)}
                                                fn verify_effect_history(&mut self,journal:&dyn fss_runtime::effect_journal::EffectJournalStore)->Result<(),fss_runtime::effect_journal::EffectPersistenceError>{self.inner.verify_effect_history(journal)}
                                                fn retain(&mut self,expected:Option<fss_runtime::effect_journal::EffectJournalPin>,next:fss_runtime::effect_journal::EffectJournalPin)->Result<(),fss_runtime::effect_journal::EffectPersistenceError>{self.inner.retain(expected,next)}
                                            }
                                            struct ReleasePin(Arc<PinGate>);
                                            impl Drop for ReleasePin {fn drop(&mut self){self.0.release.store(true,Ordering::Release);}}
                                            let pin_gate=Arc::new(PinGate {armed:AtomicBool::new(false),entered:AtomicBool::new(false),release:AtomicBool::new(false),fail_after_release:AtomicBool::new(matches!(late_audio_change,19|27)),panic_after_release:AtomicBool::new(false),reads:std::sync::atomic::AtomicUsize::new(0)});
                                            let _release_pin=ReleasePin(pin_gate.clone());
                                            let retainer=fss_object::effect_journal::FileTrustedRootPinRetainer::create(temp.0.join("background-root"),limits,Arc::new(HostSpoolIo),ContentDigest::sha256(b"background switch root"))?;
                                            let switch=fss_runtime::effect_journal::PinRetainedEffectJournal::new(create("background-switch")?,Box::new(GatedRetainer {inner:Box::new(retainer),gate:pin_gate.clone()}))?;
                                            struct DelayedRead {entered:AtomicBool, release:AtomicBool, panic_after_release:bool}
                                            impl archive::ReadAuthority for DelayedRead {
                                                fn permits(&self,_:ContentDigest,_:ContentDigest)->bool {
                                                    self.entered.store(true,Ordering::Release);
                                                    for _ in 0..2500 {
                                                        if self.release.load(Ordering::Acquire) {assert!(!self.panic_after_release,"synthetic replay panic");return true;}
                                                        std::thread::sleep(Duration::from_millis(2));
                                                    }
                                                    false
                                                }
                                            }
                                            struct ReleaseRead(Arc<DelayedRead>);
                                            impl Drop for ReleaseRead {fn drop(&mut self){self.0.release.store(true,Ordering::Release);}}
                                            let read=Arc::new(DelayedRead {entered:AtomicBool::new(false),release:AtomicBool::new(false),panic_after_release:late_audio_change==17});
                                            let _release=ReleaseRead(read.clone());
                                            let supplies=fss_reference::unifi_direct::av_rollover_worker::Supplies {
                                                next_journal:create("background-next-journal")?,next_keeper:if matches!(late_audio_change,29|30|31|32|33) {Box::new(FileEffectJournal::create(temp.0.join("background-next-keeper"),EffectJournalLimits {max_records:5,..limits},Arc::new(HostSpoolIo))?)} else {create("background-next-keeper")?},switch,read:read.clone(),
                                                object_limits:archive::StagedAvLimits {max_objects:8192,max_object_bytes:1024*1024,max_total_bytes:8*1024*1024},work_limit:100_000_000_000,
                                            };
                                            let (session,supplies)=match fss_reference::unifi_direct::recording_rollover::RecordingRollover::prepare(session,supplies) {
                                                Err(fss_reference::unifi_direct::recording_rollover::PrepareRefusal::NotReady {session,supplies})=>(session,supplies),
                                                _=>return Err("rollover did not preserve pending separate source".into()),
                                            };
                                            let (coordinator,phase)=session.into_parts();
                                            let source_boundary_guard=match phase {fss_reference::unifi_direct::recording_session::Phase::Recording(guard)=>guard,_=>return Err("not-ready session lost recording phase".into())};
                                            let mut source=coordinator.into_worker();
                                            assert_eq!(source.status(),fss_reference::unifi_direct::source_worker::Status::Pending);
                                            source.start(task,cx,clock,"fixture:source",&BudgetVector::ZERO).map_err(|_|"separate source start refused")?;
                                            let source_done=source.join().await.ok_or("separate source completion missing")?;
                                            if source_done.runtime.is_err() || !matches!(source_done.outcome,fss_reference::unifi_direct::source_worker::Outcome::Publication(fss_reference::unifi_direct::source_worker::Publication::Published {..})) {return Err("separate source not published".into());}
                                            let coordinator=fss_reference::unifi_direct::source_coordinator::Coordinator::new(source,source_key,source_claim);
                                            let session=fss_reference::unifi_direct::recording_session::Session::from_recording(coordinator,source_boundary_guard);
                                            if matches!(late_audio_change,25|26|27|28|29|30|31|32|33) {
                                                use fss_reference::unifi_direct::recording_rollover::{AutomaticRollover,AutomaticOwners,AutomaticStep,Finished};
                                                let mut auto=AutomaticRollover::prepare(session,supplies).map_err(|_|"automatic rollover preparation refused")?;
                                                assert!(matches!(auto.start(task,cx,other_clock,"fixture:archive",&BudgetVector::ZERO),Err(fss_reference::unifi_direct::av_rollover_worker::StartError::Context)));
                                                let (session,supplies)=auto.into_unstarted().map_err(|_|"automatic unstarted owners lost")?;
                                                let mut auto=AutomaticRollover::prepare(session,supplies).map_err(|_|"automatic recovery refused")?;
                                                auto.start(task,cx,clock,"fixture:archive",&BudgetVector::ZERO).map_err(|e|format!("automatic preflight refused: {e:?}"))?;
                                                let mut started=false;
                                                for _ in 0..100 {
                                                    let transition_clock=if late_audio_change==28 {other_clock} else {clock};
                                                    match auto.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,transition_clock,"fixture:archive",&BudgetVector::ZERO).await {
                                                        AutomaticStep::RolloverStarted=>{started=true;break;},
                                                        AutomaticStep::StartRefused(fss_reference::unifi_direct::av_rollover_worker::StartError::Context) if late_audio_change==28=>{
                                                            if !matches!(auto.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,"fixture:archive",&BudgetVector::ZERO).await,AutomaticStep::NotRunning) {return Err("automatic refusal was silently retried".into());}
                                                            auto.start(task,cx,clock,"fixture:archive",&BudgetVector::ZERO).map_err(|_|"explicit automatic retry refused")?;
                                                            started=true;break;
                                                        },
                                                        AutomaticStep::Control(supervisor::Step::Idle)=>(),
                                                        _=>return Err("automatic preflight stopped".into()),
                                                    }
                                                }
                                                if !started {return Err("automatic transition did not start".into());}
                                                assert!(matches!(auto.start(task,cx,clock,"fixture:archive",&BudgetVector::ZERO),Err(fss_reference::unifi_direct::av_rollover_worker::StartError::Running)));
                                                timeout(cx.now(),Duration::from_secs(5),async {while !read.entered.load(Ordering::Acquire) {asupersync::runtime::yield_now().await;}}).await.map_err(|_|"automatic replay did not enter")?;
                                                control_probe_tx.send(()).map_err(io::Error::other)?;
                                                if !matches!(auto.step(&mut owner,&operations[10],Duration::from_secs(5),task,cx,clock,"fixture:archive",&BudgetVector::ZERO).await,AutomaticStep::Control(supervisor::Step::TimeSyncWritten {..})) {return Err("automatic replay control failed".into());}
                                                if late_audio_change==26 {
                                                    auto.abort();
                                                    timeout(cx.now(),Duration::from_secs(5),async {while !auto.cancellation_observed() {asupersync::runtime::yield_now().await;}}).await.map_err(|_|"automatic cancellation not observed")?;
                                                    read.release.store(true,Ordering::Release);
                                                    if !auto.join().await {return Err("automatic cancellation did not join".into());}
                                                    if !matches!(auto.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,"fixture:archive",&BudgetVector::ZERO).await,AutomaticStep::Finished) {return Err("automatic cancellation not finalized".into());}
                                                    let (coordinator,rollover)=match auto.into_owners() {
                                                        Some(AutomaticOwners::Finished(Finished::Unresolved {coordinator,rollover}))=>(coordinator,rollover),
                                                        _=>return Err("automatic cancelled owners lost".into()),
                                                    };
                                                    let source=coordinator.into_worker().retire().map_err(|_|"automatic cancelled source retirement refused")?;
                                                    assert!(source.pending.is_none());
                                                    let retired=rollover.retire();
                                                    assert!(retired.resources.has_pending());
                                                    assert_eq!(retired.rollover_need,Some(need));
                                                    drop(retired);drop(originals);
                                                    peer.join().map_err(|_|"automatic cancellation peer panic")??;
                                                    return Ok(());
                                                }
                                                pin_gate.armed.store(true,Ordering::Release);
                                                read.release.store(true,Ordering::Release);
                                                timeout(cx.now(),Duration::from_secs(5),async {while !pin_gate.entered.load(Ordering::Acquire) {asupersync::runtime::yield_now().await;}}).await.map_err(|_|"automatic custody did not enter")?;
                                                control_probe_tx.send(()).map_err(io::Error::other)?;
                                                if !matches!(auto.step(&mut owner,&operations[11],Duration::from_secs(5),task,cx,clock,"fixture:archive",&BudgetVector::ZERO).await,AutomaticStep::Control(supervisor::Step::TimeSyncWritten {..})) {return Err("automatic custody control failed".into());}
                                                pin_gate.release.store(true,Ordering::Release);
                                                if !auto.join().await {return Err("automatic transition did not join".into());}
                                                let before=pin_gate.reads.load(Ordering::Acquire);
                                                if !matches!(auto.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,"fixture:archive",&BudgetVector::ZERO).await,AutomaticStep::Finished) {return Err("automatic transition did not finish".into());}
                                                assert_eq!(pin_gate.reads.load(Ordering::Acquire),before,"automatic finish reread custody");
                                                if late_audio_change==27 {
                                                    let (coordinator,rollover)=match auto.into_owners() {
                                                        Some(AutomaticOwners::Finished(Finished::Unresolved {coordinator,rollover}))=>(coordinator,rollover),
                                                        _=>return Err("automatic custody refusal owners lost".into()),
                                                    };
                                                    let source=coordinator.into_worker().retire().map_err(|_|"automatic refused source retirement failed")?;
                                                    assert!(source.pending.is_none());
                                                    let retired=rollover.retire();
                                                    assert!(retired.resources.has_pending());
                                                    assert_eq!(retired.rollover_need,Some(need));
                                                    assert!(matches!(retired.completion.outcome,fss_reference::unifi_direct::av_rollover_worker::Outcome::AttachRefused {..}));
                                                    drop(retired);drop(originals);
                                                    peer.join().map_err(|_|"automatic refusal peer panic")??;
                                                    return Ok(());
                                                }
                                                let mut session=match auto.into_owners() {
                                                    Some(AutomaticOwners::Finished(Finished::Resumed {session,receipt}))=>{assert_eq!(receipt.outcome,fss_publication::RootLedgerOutcome::AlreadyLedgered);session},
                                                    _=>return Err("automatic session not resumed".into()),
                                                };
                                                let av=fss_reference::unifi_direct::source_coordinator::ArchiveAdmission {resource:"fixture:archive",cost:&BudgetVector::ZERO};
                                                let source=fss_reference::unifi_direct::source_coordinator::ArchiveAdmission {resource:"fixture:source",cost:&BudgetVector::ZERO};
                                                if !matches!(session.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,av,source).await,fss_reference::unifi_direct::recording_session::Step::Recording(fss_reference::unifi_direct::source_coordinator::Step::Session(unknown::SessionEvent::Advance(Advance::ArchiveStarted)))) {return Err("automatic session did not start pending segment".into());}
                                                let (coordinator,phase)=session.into_parts();
                                                let mut guard=match phase {fss_reference::unifi_direct::recording_session::Phase::Recording(guard)=>*guard,_=>return Err("automatic session phase lost".into())};
                                                let mut coordinator=Some(coordinator);
                                                let mut published=false;
                                                for _ in 0..100 {
                                                    match guard.advance(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,"fixture:archive",&BudgetVector::ZERO).await {
                                                        Advance::Archive(Drive::Archive(done)) | Advance::Archive(Drive::Control {step:supervisor::Step::Idle|supervisor::Step::TimeSyncWritten {..},completion:Some(done)})=>{
                                                            if done.runtime.is_err() || !matches!(done.outcome,av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(_))) {return Err("automatic pending segment failed".into());}
                                                            published=true;break;
                                                        },
                                                        Advance::Archive(Drive::Control {step:supervisor::Step::Idle|supervisor::Step::TimeSyncWritten {..},completion:None})=>(),
                                                        _=>return Err("automatic session stopped".into()),
                                                    }
                                                }
                                                if !published {return Err("automatic pending segment timed out".into());}
                                                if matches!(late_audio_change,29|30|31|32|33) {
                                                    let mut visible=3;
                                                    let mut second_need=None;
                                                    let mut renewed_audio=false;
                                                    timeout(cx.now(),Duration::from_secs(15),async {
                                                        for _ in 0..8192 {
                                                            match guard.advance(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,"fixture:archive",&BudgetVector::ZERO).await {
                                                                Advance::Source(unknown::Step::Supervisor(supervisor::Step::AudioPending))=>{
                                                                    let event=guard.take_audio_event(&owner).ok_or("second rollover audio withheld")?;
                                                                    if matches!(event,pipeline::AudioEvent::Fenced(_)|pipeline::AudioEvent::Observed(fss_packet::extended_flv::aac_track::Observation::Configuration {..})) {return Err("second rollover audio fenced");}
                                                                },
                                                                Advance::Source(unknown::Step::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {record,..}))))=>originals.push(record),
                                                                Advance::Source(unknown::Step::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Buffered)|pipeline::Step::Progress {..})|supervisor::Step::TimeSyncWritten {..}|supervisor::Step::Idle))|Advance::Source(unknown::Step::SourceQueued)|Advance::ArchiveStarted|Advance::Archive(Drive::Control {step:supervisor::Step::Idle|supervisor::Step::TimeSyncWritten {..},completion:None})=>(),
                                                                Advance::Archive(Drive::Archive(done))|Advance::Archive(Drive::Control {step:supervisor::Step::Idle|supervisor::Step::TimeSyncWritten {..},completion:Some(done)})=>{
                                                                    if done.runtime.is_err(){return Err("second rollover archive task failed");}
                                                                    match done.outcome {
                                                                        av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(_))=>visible+=1,
                                                                        av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Refused {rollover:Some(need),..})=>{second_need=Some(need);return Ok(());},
                                                                        av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Refused {stage:av_worker::UnknownTimeFailureStage::Preparation,reason:av_worker::FailureReason::Media(fss_reference::unifi_direct::av_recording::Error::Clock(fss_packet::extended_flv::aac_clock::Error::Limit)),pending:None,receipt:None,rollover:None}) if !renewed_audio=>{
                                                                            assert!(matches!(guard.extend_audio_limit(0),Err(av_worker::AudioAllowanceError::Mux(fss_reference::unifi_direct::av_recording::Error::Clock(fss_packet::extended_flv::aac_clock::Error::Configuration)))));
                                                                            assert!(guard.extend_audio_limit(16).is_ok());
                                                                            assert!(guard.authorize_retry());
                                                                            renewed_audio=true;
                                                                        },
                                                                        av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Refused {stage,reason,pending,receipt,rollover})=>{eprintln!("second_rollover_refused stage={stage:?} reason={reason:?} pending={} receipt={} rollover={}",pending.is_some(),receipt.is_some(),rollover.is_some());return Err("second rollover archive outcome unexpected");},
                                                                        other=>{eprintln!("second_rollover_other={:?}",std::mem::discriminant(&other));return Err("second rollover archive outcome unexpected");},
                                                                    }
                                                                },
                                                                _=>return Err("second rollover scheduler stopped"),
                                                            }
                                                        }
                                                        Err("second rollover signal missing")
                                                    }).await.map_err(|_|"second rollover signal timed out")??;
                                                    let second_need=second_need.ok_or("second rollover need missing")?;
                                                    assert!(renewed_audio,"fixture did not exercise audio-clock exhaustion");
                                                    assert_eq!(visible,4);
                                                    assert_eq!(guard.rollover_need(),Some(second_need));
                                                    let supply_gate=Arc::new(SupplyIoGate {entered:AtomicBool::new(false),release:AtomicBool::new(false)});
                                                    let supply_root=temp.0.join("automatic-second-supplies");
                                                    let pin_root=temp.0.join("automatic-second-pin");
                                                    let switch_custody=fss_reference::unifi_direct::av_rollover_supplies::SwitchCustody {root:pin_root.clone(),replay:Arc::new(fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?),io:Arc::new(HostSpoolIo),limits,scope:ContentDigest::sha256(b"automatic second switch root")};
                                                    let second_limits=if late_audio_change==31 {EffectJournalLimits {max_records:5,..limits}} else {limits};
                                                    let supply_worker=fss_reference::unifi_direct::av_rollover_supplies::Worker::new(fss_reference::unifi_direct::av_rollover_supplies::Inputs {root:supply_root.clone(),replay:Arc::new(fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?),io:Arc::new(BlockingSupplyIo(supply_gate.clone())),journal_limits:second_limits,switch:fss_reference::unifi_direct::av_rollover_supplies::SwitchInput::Create(switch_custody),read:access.clone(),object_limits:archive::StagedAvLimits {max_objects:8192,max_object_bytes:1024*1024,max_total_bytes:8*1024*1024},work_limit:100_000_000_000}).map_err(|_|"managed supply worker refused")?;
                                                    let source_coordinator=coordinator.take().ok_or("automatic coordinator missing")?;
                                                    let second_session=fss_reference::unifi_direct::recording_session::Session::from_recording(source_coordinator,Box::new(guard));
                                                    pin_gate.entered.store(false,Ordering::Release);
                                                    pin_gate.release.store(false,Ordering::Release);
                                                    let before=pin_gate.reads.load(Ordering::Acquire);
                                                    assert!(fss_reference::unifi_direct::recording_session::AudioAllowancePolicy::new(0,128,128).is_none());
                                                    let policy=fss_reference::unifi_direct::recording_session::AudioAllowancePolicy::new(100,128,128).ok_or("automatic audio policy refused")?;
                                                    let mut second=fss_reference::unifi_direct::recording_rollover::ManagedSession::new(second_session,policy);
                                                    if !matches!(second.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,other_clock,av,source).await,fss_reference::unifi_direct::recording_rollover::ManagedStep::Recording(fss_reference::unifi_direct::recording_session::AudioAllowanceStep::Session(fss_reference::unifi_direct::recording_session::Step::Recording(fss_reference::unifi_direct::source_coordinator::Step::Context)))) {return Err("managed wrong clock did not preserve session".into());}
                                                    owner.clock=other_clock;
                                                    let wrong_owner_result=second.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,av,source).await;
                                                    owner.clock=clock;
                                                    if !matches!(wrong_owner_result,fss_reference::unifi_direct::recording_rollover::ManagedStep::Recording(fss_reference::unifi_direct::recording_session::AudioAllowanceStep::Session(fss_reference::unifi_direct::recording_session::Step::Recording(fss_reference::unifi_direct::source_coordinator::Step::Context)))) {return Err("managed wrong owner clock did not preserve session".into());}
                                                    control_probe_tx.send(()).map_err(io::Error::other)?;
                                                    if !matches!(second.step(&mut owner,&operations[14],Duration::from_secs(5),task,cx,clock,av,source).await,fss_reference::unifi_direct::recording_rollover::ManagedStep::SuppliesRequired {need,control:supervisor::Step::TimeSyncWritten {..}} if need==second_need) {return Err("managed supplies wait lost control or boundary".into());}
                                                    let mut provisioning=fss_reference::unifi_direct::recording_provision::ProvisioningSession::new(second,supply_worker);
                                                    if !matches!(provisioning.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,other_clock,av,source,&BudgetVector::ZERO).await,fss_reference::unifi_direct::recording_provision::Step::Managed(fss_reference::unifi_direct::recording_rollover::ManagedStep::Recording(fss_reference::unifi_direct::recording_session::AudioAllowanceStep::Session(fss_reference::unifi_direct::recording_session::Step::Recording(fss_reference::unifi_direct::source_coordinator::Step::Context))))) {return Err("provisioning admitted wrong clock".into());}
                                                    owner.clock=other_clock;
                                                    let wrong_owner_result=provisioning.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,av,source,&BudgetVector::ZERO).await;
                                                    owner.clock=clock;
                                                    if !matches!(wrong_owner_result,fss_reference::unifi_direct::recording_provision::Step::Managed(fss_reference::unifi_direct::recording_rollover::ManagedStep::Recording(fss_reference::unifi_direct::recording_session::AudioAllowanceStep::Session(fss_reference::unifi_direct::recording_session::Step::Recording(fss_reference::unifi_direct::source_coordinator::Step::Context))))) {return Err("provisioning admitted wrong owner clock".into());}
                                                    assert!(!supply_root.exists() && !supply_gate.entered.load(Ordering::Acquire));
                                                    if late_audio_change==32 {
                                                        use fss_reference::unifi_direct::{recording_provision as provision, recording_rollover as managed, recording_session as session_mod};
                                                        provisioning.abort();
                                                        assert!(provisioning.control().is_none());
                                                        let after_abort=provisioning.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,av,source,&BudgetVector::ZERO).await;
                                                        if matches!(after_abort,provision::Step::SupplyStarted|provision::Step::SupplyPlanned(_)) {
                                                            supply_gate.release.store(true,Ordering::Release);
                                                            provisioning.abort();
                                                            let _=provisioning.join_supply().await;
                                                            return Err("aborted provisioning started a new creator".into());
                                                        }
                                                        if !matches!(after_abort,provision::Step::Aborted) {return Err("aborted provisioning did not report cancellation".into());}
                                                        assert!(!provisioning.authorize_start_retry());
                                                        assert!(!supply_root.exists() && !pin_root.exists());
                                                        let owners=provisioning.into_parts();
                                                        assert!(owners.aborted);
                                                        assert!(!owners.started && owners.completion.is_none() && owners.ready.is_none() && owners.failed.is_none() && owners.custody.is_none());
                                                        let unstarted=owners.worker.ok_or("aborted creator lost")?.retire().map_err(|_|"aborted creator unexpectedly running")?;
                                                        assert!(unstarted.inputs.is_some() && unstarted.outcome.is_none());
                                                        let (managed_owner,_policy,unused)=owners.managed.into_parts();
                                                        assert!(unused.is_none());
                                                        let session=match managed_owner {Some(managed::ManagedOwners::Session(session))=>*session,_=>return Err("aborted managed session lost".into())};
                                                        let (source_coordinator,phase)=session.into_parts();
                                                        let guard=match phase {session_mod::Phase::Recording(guard)=>guard,_=>return Err("aborted recording guard lost".into())};
                                                        let source=source_coordinator.into_worker().retire().map_err(|_|"aborted source retirement refused")?;
                                                        assert!(source.pending.is_none());
                                                        let retired=(*guard).retire().map_err(|_|"aborted guard retirement refused")?;
                                                        assert!(retired.worker.parts.sink.retire().pending.is_some());
                                                        drop(retired.supervisor);drop(unstarted);drop(originals);
                                                        peer.join().map_err(|_|"aborted creator peer panic")??;
                                                        return Ok(());
                                                    }
                                                    if late_audio_change==30 {
                                                        let mut excessive=BudgetVector::ZERO; excessive.bytes=u64::MAX;
                                                        if !matches!(provisioning.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,av,source,&excessive).await,fss_reference::unifi_direct::recording_provision::Step::SupplyStartRefused(fss_reference::unifi_direct::av_rollover_supplies::StartError::Task(_))) {return Err("supply budget refusal lost".into());}
                                                        if !matches!(provisioning.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,av,source,&BudgetVector::ZERO).await,fss_reference::unifi_direct::recording_provision::Step::Managed(fss_reference::unifi_direct::recording_rollover::ManagedStep::SuppliesRequired {control:supervisor::Step::Idle,..})) {return Err("supply admission silently retried".into());}
                                                        assert!(!supply_root.exists());
                                                        assert!(provisioning.authorize_start_retry());
                                                        assert!(!provisioning.authorize_start_retry());
                                                    }
                                                    if !matches!(provisioning.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,av,source,&BudgetVector::ZERO).await,fss_reference::unifi_direct::recording_provision::Step::SupplyStarted) {return Err("supply worker did not start".into());}
                                                    timeout(cx.now(),Duration::from_secs(5),async {while !supply_gate.entered.load(Ordering::Acquire) {asupersync::runtime::yield_now().await;}}).await.map_err(|_|"supply storage did not block")?;
                                                    if late_audio_change==33 {
                                                        use fss_reference::unifi_direct::{recording_provision as provision, recording_rollover as managed, recording_session as session_mod};
                                                        supply_gate.release.store(true,Ordering::Release);
                                                        if !provisioning.join_supply().await {return Err("completed supply did not join".into());}
                                                        provisioning.abort();
                                                        assert!(provisioning.control().is_none());
                                                        if !matches!(provisioning.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,av,source,&BudgetVector::ZERO).await,provision::Step::Aborted) {return Err("completed supplies installed after abort".into());}
                                                        let owners=provisioning.into_parts();
                                                        assert!(owners.aborted && !owners.started && owners.worker.is_none() && owners.failed.is_none() && owners.custody.is_none());
                                                        assert!(owners.completion.as_ref().is_some_and(|completion|completion.runtime.is_ok() && completion.outcome==fss_reference::unifi_direct::av_rollover_supplies::Outcome::Ready));
                                                        let ready=owners.ready.ok_or("completed supplies lost after abort")?;
                                                        assert_eq!(ready.root,supply_root);
                                                        let (managed_owner,_policy,unused)=owners.managed.into_parts();
                                                        assert!(unused.is_none());
                                                        let session=match managed_owner {Some(managed::ManagedOwners::Session(session))=>*session,_=>return Err("late-abort managed session lost".into())};
                                                        let (source_coordinator,phase)=session.into_parts();
                                                        let guard=match phase {session_mod::Phase::Recording(guard)=>guard,_=>return Err("late-abort guard lost".into())};
                                                        let source=source_coordinator.into_worker().retire().map_err(|_|"late-abort source retirement refused")?;
                                                        assert!(source.pending.is_none());
                                                        let retired=(*guard).retire().map_err(|_|"late-abort guard retirement refused")?;
                                                        assert!(retired.worker.parts.sink.retire().pending.is_some());
                                                        drop(retired.supervisor);drop(ready);drop(originals);
                                                        peer.join().map_err(|_|"late-abort peer panic")??;
                                                        return Ok(());
                                                    }
                                                    control_probe_tx.send(()).map_err(io::Error::other)?;
                                                    if !matches!(provisioning.step(&mut owner,&operations[15],Duration::from_secs(5),task,cx,clock,av,source,&BudgetVector::ZERO).await,fss_reference::unifi_direct::recording_provision::Step::Managed(fss_reference::unifi_direct::recording_rollover::ManagedStep::SuppliesRequired {need,control:supervisor::Step::TimeSyncWritten {..}}) if need==second_need) {return Err("blocked supply storage lost control".into());}
                                                    if late_audio_change==30 {
                                                        let plan=fss_reference::unifi_direct::av_rollover_generation::Plan::new(fss_reference::unifi_direct::av_rollover_generation::Configuration {namespace:"abort_fixture".into(),scope_seed:ContentDigest::sha256(b"cancelled fixture plan"),first:3,count:1,journal_replay:Arc::new(fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?),pin_replay:Arc::new(fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?),journal_io:Arc::new(HostSpoolIo),pin_io:Arc::new(HostSpoolIo),journal_limits:limits,pin_limits:limits,read:access.clone(),object_limits:archive::StagedAvLimits {max_objects:8192,max_object_bytes:1024*1024,max_total_bytes:8*1024*1024},work_limit:100_000_000_000}).map_err(|_|"cancel fixture plan refused")?;
                                                        provisioning.set_plan(plan).map_err(|_|"cancel fixture plan not installed")?;
                                                        provisioning.abort();
                                                        supply_gate.release.store(true,Ordering::Release);
                                                        if !provisioning.join_supply().await {return Err("cancelled supply worker did not join".into());}
                                                        if !matches!(provisioning.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,av,source,&BudgetVector::ZERO).await,fss_reference::unifi_direct::recording_provision::Step::SupplyFailed(completion) if completion.outcome==fss_reference::unifi_direct::av_rollover_supplies::Outcome::Cancelled) {return Err("cancelled supply outcome lost".into());}
                                                        let failed=provisioning.take_failed().ok_or("cancelled supply owners lost")?;
                                                        if !matches!(provisioning.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,av,source,&BudgetVector::ZERO).await,fss_reference::unifi_direct::recording_provision::Step::Aborted) {return Err("cancelled provisioning did not remain stopped".into());}
                                                        let owners=provisioning.into_parts();
                                                        assert!(owners.aborted);
                                                        assert!(owners.failed.is_none() && owners.plan.as_ref().is_some_and(|plan|plan.remaining()==1));
                                                        assert!(!temp.0.join("fss-av-abort_fixture-0000000000000003").exists());
                                                        assert!(failed.root_created && !failed.pin_root_created && failed.inputs.is_some() && failed.journal.is_none() && failed.keeper.is_none());
                                                        assert!(owners.worker.is_none() && owners.ready.is_none() && owners.custody.is_none());
                                                        let (managed_owner,_policy,unused)=owners.managed.into_parts();
                                                        assert!(unused.is_none());
                                                        let session=match managed_owner {Some(fss_reference::unifi_direct::recording_rollover::ManagedOwners::Session(session))=>*session,_=>return Err("cancelled managed session lost".into())};
                                                        let (source_coordinator,phase)=session.into_parts();
                                                        let guard=match phase {fss_reference::unifi_direct::recording_session::Phase::Recording(guard)=>guard,_=>return Err("cancelled recording guard lost".into())};
                                                        let source=source_coordinator.into_worker().retire().map_err(|_|"cancelled source retirement refused")?;
                                                        assert!(source.pending.is_none());
                                                        let retired=(*guard).retire().map_err(|_|"cancelled guard retirement refused")?;
                                                        assert!(retired.worker.parts.sink.retire().pending.is_some());
                                                        drop(retired.supervisor);drop(failed);drop(originals);
                                                        peer.join().map_err(|_|"cancelled supply peer panic")??;
                                                        return Ok(());
                                                    }
                                                    supply_gate.release.store(true,Ordering::Release);
                                                    let mut installed=false;
                                                    for _ in 0..100 {
                                                        match provisioning.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,av,source,&BudgetVector::ZERO).await {
                                                            fss_reference::unifi_direct::recording_provision::Step::SupplyInstalled(completion)=>{if completion.runtime.is_err() || completion.outcome!=fss_reference::unifi_direct::av_rollover_supplies::Outcome::Ready {return Err("supply completion not ready".into());} installed=true;break;},
                                                            fss_reference::unifi_direct::recording_provision::Step::Managed(fss_reference::unifi_direct::recording_rollover::ManagedStep::SuppliesRequired {control:supervisor::Step::Idle,..})=>(),
                                                            _=>return Err("supply provisioning stopped".into()),
                                                        }
                                                    }
                                                    if !installed {return Err("supply provisioning timed out".into());}
                                                    let custody=provisioning.take_custody().ok_or("supply custody lost")?;
                                                    assert_eq!(custody.root,supply_root);
                                                    assert_eq!(custody.switch_custody.as_ref().ok_or("pin custody plan lost")?.root,pin_root);
                                                    let make_next=|name:&str| -> Result<fss_reference::unifi_direct::av_rollover_supplies::Worker,Box<dyn Error>> {
                                                        let pin=fss_reference::unifi_direct::av_rollover_supplies::SwitchCustody {root:temp.0.join(format!("{name}-pin")),replay:Arc::new(fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?),io:Arc::new(HostSpoolIo),limits,scope:ContentDigest::sha256(name.as_bytes())};
                                                        let inputs=fss_reference::unifi_direct::av_rollover_supplies::Inputs {root:temp.0.join(name),replay:Arc::new(fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?),io:Arc::new(HostSpoolIo),journal_limits:limits,switch:fss_reference::unifi_direct::av_rollover_supplies::SwitchInput::Create(pin),read:access.clone(),object_limits:archive::StagedAvLimits {max_objects:8192,max_object_bytes:1024*1024,max_total_bytes:8*1024*1024},work_limit:100_000_000_000};
                                                        fss_reference::unifi_direct::av_rollover_supplies::Worker::new(inputs).map_err(|_|"future supply configuration refused".into())
                                                    };
                                                    if late_audio_change!=31 {
                                                        provisioning.offer_worker(make_next("automatic-third-supplies")?).map_err(|_|"future supply worker refused")?;
                                                        let rejected=match provisioning.offer_worker(make_next("automatic-rejected-supplies")?) {Err(worker)=>worker,Ok(())=>return Err("staged creator overwritten".into())};
                                                        let rejected=rejected.retire().map_err(|_|"rejected creator unexpectedly running")?;
                                                        assert!(rejected.outcome.is_none() && rejected.inputs.is_some());
                                                    }
                                                    if late_audio_change==31 {
                                                        use fss_reference::unifi_direct::{recording_provision as provision, recording_rollover as managed, recording_session as session_mod, source_coordinator as source_mod, source_handoff, source_worker};
                                                        {
                                                            let mut control=provisioning.control().ok_or("recording control unavailable")?;
                                                            assert!(control.set_time_sync_reply_wait(Some(Duration::ZERO)).is_err());
                                                            control.set_time_sync_reply_wait(Some(Duration::from_secs(2)))?;
                                                            control.set_time_sync_reply_wait(None)?;
                                                        }
                                                        let plan=fss_reference::unifi_direct::av_rollover_generation::Plan::new(fss_reference::unifi_direct::av_rollover_generation::Configuration {namespace:"fixture_camera".into(),scope_seed:ContentDigest::sha256(b"automatic fixture plan"),first:3,count:2,journal_replay:Arc::new(fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?),pin_replay:Arc::new(fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.0.clone())?),journal_io:Arc::new(HostSpoolIo),pin_io:Arc::new(HostSpoolIo),journal_limits:limits,pin_limits:limits,read:access.clone(),object_limits:archive::StagedAvLimits {max_objects:8192,max_object_bytes:1024*1024,max_total_bytes:8*1024*1024},work_limit:100_000_000_000}).map_err(|_|"automatic plan refused")?;
                                                        provisioning.set_plan(plan).map_err(|_|"automatic plan not installed")?;
                                                        assert!(provisioning.extend_plan(1).is_err());
                                                        let planned=match provisioning.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,av,source,&BudgetVector::ZERO).await {provision::Step::SupplyPlanned(identity)=>identity,_=>return Err("third generation was not planned".into())};
                                                        assert_eq!(planned.generation,3);
                                                        assert!(!planned.journal_root.exists() && !planned.pin_root.exists());
                                                        if !matches!(provisioning.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,av,source,&BudgetVector::ZERO).await,provision::Step::SupplyStarted) {return Err("third creator did not start".into());}
                                                        let mut preflight_started=false;
                                                        let mut third_installed=false;
                                                        for _ in 0..512 {
                                                            match provisioning.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,av,source,&BudgetVector::ZERO).await {
                                                                provision::Step::Managed(managed::ManagedStep::PreflightStarted)=>preflight_started=true,
                                                                provision::Step::SupplyInstalled(completion)=>{if completion.runtime.is_err() || completion.outcome!=fss_reference::unifi_direct::av_rollover_supplies::Outcome::Ready {return Err("third creator completion failed".into());} third_installed=true;},
                                                                provision::Step::Managed(managed::ManagedStep::Rollover(AutomaticStep::Control(supervisor::Step::Idle)))=>(),
                                                                _=>return Err("second transition or next creator stopped".into()),
                                                            }
                                                            if preflight_started && third_installed {break;}
                                                        }
                                                        if !preflight_started || !third_installed {return Err("third creator was not installed while second rollover ran".into());}
                                                        let third_custody=provisioning.take_custody().ok_or("third creator custody lost")?;
                                                        assert_eq!(third_custody.root,planned.journal_root);
                                                        assert_eq!(third_custody.switch_custody.as_ref().ok_or("planned pin custody lost")?.root,planned.pin_root);
                                                        timeout(cx.now(),Duration::from_secs(5),async {while !pin_gate.entered.load(Ordering::Acquire) {asupersync::runtime::yield_now().await;}}).await.map_err(|_|"second preflight did not block")?;
                                                        {
                                                            let mut control=provisioning.control().ok_or("preflight control unavailable")?;
                                                            control.set_time_sync_reply_wait(Some(Duration::from_secs(2)))?;
                                                            control.set_time_sync_reply_wait(None)?;
                                                        }
                                                        control_probe_tx.send(()).map_err(io::Error::other)?;
                                                        if !matches!(provisioning.step(&mut owner,&operations[12],Duration::from_secs(5),task,cx,clock,av,source,&BudgetVector::ZERO).await,provision::Step::Managed(managed::ManagedStep::Rollover(AutomaticStep::Control(supervisor::Step::TimeSyncWritten {..})))) {return Err("second managed preflight lost control".into());}
                                                        control_probe_tx.send(()).map_err(io::Error::other)?;
                                                        let event=match provisioning.step(&mut owner,&operations[6],Duration::from_secs(5),task,cx,clock,av,source,&BudgetVector::ZERO).await {
                                                            provision::Step::Managed(managed::ManagedStep::Rollover(AutomaticStep::Control(supervisor::Step::CameraEvent(frame))))=>frame,
                                                            _=>return Err("preflight event was not delivered".into()),
                                                        };
                                                        if event.source()!=ROLLOVER_REPLY_EVENT || !event.response_expected() {return Err("wrong preflight event".into());}
                                                        let mut event_trace=provisioning.control().ok_or("preflight event control unavailable")?.prepare_journaled_event_reply(&mut owner,&event,"2026-11-05T10:00:00.000Z",&operations[17]).map_err(|_|"preflight event preparation refused")?;
                                                        let mut event_control=provisioning.control().ok_or("preflight event control disappeared")?;
                                                        Box::pin(event_control.dispatch_event_reply_tracked(&owner,conditions,Duration::from_secs(5),&mut event_trace)).await.map_err(|_|"preflight event dispatch unavailable")?;
                                                        match event_trace.take_outcome() {
                                                            Some(Ok(ManagementWrite::Written {permit})) if permit.journal_backed()=>(),
                                                            Some(Err(refusal))=>return Err(format!("preflight event reply refused: {:?}",refusal.reason).into()),
                                                            _=>return Err("preflight event reply did not complete".into()),
                                                        }
                                                        pin_gate.release.store(true,Ordering::Release);
                                                        let mut resumed=0usize;
                                                        let mut visible=4usize;
                                                        let mut between_transitions=0usize;
                                                        let mut source_offered=0usize;
                                                        let mut source_published=0usize;
                                                        let mut published_pins=Vec::new();
                                                        let mut saw_third_need=false;
                                                        let mut third_control=false;
                                                        let mut third_started=false;
                                                        let mut plan_exhausted=false;
                                                        let mut fourth_planned=None;
                                                        let mut fourth_started=false;
                                                        let mut fourth_custody=None;
                                                        let mut rollover_control_seen=false;
                                                        let mut finished=false;
                                                        for _ in 0..1024 {
                                                            let step=provisioning.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,av,source,&BudgetVector::ZERO).await;
                                                            let mut av_completion=None;
                                                            match step {
                                                                provision::Step::SupplyPlanned(identity)=>{
                                                                    if identity.generation!=4 || fourth_planned.is_some() || identity.journal_root.exists() || identity.pin_root.exists() {return Err("fourth generation identity invalid".into());}
                                                                    fourth_planned=Some(identity);
                                                                },
                                                                provision::Step::SupplyStarted=>{if fourth_started || fourth_planned.is_none(){return Err("fourth creator started unexpectedly".into());}fourth_started=true;},
                                                                provision::Step::SupplyInstalled(completion)=>{
                                                                    if completion.runtime.is_err() || completion.outcome!=fss_reference::unifi_direct::av_rollover_supplies::Outcome::Ready || fourth_custody.is_some(){return Err("fourth supply installation invalid".into());}
                                                                    fourth_custody=Some(provisioning.take_custody().ok_or("fourth custody lost")?);
                                                                },
                                                                provision::Step::PlanExhausted=>{if plan_exhausted {return Err("plan exhaustion was repeated".into());}plan_exhausted=true;},
                                                                provision::Step::Managed(managed::ManagedStep::Rollover(AutomaticStep::Control(supervisor::Step::Idle)))=>(),
                                                                provision::Step::Managed(managed::ManagedStep::Rollover(AutomaticStep::RolloverStarted))=>{
                                                                    let mut control=provisioning.control().ok_or("rollover control unavailable")?;
                                                                    control.set_time_sync_reply_wait(Some(Duration::from_secs(2)))?;
                                                                    control.set_time_sync_reply_wait(None)?;
                                                                    rollover_control_seen=true;
                                                                },
                                                                provision::Step::Managed(managed::ManagedStep::Resumed(receipt))=>{assert_eq!(receipt.outcome,fss_publication::RootLedgerOutcome::AlreadyLedgered);resumed+=1;},
                                                                provision::Step::Managed(managed::ManagedStep::PreflightStarted) if resumed==1 && saw_third_need=>{
                                                                    third_started=true;
                                                                    timeout(cx.now(),Duration::from_secs(5),async {while !pin_gate.entered.load(Ordering::Acquire) {asupersync::runtime::yield_now().await;}}).await.map_err(|_|"third preflight did not block")?;
                                                                    control_probe_tx.send(()).map_err(io::Error::other)?;
                                                                    let mut replied=false;
                                                                    for _ in 0..8 {
                                                                        match provisioning.step(&mut owner,&operations[16],Duration::from_secs(5),task,cx,clock,av,source,&BudgetVector::ZERO).await {
                                                                            provision::Step::Managed(managed::ManagedStep::Rollover(AutomaticStep::Control(supervisor::Step::TimeSyncWritten {..})))=>{replied=true;break;},
                                                                            provision::Step::SupplyInstalled(completion)=>{
                                                                                if completion.runtime.is_err() || completion.outcome!=fss_reference::unifi_direct::av_rollover_supplies::Outcome::Ready || fourth_custody.is_some(){return Err("fourth supply installation invalid".into());}
                                                                                fourth_custody=Some(provisioning.take_custody().ok_or("fourth custody lost")?);
                                                                            },
                                                                            _=>return Err("third preflight lost control".into()),
                                                                        }
                                                                    }
                                                                    if !replied {return Err("third preflight reply missing".into());}
                                                                    third_control=true;pin_gate.release.store(true,Ordering::Release);
                                                                },
                                                                provision::Step::Managed(managed::ManagedStep::Recording(session_mod::AudioAllowanceStep::Renewed {..}))=>(),
                                                                provision::Step::Managed(managed::ManagedStep::Recording(session_mod::AudioAllowanceStep::Session(session_mod::Step::Recording(event))))=>match event {
                                                                    source_mod::Step::Session(unknown::SessionEvent::Audio(event))=>if matches!(event,pipeline::AudioEvent::Fenced(_)|pipeline::AudioEvent::Observed(fss_packet::extended_flv::aac_track::Observation::Configuration {..})){return Err("third session audio fenced".into());},
                                                                    source_mod::Step::SourceOffered(source_handoff::Result::Accepted {origin:source_handoff::Origin::Source,..})=>source_offered+=1,
                                                                    source_mod::Step::SourceStarted=>(),
                                                                    source_mod::Step::SourceOffered(source_handoff::Result::Accepted {origin:source_handoff::Origin::Control {completion},..})=>{source_offered+=1;av_completion=completion;},
                                                                    source_mod::Step::SourceArchive(source_handoff::Drive::Completed(completion))=>{if completion.runtime.is_err() || !matches!(completion.outcome,source_worker::Outcome::Publication(source_worker::Publication::Published {..})){return Err("third source publication failed".into());}source_published+=1;},
                                                                    source_mod::Step::SourceArchive(source_handoff::Drive::Control {step,completion})=>{
                                                                        if !matches!(step,supervisor::Step::Idle|supervisor::Step::TimeSyncWritten {..}) {return Err("third source control stopped".into());}
                                                                        if let Some(completion)=completion {if completion.runtime.is_err() || !matches!(completion.outcome,source_worker::Outcome::Publication(source_worker::Publication::Published {..})){return Err("third source publication failed".into());}source_published+=1;}
                                                                    },
                                                                    source_mod::Step::Session(unknown::SessionEvent::Advance(Advance::Source(unknown::Step::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Buffered)|pipeline::Step::Progress {..})|supervisor::Step::Idle|supervisor::Step::TimeSyncWritten {..}))|Advance::Source(unknown::Step::SourceQueued)|Advance::ArchiveStarted))=>(),
                                                                    source_mod::Step::Session(unknown::SessionEvent::Advance(Advance::Archive(Drive::Archive(completion))))=>av_completion=Some(completion),
                                                                    source_mod::Step::Session(unknown::SessionEvent::Advance(Advance::Archive(Drive::Control {step,completion})))=>{if !matches!(step,supervisor::Step::Idle|supervisor::Step::TimeSyncWritten {..}){return Err("third archive control stopped".into());}av_completion=completion;},
                                                                    _=>return Err("third session source outcome unexpected".into()),
                                                                },
                                                                _=>return Err("managed three-generation driver stopped".into()),
                                                            }
                                                            if let Some(completion)=av_completion {
                                                                if completion.runtime.is_err(){return Err("third session archive runtime failed".into());}
                                                                match completion.outcome {
                                                                    av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(published))=>{visible+=1;published_pins.push((resumed,published.pin));if resumed==1 {between_transitions+=1;}if resumed==2 {finished=true;}},
                                                                    av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Refused {rollover:Some(_),..}) if resumed==1 && !saw_third_need=>{saw_third_need=true;pin_gate.entered.store(false,Ordering::Release);pin_gate.release.store(false,Ordering::Release);},
                                                                    _=>return Err("third session archive outcome unexpected".into()),
                                                                }
                                                            }
                                                            if finished && source_published==source_offered && fourth_custody.is_some() && plan_exhausted {break;}
                                                        }
                                                        // After configuration, this fixture's source records belong to A/V
                                                        // segments rather than the separately archived pre-roll lane.
                                                        if !finished || resumed!=2 || !saw_third_need || !third_started || !third_control || !rollover_control_seen || !plan_exhausted || !fourth_started || fourth_custody.is_none() || between_transitions==0 || source_offered!=0 || !published_pins.iter().any(|(generation,_)|*generation==1) || !published_pins.iter().any(|(generation,_)|*generation==2) {
                                                            eprintln!("three_generation_accounting finished={finished} resumed={resumed} need={saw_third_need} started={third_started} control={third_control} between={between_transitions} source_offered={source_offered} source_published={source_published} visible={visible}");
                                                            return Err("three-generation session did not complete its media obligations".into());
                                                        }
                                                        assert!(provisioning.extend_plan(0).is_err());
                                                        provisioning.extend_plan(1).map_err(|_|"exhausted A/V plan did not renew")?;
                                                        let renewed=match provisioning.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,av,source,&BudgetVector::ZERO).await {provision::Step::SupplyPlanned(identity)=>identity,_=>return Err("renewed A/V generation not planned".into())};
                                                        assert_eq!(renewed.generation,5);
                                                        assert!(provisioning.extend_plan(1).is_err());
                                                        let mut owners=provisioning.into_parts();
                                                        let planned_worker=owners.worker.take().ok_or("renewed A/V worker lost")?;
                                                        assert!(planned_worker.retire().map_err(|_|"renewed A/V worker unexpectedly running")?.inputs.is_some());
                                                        assert!(owners.ready.is_none() && owners.failed.is_none() && owners.custody.is_none());
                                                        assert!(!owners.plan_stopped && owners.plan.as_ref().is_some_and(|plan|plan.remaining()==0));
                                                        let (managed_owner,_policy,unused)=owners.managed.into_parts();
                                                        let unused=unused.ok_or("fourth staged supplies lost")?;
                                                        assert!(unused.next_journal.head().is_none() && unused.next_keeper.head().is_none() && fss_runtime::effect_journal::EffectJournalStore::head(&unused.switch).is_none());
                                                        let fourth_custody=fourth_custody.ok_or("fourth custody missing")?;
                                                        let fourth_planned=fourth_planned.ok_or("fourth identity missing")?;
                                                        assert_eq!(fourth_custody.root,fourth_planned.journal_root);
                                                        assert_eq!(fourth_custody.switch_custody.as_ref().ok_or("fourth pin custody missing")?.root,fourth_planned.pin_root);
                                                        let session=match managed_owner {Some(managed::ManagedOwners::Session(session))=>*session,_=>return Err("three-generation session owner lost".into())};
                                                        let mut shutdown=match session.stop(){session_mod::Stop::Recording(shutdown)=>shutdown,_=>return Err("three-generation stop phase lost".into())};
                                                        if let Some(completion)=shutdown.join_source().await {if completion.runtime.is_err() || !matches!(completion.outcome,source_worker::Outcome::Publication(source_worker::Publication::Published {..})){return Err("three-generation source drain failed".into());}source_published+=1;}
                                                        assert_eq!(source_published,source_offered,"source publication outcomes were not all accounted for");
                                                        if shutdown.join_av().await.is_some(){return Err("unexpected final A/V worker".into());}
                                                        let (source_coordinator,guard)=shutdown.finish().map_err(|_|"three-generation shutdown refused")?;
                                                        let source=source_coordinator.into_worker().retire().map_err(|_|"three-generation source retirement refused")?;
                                                        assert!(!source.fenced && source.pending.is_none());
                                                        let retired=(*guard).retire().map_err(|_|"three-generation guard retirement refused")?;
                                                        assert_eq!(retired.worker.parts.deployment.publisher().visible_roots().count(),visible);
                                                        assert_eq!(retired.worker.rollover_custody.as_ref().map(|c|c.transition_count()),Some(3));
                                                        let mut parts=retired.worker.parts;
                                                        assert!(parts.sink.retire().pending.is_none());
                                                        for (_,pin) in published_pins {
                                                            match archive::read_unknown_time_av_any(&mut parts.deployment,pin,access.as_ref(),archive::Limits::default(),&mut fss_geometry::WorkBudget::new(4_000_000_000),&parts.replay)? {
                                                                archive::RecoveredUnknownTimeAv::AudioVideo(clip) if clip.video_samples()>0 && clip.audio().frames>0=>(),
                                                                _=>return Err("three-generation source-linked A/V readback refused".into()),
                                                            }
                                                        }
                                                        drop(retired.supervisor);drop(originals);drop(third_custody);drop(fourth_custody);drop(unused);drop(custody);
                                                        peer.join().map_err(|_|"three-generation peer panic")??;
                                                        return Ok(());
                                                    }
                                                    let provisioned=provisioning.into_parts();
                                                    let staged=provisioned.worker.ok_or("future supply worker lost")?.retire().map_err(|_|"future creator unexpectedly running")?;
                                                    assert!(staged.outcome.is_none() && staged.inputs.is_some());
                                                    assert!(!temp.0.join("automatic-third-supplies").exists());
                                                    assert!(provisioned.ready.is_none() && provisioned.failed.is_none() && provisioned.custody.is_none());
                                                    let mut second=provisioned.managed;
                                                    assert_eq!(pin_gate.reads.load(Ordering::Acquire),before,"managed staging read custody");
                                                    if !matches!(second.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,av,source).await,fss_reference::unifi_direct::recording_rollover::ManagedStep::PreflightStarted) {return Err("managed preflight refused".into());}
                                                    timeout(cx.now(),Duration::from_secs(5),async {while !pin_gate.entered.load(Ordering::Acquire) {asupersync::runtime::yield_now().await;}}).await.map_err(|_|"second automatic prior custody did not enter")?;
                                                    control_probe_tx.send(()).map_err(io::Error::other)?;
                                                    if !matches!(second.step(&mut owner,&operations[12],Duration::from_secs(5),task,cx,clock,av,source).await,fss_reference::unifi_direct::recording_rollover::ManagedStep::Rollover(AutomaticStep::Control(supervisor::Step::TimeSyncWritten {..}))) {return Err("second automatic preflight control failed".into());}
                                                    pin_gate.release.store(true,Ordering::Release);
                                                    let mut second_started=false;
                                                    for _ in 0..100 {
                                                        match second.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,av,source).await {
                                                            fss_reference::unifi_direct::recording_rollover::ManagedStep::Rollover(AutomaticStep::RolloverStarted)=>{second_started=true;break;},
                                                            fss_reference::unifi_direct::recording_rollover::ManagedStep::Rollover(AutomaticStep::Control(supervisor::Step::Idle))=>(),
                                                            _=>return Err("second automatic preflight stopped".into()),
                                                        }
                                                    }
                                                    if !second_started {return Err("second automatic worker did not start".into());}
                                                    if !second.join().await {return Err("second automatic worker did not join".into());}
                                                    match second.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,av,source).await {
                                                        fss_reference::unifi_direct::recording_rollover::ManagedStep::Resumed(receipt)=>assert_eq!(receipt.outcome,fss_publication::RootLedgerOutcome::AlreadyLedgered),
                                                        _=>return Err("managed transition did not resume".into()),
                                                    }
                                                    match second.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,av,source).await {
                                                        fss_reference::unifi_direct::recording_rollover::ManagedStep::Recording(fss_reference::unifi_direct::recording_session::AudioAllowanceStep::Renewed {before,after,budget})=>{assert_eq!(after-before,128);assert_eq!(budget,0);},
                                                        _=>return Err("automatic audio renewal did not precede media".into()),
                                                    }
                                                    let (managed_owner,policy,unused_supplies)=second.into_parts();
                                                    assert_eq!(policy.remaining_budget(),0);
                                                    assert!(unused_supplies.is_none());
                                                    let mut second_session=match managed_owner {Some(fss_reference::unifi_direct::recording_rollover::ManagedOwners::Session(session))=>*session,_=>return Err("managed session owner lost".into())};
                                                    let mut exhausted=fss_reference::unifi_direct::recording_session::AudioAllowancePolicy::new(1_000,128,0).ok_or("empty audio policy refused")?;
                                                    control_probe_tx.send(()).map_err(io::Error::other)?;
                                                    if !matches!(second_session.step_with_audio_allowance(&mut exhausted,&mut owner,&operations[13],Duration::from_secs(5),task,cx,clock,av,source).await,fss_reference::unifi_direct::recording_session::AudioAllowanceStep::Exhausted {budget:0,control:supervisor::Step::TimeSyncWritten {..},..}) {return Err("audio policy exhaustion lost control traffic".into());}
                                                    if !matches!(second_session.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,av,source).await,fss_reference::unifi_direct::recording_session::Step::Recording(fss_reference::unifi_direct::source_coordinator::Step::Session(unknown::SessionEvent::Advance(Advance::ArchiveStarted)))) {return Err("second automatic pending segment did not start".into());}
                                                    let (source_coordinator,phase)=second_session.into_parts();
                                                    let mut second_guard=match phase {fss_reference::unifi_direct::recording_session::Phase::Recording(guard)=>*guard,_=>return Err("second automatic session phase lost".into())};
                                                    assert!(matches!(second_guard.remaining_audio_frames(),Ok(None)),"active archive must keep mux ownership");
                                                    let source=source_coordinator.into_worker().retire().map_err(|_|"second automatic source retirement refused")?;
                                                    assert!(source.pending.is_none());
                                                    let mut last_published=false;
                                                    for _ in 0..100 {
                                                        match second_guard.advance(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,"fixture:archive",&BudgetVector::ZERO).await {
                                                            Advance::Archive(Drive::Archive(done))|Advance::Archive(Drive::Control {step:supervisor::Step::Idle|supervisor::Step::TimeSyncWritten {..},completion:Some(done)})=>{
                                                                if done.runtime.is_err() || !matches!(done.outcome,av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(_))) {return Err("second automatic pending publication failed".into());}
                                                                last_published=true;break;
                                                            },
                                                            Advance::Archive(Drive::Control {step:supervisor::Step::Idle|supervisor::Step::TimeSyncWritten {..},completion:None})=>(),
                                                            _=>return Err("second automatic session stopped".into()),
                                                        }
                                                    }
                                                    if !last_published {return Err("second automatic publication timed out".into());}
                                                    let retired=second_guard.retire().map_err(|_|"second automatic guard retirement refused")?;
                                                    assert_eq!(retired.worker.parts.deployment.publisher().visible_roots().count(),5);
                                                    assert_eq!(retired.worker.rollover_custody.as_ref().map(|c|c.transition_count()),Some(2));
                                                    assert!(retired.worker.parts.sink.retire().pending.is_none());
                                                    drop(retired.supervisor);drop(originals);
                                                    peer.join().map_err(|_|"second automatic peer panic")??;
                                                    return Ok(());
                                                }
                                                let source=coordinator.take().ok_or("automatic coordinator lost")?.into_worker().retire().map_err(|_|"automatic source retirement refused")?;
                                                assert!(source.pending.is_none());
                                                let retired=guard.retire().map_err(|_|"automatic guard retirement refused")?;
                                                assert_eq!(retired.worker.parts.deployment.publisher().visible_roots().count(),3);
                                                assert!(retired.worker.parts.sink.retire().pending.is_none());
                                                drop(retired.supervisor);drop(originals);
                                                peer.join().map_err(|_|"automatic rollover peer panic")??;
                                                return Ok(());
                                            }
                                            let mut preflight=fss_reference::unifi_direct::recording_rollover::RecordingRolloverPreflight::prepare(session,supplies).map_err(|_|"session preflight preparation refused")?;
                                            assert!(matches!(preflight.start(task,cx,other_clock,"fixture:archive",&BudgetVector::ZERO),Err(fss_reference::unifi_direct::av_rollover_worker::StartError::Context)));
                                            let (session,supplies)=preflight.into_unstarted().map_err(|_|"unstarted session owners were lost")?;
                                            let mut preflight=fss_reference::unifi_direct::recording_rollover::RecordingRolloverPreflight::prepare(session,supplies).map_err(|_|"recovered session supplies were refused")?;
                                            preflight.start(task,cx,clock,"fixture:archive",&BudgetVector::ZERO).map_err(|e|format!("session preflight start refused: {e:?}"))?;
                                            if !preflight.join().await {return Err("session preflight completion missing".into());}
                                            let mut background=match preflight.finish().map_err(|_|"session preflight did not retire")? {
                                                fss_reference::unifi_direct::recording_rollover::PreflightFinished::Ready(background)=>background,
                                                _=>return Err("session preflight unresolved".into()),
                                            };
                                            background.start(task,cx,clock,"fixture:archive",&BudgetVector::ZERO).map_err(|e|format!("background start refused: {e:?}"))?;
                                            assert!(matches!(background.start(task,cx,clock,"fixture:archive",&BudgetVector::ZERO),Err(fss_reference::unifi_direct::av_rollover_worker::StartError::Running)));
                                            timeout(cx.now(),Duration::from_secs(5),async {while !read.entered.load(Ordering::Acquire) {asupersync::runtime::yield_now().await;}}).await.map_err(|_|"background replay did not enter")?;
                                            control_probe_tx.send(()).map_err(io::Error::other)?;
                                            if !matches!(background.drive(&mut owner,&operations[10],Duration::from_secs(5)).await,unknown::BackgroundDrive::Control {step:supervisor::Step::TimeSyncWritten {..},completed:false}) {return Err("background control failed".into());}
                                            if late_audio_change==17 {
                                                read.release.store(true,Ordering::Release);
                                                if !background.join().await {return Err("panicked background completion missing".into());}
                                                let unresolved=match background.finish().map_err(|_|"panicked background did not retire")? {
                                                    fss_reference::unifi_direct::recording_rollover::Finished::Unresolved {coordinator,rollover}=>{let source=coordinator.into_worker().retire().map_err(|_|"panic source retirement refused")?;assert!(source.pending.is_none());rollover},
                                                    fss_reference::unifi_direct::recording_rollover::Finished::Resumed {..}=>return Err("panicked transition resumed automatically".into()),
                                                };
                                                let retired=unresolved.retire();
                                                assert!(retired.fenced && retired.resources.has_pending());
                                                assert_eq!(retired.rollover_need,Some(need));
                                                assert!(matches!(retired.completion.outcome,fss_reference::unifi_direct::av_rollover_worker::Outcome::Panicked));
                                                drop(retired);
                                                drop(originals);
                                                peer.join().map_err(|_|"panicked rollover peer panic")??;
                                                return Ok(());
                                            }
                                            if late_audio_change==16 {
                                                background.abort();
                                                timeout(cx.now(),Duration::from_secs(5),async {while !background.cancellation_observed() {asupersync::runtime::yield_now().await;}}).await.map_err(|_|"background cancellation was not observed")?;
                                                read.release.store(true,Ordering::Release);
                                                if !background.join().await {return Err("cancelled background completion missing".into());}
                                                let unresolved=match background.finish().map_err(|_|"cancelled background did not retire")? {
                                                    fss_reference::unifi_direct::recording_rollover::Finished::Unresolved {coordinator,rollover}=>{let source=coordinator.into_worker().retire().map_err(|_|"cancel source retirement refused")?;assert!(source.pending.is_none());rollover},
                                                    fss_reference::unifi_direct::recording_rollover::Finished::Resumed {..}=>return Err("cancelled transition resumed automatically".into()),
                                                };
                                                let retired=unresolved.retire();
                                                assert!(retired.resources.has_pending());
                                                assert_eq!(retired.rollover_need,Some(need));
                                                assert!(matches!(retired.completion.outcome,fss_reference::unifi_direct::av_rollover_worker::Outcome::ReplayRefused {..}|fss_reference::unifi_direct::av_rollover_worker::Outcome::Replayed {..}));
                                                drop(retired);
                                                drop(originals);
                                                peer.join().map_err(|_|"cancelled rollover peer panic")??;
                                                return Ok(());
                                            }
                                            pin_gate.armed.store(true,Ordering::Release);
                                            read.release.store(true,Ordering::Release);
                                            timeout(cx.now(),Duration::from_secs(5),async {while !pin_gate.entered.load(Ordering::Acquire) {asupersync::runtime::yield_now().await;}}).await.map_err(|_|"attachment custody check did not enter")?;
                                            control_probe_tx.send(()).map_err(io::Error::other)?;
                                            if !matches!(background.drive(&mut owner,&operations[11],Duration::from_secs(5)).await,unknown::BackgroundDrive::Control {step:supervisor::Step::TimeSyncWritten {..},completed:false}) {return Err("attachment control failed".into());}
                                            pin_gate.release.store(true,Ordering::Release);
                                            if !background.join().await {return Err("background completion missing".into());}
                                            if late_audio_change==19 {
                                                let (coordinator,unresolved)=match background.finish().map_err(|_|"refused attachment did not retire")? {
                                                    fss_reference::unifi_direct::recording_rollover::Finished::Unresolved {coordinator,rollover}=>(coordinator,rollover),
                                                    fss_reference::unifi_direct::recording_rollover::Finished::Resumed {..}=>return Err("refused attachment resumed".into()),
                                                };
                                                let source=coordinator.into_worker().retire().map_err(|_|"refused attachment source retirement failed")?;
                                                assert!(source.pending.is_none());
                                                let retired=unresolved.retire();
                                                assert!(!retired.fenced && retired.resources.has_pending());
                                                assert_eq!(retired.rollover_need,Some(need));
                                                assert!(matches!(retired.completion.outcome,fss_reference::unifi_direct::av_rollover_worker::Outcome::AttachRefused {..}));
                                                drop(retired);
                                                drop(originals);
                                                peer.join().map_err(|_|"refused attachment peer panic")??;
                                                return Ok(());
                                            }
                                            if late_audio_change==18 {
                                                let (coordinator,unresolved)=match background.finish().map_err(|_|"cancelled attachment did not retire")? {
                                                    fss_reference::unifi_direct::recording_rollover::Finished::Unresolved {coordinator,rollover}=>(coordinator,rollover),
                                                    fss_reference::unifi_direct::recording_rollover::Finished::Resumed {..}=>return Err("cancelled attachment resumed".into()),
                                                };
                                                let source=coordinator.into_worker().retire().map_err(|_|"attachment source retirement refused")?;
                                                assert!(source.pending.is_none());
                                                let retired=unresolved.retire();
                                                assert!(!retired.fenced && retired.resources.has_pending());
                                                assert_eq!(retired.rollover_need,Some(need));
                                                assert!(matches!(retired.completion.outcome,fss_reference::unifi_direct::av_rollover_worker::Outcome::Prepared {..}));
                                                drop(retired);
                                                drop(originals);
                                                peer.join().map_err(|_|"cancelled attachment peer panic")??;
                                                return Ok(());
                                            }
                                            let reads_before_finish=pin_gate.reads.load(Ordering::Acquire);
                                            let mut session=match background.finish().map_err(|_|"background did not retire")? {
                                                fss_reference::unifi_direct::recording_rollover::Finished::Resumed {session,receipt}=>{assert_eq!(receipt.outcome,fss_publication::RootLedgerOutcome::AlreadyLedgered);session},
                                                fss_reference::unifi_direct::recording_rollover::Finished::Unresolved {..}=>return Err("background transition unresolved".into()),
                                            };
                                            assert_eq!(pin_gate.reads.load(Ordering::Acquire),reads_before_finish,"final attachment reread custody on the session task");
                                            if matches!(late_audio_change,20|21|22|23|24|29|30|31|32|33) {
                                                let (coordinator,phase)=session.into_parts();
                                                let rolled_guard=match phase {fss_reference::unifi_direct::recording_session::Phase::Recording(guard)=>guard,_=>return Err("first rollover lost session".into())};
                                                pin_gate.entered.store(false,Ordering::Release);
                                                pin_gate.release.store(false,Ordering::Release);
                                                pin_gate.fail_after_release.store(matches!(late_audio_change,22|24),Ordering::Release);
                                                pin_gate.panic_after_release.store(late_audio_change==23,Ordering::Release);
                                                let before=pin_gate.reads.load(Ordering::Acquire);
                                                let mut deferred=(*rolled_guard).defer_rollover_pause().map_err(|_|"deferred pause refused")?;
                                                assert_eq!(pin_gate.reads.load(Ordering::Acquire),before,"deferred pause read custody on session task");
                                                assert!(matches!(deferred.start(task,cx,other_clock,"fixture:archive",&BudgetVector::ZERO),Err(fss_reference::unifi_direct::av_rollover_worker::StartError::Context)));
                                                let restored=deferred.into_unstarted().map_err(|_|"unstarted deferred pause lost owner")?;
                                                let mut deferred=restored.defer_rollover_pause().map_err(|_|"deferred retry refused")?;
                                                deferred.start(task,cx,clock,"fixture:archive",&BudgetVector::ZERO).map_err(|e|format!("deferred start refused: {e:?}"))?;
                                                timeout(cx.now(),Duration::from_secs(5),async {while !pin_gate.entered.load(Ordering::Acquire) {asupersync::runtime::yield_now().await;}}).await.map_err(|_|"prior custody check did not enter")?;
                                                control_probe_tx.send(()).map_err(io::Error::other)?;
                                                if !matches!(deferred.drive(&mut owner,&operations[12],Duration::from_secs(5)).await,unknown::BackgroundDrive::Control {step:supervisor::Step::TimeSyncWritten {..},completed:false}) {return Err("deferred pause control failed".into());}
                                                if matches!(late_audio_change,21|24) {
                                                    deferred.abort();
                                                    timeout(cx.now(),Duration::from_secs(5),async {while !deferred.cancellation_observed() {asupersync::runtime::yield_now().await;}}).await.map_err(|_|"deferred cancellation not observed")?;
                                                }
                                                pin_gate.release.store(true,Ordering::Release);
                                                if !deferred.join().await {return Err("deferred pause completion missing".into());}
                                                if matches!(late_audio_change,21|22|23|24) {
                                                    let unresolved=match deferred.finish().map_err(|_|"deferred failure did not drain")? {unknown::DeferredPauseFinish::Unresolved(unresolved)=>unresolved,unknown::DeferredPauseFinish::Ready {..}=>return Err("failed preflight became ready".into())};
                                                    if late_audio_change==21 {
                                                        if !matches!(&unresolved.reason,unknown::DeferredPauseReason::Cancelled) {return Err("cancelled preflight misclassified".into());}
                                                        let restored=unresolved.restore().map_err(|_|"cancelled preflight lost guard")?;
                                                        session=fss_reference::unifi_direct::recording_session::Session::from_recording(coordinator,Box::new(restored));
                                                    } else {
                                                        let unresolved=unresolved.restore().err().ok_or("failed preflight restored without reconciliation")?;
                                                        let retired=unresolved.retire();
                                                        if matches!(late_audio_change,22|24) && !matches!(&retired.reason,unknown::DeferredPauseReason::Refused(_)) {return Err("custody refusal misclassified".into());}
                                                        if late_audio_change==23 && (!retired.fenced || !matches!(&retired.reason,unknown::DeferredPauseReason::Panicked)) {return Err("custody panic misclassified".into());}
                                                        assert!(retired.original.parts.sink.has_pending());
                                                        assert!(retired.original.rollover_custody.is_some());
                                                        let source=coordinator.into_worker().retire().map_err(|_|"deferred failed source retirement refused")?;
                                                        assert!(source.pending.is_none());
                                                        drop(retired);drop(originals);
                                                        peer.join().map_err(|_|"deferred failed peer panic")??;
                                                        return Ok(());
                                                    }
                                                } else {
                                                let (paused,previous)=match deferred.finish().map_err(|_|"deferred pause did not drain")? {unknown::DeferredPauseFinish::Ready {paused,previous}=>(paused,previous),unknown::DeferredPauseFinish::Unresolved(_)=>return Err("deferred pause unresolved".into())};
                                                assert!(paused.worker_has_pending());
                                                let restored=paused.restore(previous).map_err(|_|"deferred pause restore refused")?;
                                                session=fss_reference::unifi_direct::recording_session::Session::from_recording(coordinator,Box::new(restored));
                                                }
                                            }
                                            let av=fss_reference::unifi_direct::source_coordinator::ArchiveAdmission {resource:"fixture:archive",cost:&BudgetVector::ZERO};
                                            let source=fss_reference::unifi_direct::source_coordinator::ArchiveAdmission {resource:"fixture:source",cost:&BudgetVector::ZERO};
                                            assert!(matches!(session.step(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,av,source).await,fss_reference::unifi_direct::recording_session::Step::Recording(fss_reference::unifi_direct::source_coordinator::Step::Session(unknown::SessionEvent::Advance(Advance::ArchiveStarted)))));
                                            let (coordinator,phase)=session.into_parts();
                                            guard=match phase {fss_reference::unifi_direct::recording_session::Phase::Recording(guard)=>*guard,_=>return Err("rollover did not restore recording phase".into())};
                                            let source=coordinator.into_worker().retire().map_err(|_|"resumed source retirement refused")?;
                                            assert!(source.pending.is_none());
                                            let mut completed=false;
                                            for _ in 0..100 {
                                                match guard.advance(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,"fixture:archive",&BudgetVector::ZERO).await {
                                                    Advance::Archive(Drive::Archive(done)) | Advance::Archive(Drive::Control {step:supervisor::Step::Idle|supervisor::Step::TimeSyncWritten {..},completion:Some(done)})=>{
                                                        if done.runtime.is_err() || !matches!(done.outcome,av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(_))) {return Err("rollover resumed publication failed".into());}
                                                        completed=true;break;
                                                    },
                                                    Advance::Archive(Drive::Control {step:supervisor::Step::Idle|supervisor::Step::TimeSyncWritten {..},completion:None})=>(),
                                                    _=>return Err("rollover resumed scheduler stopped".into()),
                                                }
                                            }
                                            if !completed {return Err("rollover resumed publication timed out".into());}
                                            let retired=guard.retire().map_err(|_|"rollover guard did not retire")?;
                                            assert_eq!(retired.worker.parts.deployment.publisher().visible_roots().count(),3);
                                            assert!(retired.worker.rollover_custody.is_some());
                                            assert!(retired.worker.parts.sink.retire().pending.is_none());
                                            assert!(!retired.retry_required && retired.rollover_need.is_none());
                                            drop(originals);
                                            drop(retired.supervisor);
                                            peer.join().map_err(|_|"rollover peer panic")??;
                                            return Ok(());
                                        }
                                        if late_audio_change==3 {
                                            use unknown::{Advance, Drive};
                                            let cost=BudgetVector::ZERO;
                                            macro_rules! scheduled_completion {
                                                () => {{
                                                    let mut found=None;
                                                    for _ in 0..100 {
                                                        match guard.advance(&mut owner,&operations[6],Duration::from_millis(50),task,cx,clock,"fixture:archive",&cost).await {
                                                            Advance::Archive(Drive::Archive(completion)) | Advance::Archive(Drive::Control {completion:Some(completion),..})=>{found=Some(completion);break;},
                                                            Advance::Archive(Drive::Control {completion:None,..})=>(),
                                                            _=>return Err("scheduler did not drive archive completion".into()),
                                                        }
                                                    }
                                                    found.ok_or("scheduler completion deadline")?
                                                }};
                                            }
                                            assert!(matches!(guard.advance(&mut owner,&operations[6],Duration::from_secs(1),task,cx,other_clock,"fixture:archive",&cost).await,Advance::Context));
                                            assert!(matches!(guard.advance(&mut owner,&operations[6],Duration::from_secs(1),task,cx,clock,"fixture:archive",&cost).await,Advance::Source(unknown::Step::SourceQueued)));
                                            assert!(matches!(guard.advance(&mut owner,&operations[6],Duration::from_secs(1),task,cx,clock,"fixture:archive",&cost).await,Advance::ArchiveStarted));
                                            timeout(cx.now(),Duration::from_secs(5),async {while !access.entered.load(Ordering::Acquire) {asupersync::runtime::yield_now().await;}}).await.map_err(|_|"scheduler worker did not enter")?;
                                            control_probe_tx.send(()).map_err(io::Error::other)?;
                                            assert!(matches!(guard.advance(&mut owner,&operations[8],Duration::from_secs(5),task,cx,clock,"fixture:archive",&cost).await,Advance::Archive(Drive::Control {step:supervisor::Step::TimeSyncWritten { .. },completion:None})));
                                            access.block.store(false,Ordering::Release);
                                            let denied=scheduled_completion!();
                                            assert!(matches!(denied.outcome,av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Refused {reason:av_worker::FailureReason::Denied,..})));
                                            assert!(matches!(guard.advance(&mut owner,&operations[6],Duration::from_secs(1),task,cx,clock,"fixture:archive",&cost).await,Advance::RetryRequired));
                                            assert!(guard.authorize_retry());
                                            assert!(!guard.authorize_retry());
                                            access.allow.store(true,Ordering::Release);
                                            assert!(matches!(guard.advance(&mut owner,&operations[6],Duration::from_secs(1),task,cx,clock,"fixture:archive",&cost).await,Advance::ArchiveStarted));
                                            let first=scheduled_completion!();
                                            assert!(first.runtime.is_ok());
                                            assert!(matches!(first.outcome,av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(_))));
                                            let mut queued=false;
                                            for _ in 0..if camera_replay {8192} else {128} {
                                                match guard.advance(&mut owner,&operations[6],Duration::from_secs(5),task,cx,clock,"fixture:archive",&cost).await {
                                                    Advance::Source(unknown::Step::SourceQueued)=>{queued=true;break;},
                                                    Advance::Source(unknown::Step::Supervisor(supervisor::Step::AudioPending))=>{
                                                        let event=guard.take_audio_event(&owner).ok_or("scheduler audio withheld")?;
                                                        if matches!(event,pipeline::AudioEvent::Fenced(_)|pipeline::AudioEvent::Observed(fss_packet::extended_flv::aac_track::Observation::Configuration {..})) {return Err("scheduler audio requires reconciliation".into());}
                                                    },
                                                    Advance::Source(unknown::Step::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {..}|recording::Push::Buffered)|pipeline::Step::Progress {..})|supervisor::Step::TimeSyncWritten { .. }))=>(),
                                                    _=>return Err("scheduler failed to advance source".into()),
                                                }
                                            }
                                            if !queued {return Err("scheduler second source missing".into());}
                                            assert!(matches!(guard.advance(&mut owner,&operations[6],Duration::from_secs(1),task,cx,clock,"fixture:archive",&cost).await,Advance::ArchiveStarted));
                                            let second=scheduled_completion!();
                                            assert!(second.runtime.is_ok());
                                            assert!(matches!(second.outcome,av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(_))));
                                            guard=*exercise_guard_rollover(Box::new(guard),&temp.0,access.as_ref(),None)?;
                                            assert_eq!(guard.archive_state(),av_worker_guard::ArchiveState::Idle);
                                            let retired=guard.retire().map_err(|_|"scheduler retirement refused")?;
                                            assert!(!retired.retry_required && !retired.audio_fenced);
                                            assert!(retired.worker.rollover_custody.is_some());
                                            assert!(retired.worker.parts.sink.retire().pending.is_none());
                                            peer.join().map_err(|_|"scheduler peer panic")??;
                                            if camera_replay {println!("unknown_scheduler_camera_replay=passed published_segments=2 capture_bounds=unknown controller=simulated");}
                                            return Ok(());
                                        }
                                        if late_audio_change!=9 {
                                            assert!(matches!(guard.step(&mut owner,&operations[6],Duration::from_secs(5)).await,unknown::Step::SourceQueued));
                                            assert_eq!(guard.archive_state(),av_worker_guard::ArchiveState::Pending);
                                            assert!(matches!(guard.start_archive(task,cx,other_clock,"fixture:archive",&BudgetVector::ZERO),Err(unknown::StartError::Worker(av_worker::StartError::Context))));
                                            guard.start_archive(task,cx,clock,"fixture:archive",&BudgetVector::ZERO).map_err(|e|format!("unknown archive start: {e:?}"))?;
                                        } else {
                                            assert_eq!(guard.archive_state(),av_worker_guard::ArchiveState::Running);
                                        }
                                        timeout(cx.now(),Duration::from_secs(5),async {while !access.entered.load(Ordering::Acquire) {asupersync::runtime::yield_now().await;}}).await.map_err(|_|"unknown worker did not enter")?;
                                        guard=*refuse_guard_pause(Box::new(guard))?;
                                        assert_eq!(guard.archive_state(),av_worker_guard::ArchiveState::Running);
                                        assert!(matches!(guard.step(&mut owner,&operations[6],Duration::from_secs(5)).await,unknown::Step::ArchivePending));
                                        control_probe_tx.send(()).map_err(io::Error::other)?;
                                        assert!(matches!(guard.drive_archive(&mut owner,&operations[8],Duration::from_secs(5)).await,unknown::Drive::Control {step:supervisor::Step::TimeSyncWritten { .. },completion:None}));
                                        if cancel_archive {
                                            guard.abort_archive();
                                            timeout(cx.now(),Duration::from_secs(5),async {while !guard.cancellation_observed() {asupersync::runtime::yield_now().await;}}).await.map_err(|_|"unknown cancellation not observed")?;
                                        }
                                        let pending=poll_fn(|context| {let mut wait=std::pin::pin!(guard.join_archive()); Poll::Ready(wait.as_mut().poll(context).is_pending())}).await;
                                        assert!(pending,"unknown archive joined before retention released");
                                        guard=match guard.retire() {Err(guard)=>guard, Ok(_)=>return Err("unknown guard retired while running".into())};
                                        access.block.store(false,Ordering::Release);
                                        let completion=timeout(cx.now(),Duration::from_secs(5),guard.join_archive()).await?.ok_or("unknown completion missing")?;
                                        assert!(completion.runtime.is_ok());
                                        let reason=if cancel_archive {av_worker::FailureReason::CancelledOrDenied} else {av_worker::FailureReason::Denied};
                                        assert!(matches!(completion.outcome,av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Refused {reason:actual,..}) if actual==reason));
                                        assert_eq!(guard.archive_state(),av_worker_guard::ArchiveState::Pending);
                                        access.allow.store(true,Ordering::Release);
                                        guard.start_archive(task,cx,clock,"fixture:archive",&BudgetVector::ZERO).map_err(|e|format!("unknown archive retry: {e:?}"))?;
                                        let completion=timeout(cx.now(),Duration::from_secs(5),guard.join_archive()).await?.ok_or("unknown retry missing")?;
                                        assert!(completion.runtime.is_ok());
                                        assert!(matches!(completion.outcome,av_worker::UnknownTimeOutcome::Publication(av_worker::UnknownTimePublication::Published(_))));
                                        assert_eq!(guard.archive_state(),av_worker_guard::ArchiveState::Idle);
                                        let mut next=false;
                                        let mut fenced_audio=false;
                                        let mut audio_withheld=false;
                                        for _ in 0..if camera_replay {8192} else {128} {
                                            match guard.step(&mut owner,&operations[6],Duration::from_secs(5)).await {
                                                unknown::Step::SourceQueued=>{next=true;break;},
                                                unknown::Step::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {record,..})))=>originals.extend_from_slice(record.bytes()),
                                                unknown::Step::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Buffered)|pipeline::Step::Progress {..})) | unknown::Step::Supervisor(supervisor::Step::TimeSyncWritten { .. })=>(),
                                                unknown::Step::Supervisor(supervisor::Step::AudioPending)=>{
                                                    if late_audio_change==2 {
                                                        policy.peer.set(false);
                                                        assert!(guard.take_audio_event(&owner).is_none());
                                                        assert!(matches!(guard.queue_held(),Err(unknown::QueueError::AudioPending)));
                                                        assert!(matches!(guard.start_archive(task,cx,clock,"fixture:archive",&BudgetVector::ZERO),Err(unknown::StartError::Queue(unknown::QueueError::AudioPending))));
                                                        policy.peer.set(true);
                                                        assert!(guard.take_audio_event(&owner).is_none(),"admission revocation must remain fenced");
                                                        audio_withheld=true;
                                                        break;
                                                    }
                                                    let event=guard.take_audio_event(&owner).ok_or("missing audio observation")?;
                                                    if matches!(event,pipeline::AudioEvent::Observed(fss_packet::extended_flv::aac_track::Observation::Configuration {..})) {fenced_audio=true;break;}
                                                },
                                                _=>return Err("unknown guard did not resume".into()),
                                            }
                                        }
                                        if late_audio_change==1 {
                                            assert!(fenced_audio && !next);
                                            assert!(matches!(guard.step(&mut owner,&operations[6],Duration::from_secs(5)).await,unknown::Step::AudioFenced));
                                            assert!(matches!(guard.queue_held(),Err(unknown::QueueError::AudioFenced)));
                                            assert!(matches!(guard.start_archive(task,cx,clock,"fixture:archive",&BudgetVector::ZERO),Err(unknown::StartError::Queue(unknown::QueueError::AudioFenced))));
                                        } else if late_audio_change==2 {
                                            assert!(audio_withheld && !next);
                                        } else if !next {return Err("unknown guard did not queue next segment".into());}
                                        let retired=guard.retire().map_err(|_|"unknown guard failed to retire")?;
                                        assert_eq!(retired.audio_fenced,late_audio_change==1);
                                        assert_eq!(retired.supervisor.media.pending_audio.is_some(),late_audio_change==2);
                                        assert!(retired.held.is_none());
                                        let pending=retired.worker.parts.sink.retire().pending;
                                        if matches!(late_audio_change,1|2) {assert!(pending.is_none());} else {
                                            let segment=pending.ok_or("unknown guard lost next source")?;
                                            for source in segment.source() { originals.extend_from_slice(source.bytes()); }
                                        }
                                        for source in retired.supervisor.media.recorder.pending { originals.extend_from_slice(source.bytes()); }
                                        originals.extend_from_slice(retired.supervisor.media.ingress.framing.bytes());
                                        if let Some(buffered)=retired.supervisor.media.ingress.buffered {originals.extend_from_slice(&buffered.source.bytes()[buffered.appended..]);}
                                        if let Some(pending)=retired.supervisor.media.ingress.source.pending {originals.extend_from_slice(pending.bytes());}
                                        assert_eq!(originals,expected[..originals.len()]);
                                        peer.join().map_err(|_|"unknown guard peer panic")??;
                                        if camera_replay {println!("unknown_guard_camera_replay=passed source_prefix_bytes={} capture_bounds=unknown controller=simulated", originals.len());}
                                        return Ok(());
                                    }
                                    let store=FileEffectJournal::create(temp.0.join("worker-guard-intent"),EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
                                    let journal=archive::journal::Journal::create(Box::new(store),ContentDigest::sha256(b"worker guard scope"),&replay)?;
                                    let store=FileEffectJournal::create(temp.0.join("worker-guard-anchor"),EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
                                    let keeper=archive::journal::AnchorKeeper::create(Box::new(store),&journal,&replay)?;
                                    let access=Arc::new(Retention {block:AtomicBool::new(true), entered:AtomicBool::new(false), allow:AtomicBool::new(false)});
                                    let _unblock=Unblock(Arc::clone(&access));
                                    let authority:Arc<dyn archive::RetainAuthority + Send + Sync>=access.clone();
                                    let resources=av_worker_guard::BootstrapResources {deployment,journal,keeper,replay,authority,limits:archive::Limits::default(),work_limit:0};
                                    let refusal=match av_worker_guard::Guard::from_bootstrap(handoff,resources) {
                                        Err(refusal)=>refusal, Ok(_)=>return Err("invalid worker limit accepted".into()),
                                    };
                                    assert_eq!(ContentDigest::sha256(refusal.first_segment.fragment().bytes()),first_digest);
                                    let (handoff,mut resources)=refusal.into_retry();
                                    assert_eq!(ContentDigest::sha256(handoff.bootstrap.first_segment.fragment().bytes()),first_digest);
                                    resources.work_limit=4_000_000_000;
                                    let started=av_worker_guard::Guard::from_bootstrap(handoff,resources).map_err(|_|"worker limits invalid")?;
                                    assert_eq!(started.origin.audio_ticks,1024);
                                    let mut guard=started.guard;
                                    assert!(matches!(guard.step(&mut owner,&operations[6],Duration::from_secs(5)).await,av_sink::GuardStep::CaptureRequired));
                                    let segment=guard.awaiting_capture().ok_or("missing source")?;
                                    let source_digest=ContentDigest::sha256(segment.fragment().bytes());
                                    for source in segment.source() { originals.extend_from_slice(source.bytes()); }
                                    control_probe_tx.send(()).map_err(io::Error::other)?;
                                    assert!(matches!(guard.service_control(&mut owner,&operations[7],Duration::from_secs(5)).await,supervisor::Step::TimeSyncWritten { .. }));
                                    assert_eq!(ContentDigest::sha256(guard.awaiting_capture().ok_or("control consumed source")?.fragment().bytes()),source_digest);
                                    guard.supply_capture(fss_core::CaptureInterval::new(TimestampNs(1),TimestampNs(2))?).map_err(|_|"capture binding refused")?;
                                    assert_eq!(guard.archive_state(),av_worker_guard::ArchiveState::Pending);
                                    assert!(matches!(guard.drive_archive(&mut owner,&operations[6],Duration::from_millis(100)).await,av_worker_guard::Drive::NotRunning));
                                    assert!(matches!(guard.start_archive(task,cx,other_clock,"fixture:archive",&BudgetVector::ZERO),Err(av_worker_guard::StartError::Worker(av_worker::StartError::Context))));
                                    assert_eq!(guard.archive_state(),av_worker_guard::ArchiveState::Pending);
                                    guard.start_archive(task,cx,clock,"fixture:archive",&BudgetVector::ZERO).map_err(|e|format!("archive start refused: {e:?}"))?;
                                    timeout(cx.now(),Duration::from_secs(5),async {
                                        while !access.entered.load(Ordering::Acquire) { asupersync::runtime::yield_now().await; }
                                    }).await.map_err(|_|"archive worker did not enter")?;
                                    assert_eq!(guard.archive_state(),av_worker_guard::ArchiveState::Running);
                                    assert!(matches!(guard.step(&mut owner,&operations[6],Duration::from_secs(5)).await,av_sink::GuardStep::ArchivePending));
                                    control_probe_tx.send(()).map_err(io::Error::other)?;
                                    assert!(matches!(guard.drive_archive(&mut owner,&operations[8],Duration::from_secs(5)).await,av_worker_guard::Drive::Control {step:supervisor::Step::TimeSyncWritten { .. },completion:None}));
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
                                    let mut fenced_audio=false;
                                    let mut audio_withheld=false;
                                    for _ in 0..128 {
                                        match guard.step(&mut owner,&operations[6],Duration::from_secs(5)).await {
                                            av_sink::GuardStep::CaptureRequired=>{next=true;break;},
                                            av_sink::GuardStep::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {record,..})))=>originals.extend_from_slice(record.bytes()),
                                            av_sink::GuardStep::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Buffered)|pipeline::Step::Progress {..})) | av_sink::GuardStep::Supervisor(supervisor::Step::TimeSyncWritten { .. })=>(),
                                            av_sink::GuardStep::Supervisor(supervisor::Step::AudioPending)=>{
                                                assert!(matches!(guard.supply_capture(fss_core::CaptureInterval::new(TimestampNs(1),TimestampNs(2))?),Err(av_worker_guard::CaptureError::AudioPending)));
                                                assert!(matches!(guard.start_archive(task,cx,clock,"fixture:archive",&BudgetVector::ZERO),Err(av_worker_guard::StartError::AudioPending)));
                                                if late_audio_change==2 {
                                                    policy.peer.set(false);
                                                    assert!(guard.take_audio_event(&owner).is_none());
                                                    policy.peer.set(true);
                                                    assert!(guard.take_audio_event(&owner).is_none());
                                                    audio_withheld=true;
                                                    break;
                                                }
                                                let event=guard.take_audio_event(&owner).ok_or("missing audio observation")?;
                                                if matches!(event,pipeline::AudioEvent::Observed(fss_packet::extended_flv::aac_track::Observation::Configuration {..})) {fenced_audio=true;break;}
                                            },
                                            other=>return Err(format!("async supervisor did not resume: {other:?}").into()),
                                        }
                                    }
                                    if late_audio_change==1 {
                                        assert!(fenced_audio && !next);
                                        assert!(matches!(guard.step(&mut owner,&operations[6],Duration::from_secs(5)).await,av_sink::GuardStep::AudioFenced));
                                        assert!(matches!(guard.supply_capture(fss_core::CaptureInterval::new(TimestampNs(1),TimestampNs(2))?),Err(av_worker_guard::CaptureError::AudioFenced)));
                                        assert!(matches!(guard.start_archive(task,cx,clock,"fixture:archive",&BudgetVector::ZERO),Err(av_worker_guard::StartError::AudioFenced)));
                                    } else if late_audio_change==2 {
                                        assert!(audio_withheld && !next);
                                    } else if !next {return Err("async guard did not resume".into());}
                                    let retired=guard.retire().map_err(|_|"guard failed to retire")?;
                                    assert_eq!(retired.audio_fenced,late_audio_change==1);
                                    assert_eq!(retired.supervisor.media.pending_audio.is_some(),late_audio_change==2);
                                    assert!(retired.worker.parts.sink.retire().pending.is_none());
                                    if late_audio_change==0 {
                                        let segment=retired.awaiting_capture.ok_or("async guard lost next source")?;
                                        for source in segment.source() {originals.extend_from_slice(source.bytes());}
                                    } else { assert!(retired.awaiting_capture.is_none()); }
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
                                        av_sink::GuardStep::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Buffered)|pipeline::Step::Progress {..})) | av_sink::GuardStep::Supervisor(supervisor::Step::TimeSyncWritten { .. }) => (),
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
                                assert!(matches!(recording_guard.service_control(&mut owner,&operations[7],Duration::from_secs(5)).await,supervisor::Step::TimeSyncWritten { .. }));
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
                                assert!(matches!(recording_guard.service_control(&mut owner,&operations[8],Duration::from_secs(5)).await,supervisor::Step::TimeSyncWritten { .. }));
                                assert!(matches!(recording_guard.step(&mut owner,&operations[6],Duration::from_secs(5)).await,av_sink::GuardStep::ArchivePending));
                                let receipt=recording_guard.flush(&mut deployment,&Retention(true),limits,&mut fss_geometry::WorkBudget::new(4_000_000_000),&replay,&mut journal,&mut anchor).map_err(|_|"guard publication failed")?.ok_or("guard receipt missing")?;
                                assert_eq!(receipt.receipt.outcome,fss_publication::RootLedgerOutcome::Committed);
                                let mut next=false;
                                for _ in 0..128 {
                                    match recording_guard.step(&mut owner,&operations[6],Duration::from_secs(5)).await {
                                        av_sink::GuardStep::CaptureRequired=>{next=true;break;},
                                        av_sink::GuardStep::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {record,..})))=>originals.extend_from_slice(record.bytes()),
                                        av_sink::GuardStep::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Buffered)|pipeline::Step::Progress {..})) | av_sink::GuardStep::Supervisor(supervisor::Step::TimeSyncWritten { .. })=>(),
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
                        supervisor::Step::TimeSyncWritten { .. } => later_syncs+=1,
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
            }).await;
            let outcome=if output.is_ok() { TaskOutcome::Indeterminate("fixture changes require reconciliation".into()) } else { TaskOutcome::Failed("conversation fixture failed".into()) };
            TaskCompletion { output, outcome, completed_at:TimestampNs(59_000_000_000) }
        }).await?;
        result.receipt?; result.output
    })?;
    for (index, operation) in operations.iter().enumerate() {
        if index == 4 && !reply_after_media { continue; }
        if index == 5 && !early_reply { continue; }
        if index == 6 && (revoke_stream || revoke_after_start || revoke_audio_pending || stop_mode != 0 || matches!(late_audio_change,12|13)) { continue; }
        if index >= 7 && (!archive_guard || audio_change || (matches!(late_audio_change,10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33) && !(late_audio_change==13 && index==9)) || (matches!(late_audio_change,5|7) && index>=8) || (index>=9 && late_audio_change!=13)) { continue; }
        assert_eq!(
            effects
                .journal()
                .operation(operation)
                .ok_or("missing journal operation")?
                .state,
            fss_core::EffectState::Committed
        );
    }
    if late_audio_change==31 {
        assert_eq!(effects.journal().operation(&operations[17]).ok_or("rollover event effect missing")?.state,fss_core::EffectState::Committed);
    }
    assert!(!authority.finalize_report(&tree)?.is_empty());
    Ok(())
}

#[test]
fn asynchronous_guard_services_control_while_archive_is_blocked() -> Test {
    conversation_scenario_with_worker_guard(false, false, false, false, false, false, 0, false, true, true, false, false)
}

#[test]
fn known_time_guard_fences_later_audio_configuration() -> Test {
    conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,false,None,1)
}

#[test]
fn known_time_guard_retains_withheld_audio_on_revocation() -> Test {
    conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,false,None,2)
}

#[test]
fn unknown_time_guard_services_control_while_archive_is_blocked() -> Test {
    conversation_scenario_with_worker_guard_mode(false, false, false, false, false, false, 0, false, true, true, false, false, true, None, 0)
}

#[test]
fn unknown_time_source_scheduler_keeps_control_live_and_media_held() -> Test {
    conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,8)
}

#[test]
fn unknown_time_source_coordinator_starts_and_drains_source() -> Test {
    conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,9)
}

#[test]
fn coordinated_shutdown_drains_both_archive_workers() -> Test {
    conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,11)
}

#[test]
fn bootstrap_shutdown_drains_running_source_and_preserves_original() -> Test {
    conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,14)
}

#[test]
fn owned_recording_session_archives_bootstrap_and_av() -> Test {
    conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,12)
}

#[test]
fn owned_recording_session_replies_to_event_during_archive() -> Test {
    conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,13)
}

#[test]
fn bootstrap_coordinator_publishes_forwarded_original_source() -> Test {
    conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,10)
}

#[test]
fn unknown_time_guard_cancels_drains_and_retries_source() -> Test {
    conversation_scenario_with_worker_guard_mode(false, false, false, false, false, false, 0, false, true, true, true, false, true, None, 0)
}

#[test]
fn unknown_time_guard_fences_later_audio_configuration() -> Test {
    conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,1)
}

#[test]
fn unknown_time_guard_retains_withheld_audio_on_revocation() -> Test {
    conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,2)
}

#[test]
fn unknown_time_scheduler_starts_two_segments_and_latches_refusal() -> Test {
    conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,3)
}

#[test]
fn unknown_time_background_rollover_resumes_after_capacity() -> Test {
    // The shared conversation fixture already exceeds a normal test-thread
    // stack; this explicitly bounded diagnostic does not qualify that stack.
    let task=std::thread::Builder::new().name("rollover-fixture".into()).stack_size(16*1024*1024).spawn(|| {
        conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,15).map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"rollover fixture thread panicked")?.map_err(Into::into)
}

#[test]
fn unknown_time_background_rollover_cancellation_retains_source() -> Test {
    let task=std::thread::Builder::new().name("rollover-cancel-fixture".into()).stack_size(16*1024*1024).spawn(|| {
        conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,16).map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"rollover cancellation fixture thread panicked")?.map_err(Into::into)
}

#[test]
fn unknown_time_background_rollover_panic_fences_source() -> Test {
    let task=std::thread::Builder::new().name("rollover-panic-fixture".into()).stack_size(16*1024*1024).spawn(|| {
        conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,17).map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"rollover panic fixture thread panicked")?.map_err(Into::into)
}

#[test]
fn unknown_time_background_rollover_cancelled_attachment_retains_owners() -> Test {
    let task=std::thread::Builder::new().name("rollover-attach-cancel-fixture".into()).stack_size(16*1024*1024).spawn(|| {
        conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,18).map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"rollover attachment cancellation fixture thread panicked")?.map_err(Into::into)
}

#[test]
fn unknown_time_background_rollover_custody_refusal_retains_owners() -> Test {
    let task=std::thread::Builder::new().name("rollover-custody-refusal-fixture".into()).stack_size(16*1024*1024).spawn(|| {
        conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,19).map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"rollover custody refusal fixture thread panicked")?.map_err(Into::into)
}

#[test]
fn unknown_time_background_rollover_deferred_second_pause_services_control() -> Test {
    let task=std::thread::Builder::new().name("rollover-deferred-pause-fixture".into()).stack_size(16*1024*1024).spawn(|| {
        conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,20).map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"deferred pause fixture thread panicked")?.map_err(Into::into)
}

#[test]
fn unknown_time_background_rollover_deferred_pause_cancellation_retains_media() -> Test {
    let task=std::thread::Builder::new().name("rollover-deferred-cancel".into()).stack_size(16*1024*1024).spawn(|| {
        conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,21).map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"deferred cancellation fixture thread panicked")?.map_err(Into::into)
}

#[test]
fn unknown_time_background_rollover_deferred_pause_refusal_retains_media() -> Test {
    let task=std::thread::Builder::new().name("rollover-deferred-refusal".into()).stack_size(16*1024*1024).spawn(|| {
        conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,22).map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"deferred refusal fixture thread panicked")?.map_err(Into::into)
}

#[test]
fn unknown_time_background_rollover_deferred_pause_panic_retains_media() -> Test {
    let task=std::thread::Builder::new().name("rollover-deferred-panic".into()).stack_size(16*1024*1024).spawn(|| {
        conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,23).map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"deferred panic fixture thread panicked")?.map_err(Into::into)
}

#[test]
fn unknown_time_background_rollover_deferred_pause_cancelled_error_retains_media() -> Test {
    let task=std::thread::Builder::new().name("rollover-deferred-cancelled-error".into()).stack_size(16*1024*1024).spawn(|| {
        conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,24).map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"deferred cancelled error fixture thread panicked")?.map_err(Into::into)
}

#[test]
fn unknown_time_background_rollover_automatic_session_resumes() -> Test {
    let task=std::thread::Builder::new().name("rollover-automatic-session".into()).stack_size(16*1024*1024).spawn(|| {
        conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,25).map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"automatic rollover fixture thread panicked")?.map_err(Into::into)
}

#[test]
fn unknown_time_background_rollover_automatic_cancellation_retains_media() -> Test {
    let task=std::thread::Builder::new().name("rollover-automatic-cancel".into()).stack_size(16*1024*1024).spawn(|| {
        conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,26).map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"automatic cancellation fixture thread panicked")?.map_err(Into::into)
}

#[test]
fn unknown_time_background_rollover_automatic_custody_refusal_retains_media() -> Test {
    let task=std::thread::Builder::new().name("rollover-automatic-refusal".into()).stack_size(16*1024*1024).spawn(|| {
        conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,27).map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"automatic refusal fixture thread panicked")?.map_err(Into::into)
}

#[test]
fn unknown_time_background_rollover_automatic_start_refusal_requires_retry() -> Test {
    let task=std::thread::Builder::new().name("rollover-automatic-start-refusal".into()).stack_size(16*1024*1024).spawn(|| {
        conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,28).map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"automatic start refusal fixture thread panicked")?.map_err(Into::into)
}

#[test]
fn unknown_time_background_rollover_automatic_two_generations_resume() -> Test {
    let task=std::thread::Builder::new().name("rollover-automatic-two-generations".into()).stack_size(16*1024*1024).spawn(|| {
        conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,29).map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"automatic two-generation fixture thread panicked")?.map_err(Into::into)
}

#[test]
fn unknown_time_background_rollover_automatic_provisioning_cancel_preserves_owners() -> Test {
    let task=std::thread::Builder::new().name("rollover-provision-cancel".into()).stack_size(16*1024*1024).spawn(|| {
        conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,30).map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"provision cancellation fixture thread panicked")?.map_err(Into::into)
}

#[test]
fn unknown_time_background_rollover_automatic_abort_before_creator_start() -> Test {
    let task=std::thread::Builder::new().name("rollover-provision-abort-before-start".into()).stack_size(16*1024*1024).spawn(|| {
        conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,32).map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"pre-start cancellation fixture thread panicked")?.map_err(Into::into)
}

#[test]
fn unknown_time_background_rollover_automatic_abort_after_creator_completion() -> Test {
    let task=std::thread::Builder::new().name("rollover-provision-abort-after-completion".into()).stack_size(16*1024*1024).spawn(|| {
        conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,33).map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"post-completion cancellation fixture thread panicked")?.map_err(Into::into)
}

#[test]
fn unknown_time_background_rollover_automatic_three_generations_resume() -> Test {
    let task=std::thread::Builder::new().name("rollover-three-generations".into()).stack_size(16*1024*1024).spawn(|| {
        conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,31).map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"three-generation fixture thread panicked")?.map_err(Into::into)
}

#[test]
fn unknown_time_session_slice_drives_two_segments() -> Test {
    conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,4)
}

#[test]
fn unknown_time_session_slice_drains_refused_observer() -> Test {
    conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,5)
}

#[test]
fn unknown_time_session_yields_and_resumes_running_archive() -> Test {
    conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,6)
}

#[test]
fn unknown_time_session_inbox_drives_two_segments() -> Test {
    conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,None,7)
}

#[test]
#[ignore = "requires private bounded camera-derived replay input on stdin"]
fn unknown_guard_camera_replay_from_stdin() -> Test {
    let mut wire=Vec::new();
    std::io::stdin().lock().take((8*1024*1024+1) as u64).read_to_end(&mut wire)?;
    if wire.is_empty() || wire.len()>8*1024*1024 {return Err("bounded replay input refused".into());}
    conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,Some(wire),0)
}

#[test]
#[ignore = "requires private bounded camera-derived replay input on stdin"]
fn unknown_scheduler_camera_replay_from_stdin() -> Test {
    let mut wire=Vec::new();
    std::io::stdin().lock().take((8*1024*1024+1) as u64).read_to_end(&mut wire)?;
    if wire.is_empty() || wire.len()>8*1024*1024 {return Err("bounded replay input refused".into());}
    conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,Some(wire),3)
}

#[test]
#[ignore = "requires private bounded camera-derived replay input on stdin"]
fn unknown_session_camera_replay_from_stdin() -> Test {
    let mut wire=Vec::new();
    std::io::stdin().lock().take((8*1024*1024+1) as u64).read_to_end(&mut wire)?;
    if wire.is_empty() || wire.len()>8*1024*1024 {return Err("bounded replay input refused".into());}
    conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,Some(wire),4)
}

#[test]
#[ignore = "requires private bounded camera-derived replay input on stdin"]
fn unknown_inbox_camera_replay_from_stdin() -> Test {
    let mut wire=Vec::new();
    std::io::stdin().lock().take((8*1024*1024+1) as u64).read_to_end(&mut wire)?;
    if wire.is_empty() || wire.len()>8*1024*1024 {return Err("bounded replay input refused".into());}
    conversation_scenario_with_worker_guard_mode(false,false,false,false,false,false,0,false,true,true,false,false,true,Some(wire),7)
}

#[test]
#[ignore = "requires private bounded camera-derived replay input on stdin"]
fn owned_session_camera_replay_from_stdin() -> Test {
    let mut wire=Vec::new();
    std::io::stdin().lock().take((8*1024*1024+1) as u64).read_to_end(&mut wire)?;
    if wire.is_empty() || wire.len()>8*1024*1024 {return Err("bounded replay input refused".into());}
    lean_owned_session_replay(wire,false,false,false,0)?;
    println!("owned_session_camera_replay=passed");
    Ok(())
}

#[test]
fn owned_session_camera_fixture_stack_control() -> Test {
    lean_owned_session_replay(media_fixture()?,false,true,false,0)
}

#[test]
fn owned_session_restarts_with_rolled_av_lineage() -> Test {
    lean_owned_session_replay(media_fixture_with_count(include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264"),3,10)?,false,true,false,23)
}

#[test]
fn owned_session_begin_refusal_returns_all_owners() -> Test {
    lean_owned_session_replay(media_fixture()?,true,true,false,0)
}

#[test]
fn video_session_archives_sources_and_video_without_audio() -> Test {
    let task = std::thread::Builder::new().name("video-session".into()).stack_size(16 * 1024 * 1024).spawn(|| {
        let result: Test = (|| lean_owned_session_replay(video_only_media_fixture()?, false, true, false, 1))();
        result.map_err(|error| error.to_string())
    })?;
    task.join().map_err(|_| "video session fixture panicked")?.map_err(Into::into)
}

#[test]
fn video_session_retirement_preserves_pending_video_and_archives_tail() -> Test {
    let task = std::thread::Builder::new().name("video-pending-tail".into()).stack_size(16 * 1024 * 1024).spawn(|| {
        let result: Test = (|| lean_owned_session_replay(video_only_media_fixture()?, false, true, false, 22))();
        result.map_err(|error| error.to_string())
    })?;
    task.join().map_err(|_| "pending video fixture panicked")?.map_err(Into::into)
}

#[test]
fn video_session_rolls_over_and_services_controller() -> Test {
    let task = std::thread::Builder::new().name("video-session-rollover".into()).stack_size(16 * 1024 * 1024).spawn(|| {
        let result: Test = (|| lean_owned_session_replay(video_only_media_fixture_from(media_fixture_with_count(include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264"), 3, 10)?)?, false, true, false, 5))();
        result.map_err(|error| error.to_string())
    })?;
    task.join().map_err(|_| "video rollover fixture panicked")?.map_err(Into::into)
}

#[test]
fn video_session_cancelled_rollover_retains_pending_source() -> Test {
    let task = std::thread::Builder::new().name("video-session-cancel-rollover".into()).stack_size(16 * 1024 * 1024).spawn(|| {
        let result: Test = (|| lean_owned_session_replay(video_only_media_fixture_from(media_fixture_with_count(include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264"), 3, 10)?)?, false, true, false, 6))();
        result.map_err(|error| error.to_string())
    })?;
    task.join().map_err(|_| "video rollover cancellation fixture panicked")?.map_err(Into::into)
}

#[test]
fn video_session_cancelled_ready_rollover_cannot_resume() -> Test {
    let task = std::thread::Builder::new().name("video-session-cancel-ready".into()).stack_size(16 * 1024 * 1024).spawn(|| {
        let result: Test = (|| lean_owned_session_replay(video_only_media_fixture_from(media_fixture_with_count(include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264"), 3, 10)?)?, false, true, false, 7))();
        result.map_err(|error| error.to_string())
    })?;
    task.join().map_err(|_| "video rollover ready cancellation fixture panicked")?.map_err(Into::into)
}

#[test]
fn video_session_automatic_rollover_requires_explicit_admission_retry() -> Test {
    let task = std::thread::Builder::new().name("video-session-auto".into()).stack_size(16 * 1024 * 1024).spawn(|| {
        let result: Test = (|| lean_owned_session_replay(video_only_media_fixture_from(media_fixture_with_count(include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264"), 3, 10)?)?, false, true, false, 8))();
        result.map_err(|error| error.to_string())
    })?;
    task.join().map_err(|_| "automatic video rollover fixture panicked")?.map_err(Into::into)
}

#[test]
fn video_session_managed_rollover_waits_for_supplies_and_resumes() -> Test {
    let task = std::thread::Builder::new().name("video-session-managed".into()).stack_size(16 * 1024 * 1024).spawn(|| {
        let result: Test = (|| lean_owned_session_replay(video_only_media_fixture_from(media_fixture_with_count(include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264"), 3, 10)?)?, false, true, false, 9))();
        result.map_err(|error| error.to_string())
    })?;
    task.join().map_err(|_| "managed video rollover fixture panicked")?.map_err(Into::into)
}

#[test]
fn video_session_managed_detects_capacity_and_resumes() -> Test {
    let task = std::thread::Builder::new().name("video-session-managed-detect".into()).stack_size(16 * 1024 * 1024).spawn(|| {
        let result: Test = (|| lean_owned_session_replay(video_only_media_fixture_from(media_fixture_with_count(include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264"), 3, 10)?)?, false, true, false, 10))();
        result.map_err(|error| error.to_string())
    })?;
    task.join().map_err(|_| "managed video capacity fixture panicked")?.map_err(Into::into)
}

#[test]
fn video_session_provisions_rollover_and_resumes() -> Test {
    let task = std::thread::Builder::new().name("video-session-provision".into()).stack_size(16 * 1024 * 1024).spawn(|| {
        let result: Test = (|| lean_owned_session_replay(video_only_media_fixture_from(media_fixture_with_count(include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264"), 3, 10)?)?, false, true, false, 11))();
        result.map_err(|error| error.to_string())
    })?;
    task.join().map_err(|_| "video provisioning fixture panicked")?.map_err(Into::into)
}

#[test]
fn video_session_retained_reservation_precedes_rollover_creator() -> Test {
    let task = std::thread::Builder::new().name("video-session-retained-provision".into()).stack_size(16 * 1024 * 1024).spawn(|| {
        let result: Test = (|| lean_owned_session_replay(video_only_media_fixture_from(media_fixture_with_count(include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264"), 3, 10)?)?, false, true, false, 13))();
        result.map_err(|error| error.to_string())
    })?;
    task.join().map_err(|_| "retained video provisioning fixture panicked")?.map_err(Into::into)
}

#[test]
fn video_session_cancelled_reservation_never_starts_creator() -> Test {
    let task = std::thread::Builder::new().name("video-session-retained-cancel".into()).stack_size(16 * 1024 * 1024).spawn(|| {
        let result: Test = (|| lean_owned_session_replay(video_only_media_fixture_from(media_fixture_with_count(include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264"), 3, 10)?)?, false, true, false, 14))();
        result.map_err(|error| error.to_string())
    })?;
    task.join().map_err(|_| "cancelled retained provisioning fixture panicked")?.map_err(Into::into)
}

#[test]
#[ignore = "requires bounded private camera-derived video-only FLV on stdin"]
fn video_session_retained_replays_private_camera() -> Test {
    let mut wire=Vec::new();
    std::io::stdin().lock().take(8*1024*1024+1).read_to_end(&mut wire)?;
    if wire.len()<13 || wire.len()>8*1024*1024 || !wire.starts_with(b"FLV\x01") {return Err("bounded private video input refused".into());}
    let task=std::thread::Builder::new().name("video-session-retained-private".into()).stack_size(16*1024*1024).spawn(move || {
        lean_owned_session_replay(wire,false,true,false,15).map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"retained private video fixture panicked")?.map_err(Into::into)
}

#[test]
#[ignore = "requires bounded private camera-derived video-only FLV on stdin"]
fn video_session_bootstrap_retained_replays_private_camera() -> Test {
    let mut wire=Vec::new();
    std::io::stdin().lock().take(8*1024*1024+1).read_to_end(&mut wire)?;
    if wire.len()<13 || wire.len()>8*1024*1024 || !wire.starts_with(b"FLV\x01") {return Err("bounded private video input refused".into());}
    let task=std::thread::Builder::new().name("video-session-bootstrap-private".into()).stack_size(16*1024*1024).spawn(move || {
        lean_owned_session_replay(wire,false,true,false,18).map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"bootstrap private video fixture panicked")?.map_err(Into::into)
}

#[test]
fn video_session_bootstraps_retained_reservation_before_creator() -> Test {
    let task=std::thread::Builder::new().name("video-session-bootstrap-retained".into()).stack_size(16*1024*1024).spawn(|| {
        let result:Test=(|| lean_owned_session_replay(video_only_media_fixture_from(media_fixture_with_count(include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264"),3,10)?)?,false,true,false,16))();
        result.map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"retained bootstrap fixture panicked")?.map_err(Into::into)
}

#[test]
fn video_session_automatically_records_creator_and_reserves_next() -> Test {
    let task=std::thread::Builder::new().name("video-session-automatic-retained".into()).stack_size(16*1024*1024).spawn(|| {
        let result:Test=(|| lean_owned_session_replay(video_only_media_fixture_from(media_fixture_with_count(include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264"),3,10)?)?,false,true,false,19))();
        result.map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"automatic retained bootstrap fixture panicked")?.map_err(Into::into)
}

#[test]
fn video_session_cancelled_creator_observation_preserves_reservation() -> Test {
    let task=std::thread::Builder::new().name("video-session-automatic-cancel".into()).stack_size(16*1024*1024).spawn(|| {
        let result:Test=(|| lean_owned_session_replay(video_only_media_fixture_from(media_fixture_with_count(include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264"),3,10)?)?,false,true,false,20))();
        result.map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"automatic retained cancellation fixture panicked")?.map_err(Into::into)
}

#[test]
fn video_session_renews_automatic_allowance_only_after_custody_handoff() -> Test {
    let task=std::thread::Builder::new().name("video-session-automatic-renew".into()).stack_size(16*1024*1024).spawn(|| {
        let result:Test=(|| lean_owned_session_replay(video_only_media_fixture_from(media_fixture_with_count(include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264"),3,10)?)?,false,true,false,21))();
        result.map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"automatic renewal fixture panicked")?.map_err(Into::into)
}

#[test]
fn video_session_cancelled_bootstrap_never_starts_reservation() -> Test {
    let task=std::thread::Builder::new().name("video-session-bootstrap-cancel".into()).stack_size(16*1024*1024).spawn(|| {
        let result:Test=(|| lean_owned_session_replay(video_only_media_fixture_from(media_fixture_with_count(include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264"),3,10)?)?,false,true,false,17))();
        result.map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"cancelled bootstrap fixture panicked")?.map_err(Into::into)
}

#[test]
fn video_session_cancelled_rollover_join_preserves_outcome() -> Test {
    let task = std::thread::Builder::new().name("video-session-cancel-join".into()).stack_size(16 * 1024 * 1024).spawn(|| {
        let result: Test = (|| lean_owned_session_replay(video_only_media_fixture_from(media_fixture_with_count(include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264"), 3, 10)?)?, false, true, false, 12))();
        result.map_err(|error| error.to_string())
    })?;
    task.join().map_err(|_| "video rollover cancellation join fixture panicked")?.map_err(Into::into)
}

#[test]
fn video_bootstrap_uses_connection_configuration() -> Test {
    let task = std::thread::Builder::new().name("video-bootstrap".into()).stack_size(16 * 1024 * 1024).spawn(|| {
        let result: Test = (|| lean_owned_session_replay(video_only_media_fixture()?, false, true, false, 2))();
        result.map_err(|error| error.to_string())
    })?;
    task.join().map_err(|_| "video bootstrap fixture panicked")?.map_err(Into::into)
}

#[test]
fn video_bootstrap_requires_explicit_source_retry() -> Test {
    let task = std::thread::Builder::new().name("video-bootstrap-retry".into()).stack_size(16 * 1024 * 1024).spawn(|| {
        let result: Test = (|| lean_owned_session_replay(video_only_media_fixture()?, false, true, false, 3))();
        result.map_err(|error| error.to_string())
    })?;
    task.join().map_err(|_| "video bootstrap retry fixture panicked")?.map_err(Into::into)
}

#[test]
#[ignore = "requires bounded private camera-derived video-only FLV on stdin"]
fn video_bootstrap_replays_private_camera_video() -> Test {
    let mut wire = Vec::new();
    std::io::stdin().lock().take(8 * 1024 * 1024 + 1).read_to_end(&mut wire)?;
    if wire.len() < 13 || wire.len() > 8 * 1024 * 1024 { return Err("private video input bound refused".into()); }
    let task = std::thread::Builder::new().name("video-bootstrap-private".into()).stack_size(16 * 1024 * 1024).spawn(move || {
        let result: Test = lean_owned_session_replay(wire, false, true, false, 4);
        result.map_err(|error| error.to_string())
    })?;
    task.join().map_err(|_| "private video bootstrap fixture panicked")?.map_err(Into::into)
}

#[test]
fn owned_video_only_restart_archives_new_connection() -> Test {
    let task=std::thread::Builder::new().name("owned-video-restart".into()).stack_size(16*1024*1024).spawn(|| {
        let result:Test=(|| {
            let wire=media_fixture_with_pictures(include_bytes!("../../../experiments/unifi_tls_05_server_lab/tests/fixtures/synthetic_g4_resolution.264"),4)?;
            lean_owned_session_replay(wire,false,true,true,0)
        })();
        result.map_err(|error|error.to_string())
    })?;
    task.join().map_err(|_|"owned video restart fixture thread panicked")?.map_err(Into::into)
}

#[test]
fn owned_video_graph_restart_recovers_exact_profile() -> Test {
    let task = std::thread::Builder::new().name("owned-video-graph-restart".into()).stack_size(16 * 1024 * 1024).spawn(|| {
        let result: Test = (|| lean_owned_session_replay(video_only_media_fixture()?, false, true, false, 24))();
        result.map_err(|error| error.to_string())
    })?;
    task.join().map_err(|_| "video graph restart fixture thread panicked")?.map_err(Into::into)
}

#[test]
#[ignore = "requires bounded private full-resolution camera-derived video-only FLV on stdin"]
fn owned_video_graph_restart_private_camera_video() -> Test {
    let mut wire = Vec::new();
    std::io::stdin().lock().take(8 * 1024 * 1024 + 1).read_to_end(&mut wire)?;
    if wire.len() < 13 || wire.len() > 8 * 1024 * 1024 { return Err("private video input bound refused".into()); }
    let task = std::thread::Builder::new().name("private-video-graph-restart".into()).stack_size(16 * 1024 * 1024).spawn(move || {
        let result: Test = lean_owned_session_replay(wire, false, true, false, 25);
        result.map_err(|error| error.to_string())
    })?;
    task.join().map_err(|_| "private video graph restart fixture panicked")?.map_err(Into::into)
}

#[test]
fn owned_rolled_video_graph_restart_archives_new_connection() -> Test {
    let task = std::thread::Builder::new().name("rolled-video-graph-restart".into()).stack_size(16 * 1024 * 1024).spawn(|| {
        let result: Test = (|| lean_owned_session_replay(video_only_media_fixture()?, false, true, false, 26))();
        result.map_err(|error| error.to_string())
    })?;
    task.join().map_err(|_| "rolled video graph restart fixture panicked")?.map_err(Into::into)
}

#[test]
#[ignore = "requires bounded private full-resolution camera-derived video-only FLV on stdin"]
fn owned_rolled_video_graph_restart_private_camera_video() -> Test {
    let mut wire = Vec::new();
    std::io::stdin().lock().take(8 * 1024 * 1024 + 1).read_to_end(&mut wire)?;
    if wire.len() < 13 || wire.len() > 8 * 1024 * 1024 { return Err("private video input bound refused".into()); }
    let task = std::thread::Builder::new().name("private-rolled-video-restart".into()).stack_size(16 * 1024 * 1024).spawn(move || {
        let result: Test = lean_owned_session_replay(wire, false, true, false, 27);
        result.map_err(|error| error.to_string())
    })?;
    task.join().map_err(|_| "private rolled video graph restart fixture panicked")?.map_err(Into::into)
}

fn owned_source_limits() -> fss_reference::DeploymentLimits {
    fss_reference::DeploymentLimits {max_roots:256,spool_total_max_bytes:1024*1024*1024,..fss_reference::DeploymentLimits::standard()}
}

fn owned_av_limits() -> fss_reference::DeploymentLimits {
    fss_reference::DeploymentLimits {max_roots:384,spool_total_max_bytes:1536*1024*1024,..fss_reference::DeploymentLimits::standard()}
}

async fn drive_video_only_session<'scope, 'task, IO: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin>(
    supervisor: supervisor::Supervisor<'scope, 'task, IO>,
    coordinator: fss_reference::unifi_direct::source_coordinator::Coordinator,
    resources: Box<fss_reference::unifi_direct::av_unknown_worker_guard::BootstrapResources>,
    expected: &[u8],
    owner: &mut conversation::Owner<'_, 'scope, 'task>,
    operation: &OperationId,
    access: &dyn fss_reference::unifi_direct::archive::ReadAuthority,
    rollover_read: Arc<dyn fss_reference::unifi_direct::archive::ReadAuthority + Send + Sync>,
    rollover_root: &std::path::Path,
    rollover_replay: Arc<fss_reference::ReplayCx>,
    task: &'scope fss_runtime::execution::TaskCx<'task>,
    cx: &'scope asupersync::Cx,
    clock: MeteredClock<'scope, 'task>,
    bootstrap_mode: u8,
    storage_cfg: fss_reference::unifi_direct::recording_storage::Configuration<'_>,
    replay_authority: &fss_core::region::ContextAuthority,
    retain: Arc<dyn fss_reference::unifi_direct::archive::RetainAuthority + Send + Sync>,
    management: Preconditions,
    stream: intent::Preconditions,
    admission_policy: &'scope FixtureMediaAdmission,
) -> Test {
    use fss_reference::unifi_direct::{archive, evidence, retirement_source, source_coordinator::ArchiveAdmission, source_worker, video_bootstrap, video_owned_sink, video_session, video_worker};
    use fss_packet::extended_flv::stream::{Next, SearchMode};
    let key = storage_cfg.source;
    let admission = ArchiveAdmission { resource: "fixture:video-session", cost: &BudgetVector::ZERO };
    let mut source_pins = Vec::new();
    let mut offered_sources = 0usize;
    let mut syncs = 0usize;
    let mut session = if bootstrap_mode != 0 {
        let policy = video_bootstrap::Policy { inband: matches!(bootstrap_mode, 4 | 25 | 27), retention: ContentDigest::sha256(b"worker guard retention"), media_limits: fss_container::Mp4Limits::default(), evidence_limits: evidence::Limits::default() };
        let wrong_key = SourceKey { connection: key.connection, generation: key.generation + 1 };
        let refused = match video_bootstrap::Bootstrap::begin(supervisor, coordinator.into_worker(), resources, wrong_key, storage_cfg.camera_claim, policy) {
            Err(parts) => parts,
            Ok(_) => return Err("bootstrap accepted a different recorder key".into()),
        };
        let mut bootstrap = video_bootstrap::Bootstrap::begin(refused.supervisor, refused.source, refused.resources.ok_or("bootstrap resources lost")?, key, refused.camera_claim, refused.policy)
            .map_err(|_| "bootstrap refused matching owners")?;
        bootstrap = match bootstrap.into_session() {
            Err(video_bootstrap::HandoffRefusal::NotReady(bootstrap)) => bootstrap,
            _ => return Err("bootstrap allowed premature handoff".into()),
        };
        bootstrap.control().ok_or("bootstrap control missing")?.set_time_sync_reply_wait(Some(Duration::from_secs(5)))?;
        if bootstrap.authorize_source_retry() { return Err("bootstrap retry without pending source".into()); }
        if !matches!(Box::pin(bootstrap.step(owner, operation, Duration::ZERO, task, cx, clock, admission)).await, video_bootstrap::Step::Configuration) { return Err("bootstrap invalid wait accepted".into()); }
        let mut bad_cost = BudgetVector::ZERO;
        bad_cost.bytes = 33_000_000;
        let bad_admission = ArchiveAdmission { resource: "fixture:video-session", cost: &bad_cost };
        let mut force_refusal = false;
        let mut await_retry = false;
        let mut did_retry = false;
        timeout(cx.now(), Duration::from_secs(30), async {
            for index in 0..4096u64 {
                let op = OperationId::parse(format!("{}:bootstrap-{index:016x}", operation.as_str()))?;
                let mut control = None;
                let mut completion = None;
                let current_admission = if force_refusal { bad_admission } else { admission };
                match Box::pin(bootstrap.step(owner, &op, Duration::from_millis(100), task, cx, clock, current_admission)).await {
                    video_bootstrap::Step::SourceOffered(_) | video_bootstrap::Step::Configured => {
                        offered_sources += 1;
                        if bootstrap_mode == 3 && !did_retry { force_refusal = true; }
                    },
                    video_bootstrap::Step::SourceStarted => (),
                    video_bootstrap::Step::SourceStartRefused(fss_reference::unifi_direct::av_worker::StartError::Task(_)) if force_refusal => {
                        force_refusal = false;
                        await_retry = true;
                    },
                    video_bootstrap::Step::SourceRetryRequired(step) if await_retry => {
                        if !bootstrap.authorize_source_retry() || bootstrap.authorize_source_retry() { return Err("bootstrap retry authorization failed".into()); }
                        await_retry = false;
                        did_retry = true;
                        control = Some(step);
                    },
                    video_bootstrap::Step::Supervisor(step) => control = Some(step),
                    video_bootstrap::Step::SourceArchive { control: step, completion: result } => { control = step; completion = result; },
                    video_bootstrap::Step::Ready => return Ok::<(), Box<dyn Error>>(()),
                    _ => return Err("video bootstrap refused or halted".into()),
                }
                if let Some(step) = control {
                    match step {
                        supervisor::Step::Idle | supervisor::Step::Media(pipeline::Step::Progress { .. }) | supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Buffered)) => (),
                        supervisor::Step::Observation(Observation::StreamSettingsReply { success, .. }) if success != Some(false) => (),
                        supervisor::Step::TimeSyncWritten { mut trace } => {
                            let op = trace.operation().ok_or("bootstrap clock operation missing")?;
                            if owner.effects.journal().operation(op).map(|entry| entry.state) != Some(fss_core::EffectState::Committed) { return Err("bootstrap clock effect not committed".into()); }
                            if !matches!(trace.take_written(), Some(ManagementWrite::Written { permit }) if permit.journal_backed()) { return Err("bootstrap clock receipt missing".into()); }
                            syncs += 1;
                        },
                        other => { eprintln!("video bootstrap stopped supervisor {:?}",std::mem::discriminant(&other)); return Err("video bootstrap control stopped".into()); },
                    }
                }
                if let Some(completion) = completion {
                    if completion.runtime.is_err() { return Err("bootstrap source runtime failed".into()); }
                    match completion.outcome {
                        source_worker::Outcome::Publication(source_worker::Publication::Published { pin, .. }) => source_pins.push(pin),
                        _ => return Err("bootstrap source publication failed".into()),
                    }
                }
            }
            Err("bootstrap step limit".into())
        }).await??;
        if offered_sources != source_pins.len() || (bootstrap_mode == 3 && !did_retry) { return Err("bootstrap source custody or retry incomplete".into()); }
        bootstrap.into_session().map_err(|_| "bootstrap handoff refused")?
    } else {
    let mut framer = Framer::with_mode(FlvLimits::default(), fss_packet::extended_flv::stream::MAX_BUFFER_BYTES, SearchMode::ZeroStreamId)?;
    framer.append(0, expected)?;
    let mut probe = recording::Recorder::new(key, recording::Limits::default())?;
    let configuration = loop {
        match framer.take()? {
            Next::Record(record) => match probe.push(record).map_err(|refusal| refusal.reason)? {
                recording::Push::Source { record, disposition: recording::SourceDisposition::Configuration } => break record,
                _ => (),
            },
            _ => return Err("fixture configuration missing".into()),
        }
    };
    let wrong_key = SourceKey { connection: key.connection, generation: key.generation + 1 };
    let sink = video_owned_sink::Sink::new(video_owned_sink::Inputs {
        configuration, source: wrong_key, inband: false, retention: ContentDigest::sha256(b"worker guard retention"),
        media_limits: fss_container::Mp4Limits::default(), evidence_limits: evidence::Limits::default(),
    }).map_err(|_| "video sink construction failed")?;
    let fss_reference::unifi_direct::av_unknown_worker_guard::BootstrapResources { deployment, journal, keeper, replay, authority, limits, work_limit, rollover_custody } = *resources;
    if rollover_custody.is_some() { return Err("unexpected recovered rollover custody".into()); }
    let video = video_worker::Worker::new(video_worker::Parts { sink, deployment, journal, keeper, replay, authority, limits, work_limit })
        .map_err(|_| "video worker construction failed")?;
    let refused = match video_session::Session::attach(supervisor, video, coordinator.into_worker(), wrong_key, ContentDigest::sha256(b"fixture camera")) {
        Err(parts) => parts,
        Ok(_) => return Err("wrong recorder source binding accepted".into()),
    };
    let retired = refused.video.retire().map_err(|_| "wrong-key worker did not retire")?;
    if retired.fenced || retired.report.is_some() { return Err("wrong-key worker not intact".into()); }
    let video_worker::Parts { sink, deployment, journal, keeper, replay, authority, limits, work_limit } = retired.parts;
    let retired_sink = sink.retire();
    if retired_sink.pending.is_some() || retired_sink.pending_pin.is_some() { return Err("wrong-key sink not intact".into()); }
    let mut inputs = retired_sink.inputs;
    inputs.source = key;
    let sink = video_owned_sink::Sink::new(inputs).map_err(|_| "recovered video sink refused")?;
    let video = video_worker::Worker::new(video_worker::Parts { sink, deployment, journal, keeper, replay, authority, limits, work_limit })
        .map_err(|_| "recovered video worker refused")?;
    let refused = match video_session::Session::attach(refused.supervisor, video, refused.source, wrong_key, refused.camera_claim) {
        Err(parts) => parts,
        Ok(_) => return Err("wrong sink source binding accepted".into()),
    };
    video_session::Session::attach(refused.supervisor, refused.video, refused.source, key, refused.camera_claim)
        .map_err(|_| "video session attachment refused")?
    };
    if session.authorize_video_retry() || session.authorize_source_retry() { return Err("retry accepted without pending work".into()); }
    session.control().ok_or("video session control missing")?.set_time_sync_reply_wait(Some(Duration::from_secs(5)))?;
    let mut video_pins = Vec::new();
    let mut rollover_count = 0usize;
    let mut rollover_candidate = None;
    if !matches!(Box::pin(session.step(owner, operation, Duration::ZERO, task, cx, clock, admission, admission)).await, video_session::Step::Configuration) {
        return Err("invalid wait was not refused".into());
    }
    let mut session = Some(session);
    let mut managed_session = if bootstrap_mode == 10 { Some(video_session::ManagedSession::new(session.take().ok_or("managed initial session missing")?)) } else { None };
    let cancelled = timeout(cx.now(), Duration::from_secs(30), async {
        for index in 0..4096u64 {
            let op = OperationId::parse(format!("{}:video-{index:016x}", operation.as_str()))?;
            let mut control = None;
            let mut source_completion = None;
            let mut video_completion = None;
            let next = if let Some(managed) = managed_session.as_mut() {
                match Box::pin(managed.step(owner, &op, Duration::from_millis(100), task, cx, clock, admission, admission)).await {
                    video_session::ManagedStep::Session(step) => step,
                    video_session::ManagedStep::SuppliesRequired(video_session::Step::VideoRetryRequired(supervisor::Step::Idle)) => {
                        use fss_runtime::effect_journal::PinRetainedEffectJournal;
                        task.checkpoint_for(RuntimeGrant::ObjectStage, rollover_root.to_str().ok_or("rollover path")?, clock.now()?, &BudgetVector::ZERO)?;
                        let create = |name: &str| -> Result<Box<dyn fss_runtime::effect_journal::EffectJournalStore>, Box<dyn Error>> { Ok(Box::new(FileEffectJournal::create(rollover_root.join(name), EffectJournalLimits::default(), Arc::new(HostSpoolIo))?)) };
                        let retainer = fss_object::effect_journal::FileTrustedRootPinRetainer::create(rollover_root.join("managed-video-retainer"), EffectJournalLimits::default(), Arc::new(HostSpoolIo), ContentDigest::sha256(b"managed-video-session-switch"))?;
                        let supplies = fss_reference::unifi_direct::av_rollover_worker::Supplies {
                            next_journal: create("managed-video-journal")?, next_keeper: create("managed-video-keeper")?,
                            switch: PinRetainedEffectJournal::new(create("managed-video-switch")?, Box::new(retainer))?, read: rollover_read.clone(),
                            object_limits: archive::StagedAvLimits {max_objects:8192,max_object_bytes:64*1024*1024,max_total_bytes:128*1024*1024}, work_limit:4_000_000_000,
                        };
                        managed.provide(supplies).map_err(|_| "managed automatic supplies refused")?;
                        continue;
                    }
                    video_session::ManagedStep::RolloverBeginning | video_session::ManagedStep::Rollover(video_session::AutomaticRolloverStep::Started) | video_session::ManagedStep::Rollover(video_session::AutomaticRolloverStep::Rollover(video_session::RolloverStep::PreflightReady)) => continue,
                    video_session::ManagedStep::Rollover(video_session::AutomaticRolloverStep::Rollover(video_session::RolloverStep::Control(step))) => video_session::Step::Supervisor(step),
                    video_session::ManagedStep::Resumed(receipt) => {
                        if receipt.outcome != fss_publication::RootLedgerOutcome::AlreadyLedgered { return Err("managed automatic replay receipt changed".into()); }
                        rollover_count += 1;
                        continue;
                    }
                    _ => return Err("managed automatic session stopped".into()),
                }
            } else { Box::pin(session.as_mut().ok_or("video session owner missing")?.step(owner, &op, Duration::from_millis(100), task, cx, clock, admission, admission)).await };
            match next {
                video_session::Step::SourceOffered(_) => offered_sources += 1,
                video_session::Step::VideoOffered if bootstrap_mode == 22 => {
                    let mut active = session.take().ok_or("pending video session missing")?;
                    active.abort();
                    if active.join_source().await.is_some() || active.join_video().await.is_some() {
                        return Err("unexpected running attempt during pending retirement".into());
                    }
                    let parts = active.into_parts().map_err(|_| "pending video session did not drain")?;
                    if parts.video.status() != video_worker::Status::Pending {
                        return Err("video segment not retained before retirement".into());
                    }
                    let retired = parts.prepare_retirement().map_err(|_| "pending video retirement refused")?;
                    if !retired.halted || retired.time_sync.is_some() || retired.video.status() != video_worker::Status::Pending {
                        return Err("pending video or controller custody changed".into());
                    }
                    let mut tail = retired.tail;
                    let tail_count = tail.plan().len();
                    if tail_count == 0 || tail.plan().pending_audio.is_some() || tail.plan().recorder_fenced {
                        return Err("pending video fixture did not retain a valid tail".into());
                    }
                    let mut offered = None;
                    let mut pins = Vec::new();
                    let mut finished = false;
                    for _ in 0..1024 {
                        match Box::pin(tail.step(task, cx, clock, admission)).await {
                            retirement_source::DriverStep::Offered { offset, len, disposition } if offered.is_none() => {
                                offered = Some((offset, len, disposition));
                            }
                            retirement_source::DriverStep::Started => (),
                            retirement_source::DriverStep::Completed(completion) if offered.is_some() => {
                                if completion.runtime.is_err() { return Err("tail publication runtime failed".into()); }
                                let pin = match completion.outcome {
                                    source_worker::Outcome::Publication(source_worker::Publication::Published { pin, .. }) => pin,
                                    _ => return Err("tail publication requires reconciliation".into()),
                                };
                                pins.push((pin, offered.take().ok_or("tail source missing")?));
                            }
                            retirement_source::DriverStep::Finished if offered.is_none() => { finished = true; break; },
                            _ => return Err("tail source requires reconciliation".into()),
                        }
                    }
                    let tail_parts = tail.into_parts().map_err(|_| "tail publication still running")?;
                    if !finished || !tail_parts.plan.is_empty() || offered.is_some() || pins.len() != tail_count {
                        return Err("pending video tail was not fully drained".into());
                    }
                    if retired.video.status() != video_worker::Status::Pending {
                        return Err("pending video changed while the tail was archived".into());
                    }
                    let mut source = tail_parts.worker.retire().map_err(|_| "tail source did not retire")?;
                    if source.fenced || source.pending.is_some() { return Err("tail source needs reconciliation".into()); }
                    for (pin, (offset, len, disposition)) in pins {
                        let record = archive::read_unknown_time_source(&mut source.parts.deployment, pin, access,
                            archive::Limits::default(), &mut fss_geometry::WorkBudget::new(4_000_000_000), &source.parts.replay)?;
                        let start = usize::try_from(offset)?;
                        let end = start.checked_add(len).ok_or("tail range overflow")?;
                        if record.offset() != offset || record.disposition() != disposition || expected.get(start..end) != Some(record.bytes()) {
                            return Err("tail source bytes changed".into());
                        }
                    }
                    let video = retired.video.retire().map_err(|_| "pending video worker did not retire")?;
                    if video.fenced || video.report.is_some() { return Err("pending video worker needs reconciliation".into()); }
                    let sink = video.parts.sink.retire();
                    if sink.pending_pin.is_some() { return Err("unstarted video acquired a candidate pin".into()); }
                    let segment = sink.pending.ok_or("pending video segment disappeared")?;
                    if segment.source().is_empty() { return Err("pending video source missing".into()); }
                    for record in segment.source() {
                        let start = usize::try_from(record.offset())?;
                        let end = start.checked_add(record.bytes().len()).ok_or("video source range overflow")?;
                        if expected.get(start..end) != Some(record.bytes()) { return Err("pending video source changed".into()); }
                    }
                    println!("video_pending_tail=verified tail_records={tail_count} pending_video_retained=true pending_pin=none");
                    return Ok::<bool, Box<dyn Error>>(true);
                }
                video_session::Step::VideoOffered | video_session::Step::SourceStarted | video_session::Step::VideoStarted => (),
                video_session::Step::Supervisor(step) => control = Some(step),
                video_session::Step::SourceArchive { control: step, completion } => { control = step; source_completion = completion; },
                video_session::Step::VideoArchive { control: step, completion } => { control = step; video_completion = completion; },
                _ => return Err("video session refused or halted".into()),
            }
            if let Some(step) = control {
                match step {
                    supervisor::Step::Idle | supervisor::Step::Media(pipeline::Step::Progress { .. }) | supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Buffered)) => (),
                    supervisor::Step::Observation(Observation::StreamSettingsReply { success, .. }) if success != Some(false) => (),
                    supervisor::Step::TimeSyncWritten { mut trace } => {
                        let op = trace.operation().ok_or("clock operation missing")?;
                        if owner.effects.journal().operation(op).map(|entry| entry.state) != Some(fss_core::EffectState::Committed) { return Err("clock effect not committed".into()); }
                        if !matches!(trace.take_written(), Some(ManagementWrite::Written { permit }) if permit.journal_backed()) { return Err("clock receipt missing".into()); }
                        syncs += 1;
                    }
                    supervisor::Step::TimeSyncStopped { error, .. } => { eprintln!("video_session_clock_stop={error:?}"); return Err("video session clock stopped".into()); },
                    other => { eprintln!("video_session_control_kind={:?}", std::mem::discriminant(&other)); return Err("video session control stopped".into()); },
                }
            }
            if let Some(completion) = source_completion {
                if completion.runtime.is_err() { return Err("source runtime failed".into()); }
                match completion.outcome {
                    source_worker::Outcome::Publication(source_worker::Publication::Published { pin, .. }) => source_pins.push(pin),
                    _ => return Err("source publication failed".into()),
                }
            }
            if let Some(completion) = video_completion {
                if completion.runtime.is_err() { return Err("video runtime failed".into()); }
                match completion.outcome {
                    video_worker::Outcome::Publication(video_worker::Publication::Published(published)) => {
                        if rollover_candidate.take().is_some_and(|candidate| candidate != published.pin) { return Err("rollover changed pending video candidate".into()); }
                        video_pins.push(published.pin);
                    },
                    video_worker::Outcome::Publication(video_worker::Publication::Refused { pending: Some(candidate), reason: video_worker::Refusal::BeforePublication(fss_reference::unifi_direct::av_worker::FailureReason::JournalCapacity) }) if bootstrap_mode == 10 && rollover_count == 0 => { rollover_candidate = Some(candidate); },
                    video_worker::Outcome::Publication(video_worker::Publication::Refused { pending: Some(candidate), reason: video_worker::Refusal::BeforePublication(fss_reference::unifi_direct::av_worker::FailureReason::JournalCapacity) }) if matches!(bootstrap_mode,13|14|15|16|17|18|19|20|21) && rollover_count == 0 => {
                        use fss_reference::unifi_direct::{av_rollover_generation as generation, av_rollover_supplies, video_provision, video_retained_provision as retained};
                        use fss_runtime::effect_journal::PinRetainedEffectJournal;
                        let current = session.take().ok_or("session missing for retained provisioning")?;
                        let managed = video_session::ManagedSession::at_capacity(current, candidate).map_err(|_| "retained capacity refused")?;
                        let plan = generation::Plan::new(generation::Configuration {
                            namespace: "retained-video".into(), scope_seed: ContentDigest::sha256(b"retained video fixture"), first: 1, count: 1,
                            journal_replay: rollover_replay.clone(), pin_replay: rollover_replay.clone(),
                            journal_io: Arc::new(HostSpoolIo), pin_io: Arc::new(HostSpoolIo), journal_limits: EffectJournalLimits::default(), pin_limits: EffectJournalLimits::default(),
                            read: rollover_read.clone(), object_limits: archive::StagedAvLimits {max_objects:8192,max_object_bytes:64*1024*1024,max_total_bytes:128*1024*1024}, work_limit: if matches!(bootstrap_mode,15|18) {100_000_000_000} else {4_000_000_000},
                        }).map_err(|_| "retained plan invalid")?;
                        let journal_path=rollover_root.join("generation-journal");
                        let pin_path=rollover_root.join("generation-pin");
                        task.checkpoint_for(RuntimeGrant::ObjectStage, journal_path.to_str().ok_or("journal path")?, clock.now()?, &BudgetVector::ZERO)?;
                        task.checkpoint_for(RuntimeGrant::ObjectStage, pin_path.to_str().ok_or("pin path")?, clock.now()?, &BudgetVector::ZERO)?;
                        let mut driver=if matches!(bootstrap_mode,16|17|18|19|20|21) {
                            let bootstrap=generation::BootstrapWorker::new(generation::BootstrapInputs {plan,storage:generation::BootstrapStorage {
                                mode:generation::BootstrapMode::Create,journal_root:journal_path,custody_root:pin_path,
                                journal_replay:rollover_replay.clone(),custody_replay:rollover_replay.clone(),
                                journal_io:Arc::new(HostSpoolIo),custody_io:Arc::new(HostSpoolIo),journal_limits:EffectJournalLimits::default(),custody_limits:EffectJournalLimits::default(),
                                custody_scope:ContentDigest::sha256(b"retained generation pin"),
                            }}).map_err(|_|"bootstrap worker invalid")?;
                            if matches!(bootstrap_mode,19|20|21) {
                                let mut recording = video_bootstrap::ManagedRecording::from_managed(managed);
                                if recording.control().is_none() { return Err("recording controller missing before provisioning handoff".into()); }
                                let bootstrap = if bootstrap_mode == 19 {
                                    bootstrap.abort();
                                    let (returned, refused) = match recording.into_retained_provisioning(bootstrap) {
                                        Err(owners) => owners,
                                        Ok(_) => return Err("cancelled generation bootstrap was accepted".into()),
                                    };
                                    recording = returned;
                                    if recording.control().is_none() { return Err("refusal lost recording controller".into()); }
                                    let mut retired = refused.retire().map_err(|_| "refused bootstrap unexpectedly running")?;
                                    if !retired.fenced || retired.journal_attempted || retired.custody_attempted || retired.outcome.is_some() {
                                        return Err("refused bootstrap changed storage".into());
                                    }
                                    let plan = retired.plan.take().ok_or("refused bootstrap lost plan")?;
                                    generation::BootstrapWorker::new(generation::BootstrapInputs { plan, storage: retired.storage })
                                        .map_err(|_| "explicit replacement bootstrap refused")?
                                } else { bootstrap };
                                let mut retained = recording.into_retained_provisioning(bootstrap).map_err(|_| "recording provisioning handoff refused")?;
                                if retained.control().is_none() { return Err("recording controller missing after provisioning handoff".into()); }
                                retained
                            } else {
                                retained::RetainedSession::with_bootstrap(managed,bootstrap).map_err(|_|"retained bootstrap session refused")?
                            }
                        } else {
                            let store=FileEffectJournal::create(&journal_path, EffectJournalLimits::default(), Arc::new(HostSpoolIo))?;
                            let pin=fss_object::effect_journal::FileTrustedRootPinRetainer::create(&pin_path, EffectJournalLimits::default(), Arc::new(HostSpoolIo), ContentDigest::sha256(b"retained generation pin"))?;
                            let journal=PinRetainedEffectJournal::new(Box::new(store),Box::new(pin))?;
                            let plan=generation::ReservedPlan::create(plan,journal,&rollover_replay).map_err(|_| "retained plan bind refused")?;
                            let reservation=generation::ReservationWorker::new(generation::ReservationInputs {plan,request:generation::ReservationRequest::Reserve,journal_resource:journal_path,custody_resource:pin_path,journal_replay:rollover_replay.clone(),custody_replay:rollover_replay.clone()}).map_err(|_| "reservation worker invalid")?;
                            retained::RetainedSession::new(managed,reservation).map_err(|_| "retained session refused")?
                        };
                        if matches!(bootstrap_mode,19|20|21) {
                            if !driver.enable_creator_observation(if bootstrap_mode==21 {0} else {1}) || driver.enable_creator_observation(1) {return Err("automatic policy admission failed".into());}
                            let mut bootstrap_started=false; let mut ready=false; let mut first=false;
                            let mut creator_started=false; let mut installed=false; let mut reconciled=false; let mut second=None;
                            let mut released_custody=None;
                            for round in 0..2048u64 {
                                let op=OperationId::parse(format!("{}:automatic-retained-{round:016x}",operation.as_str()))?;
                                match Box::pin(driver.step(owner,&op,Duration::from_millis(10),task,cx,clock,admission,admission,&BudgetVector::ZERO)).await {
                                    retained::Step::BootstrapStarted=>bootstrap_started=true,
                                    retained::Step::BootstrapReady if bootstrap_started=>ready=true,
                                    retained::Step::ReservationStarted if ready=>(),
                                    retained::Step::Reserved(identity) if identity.generation==1 && !first=>first=true,
                                    retained::Step::Session(video_provision::Step::SupplyStarted) if first && !creator_started=>creator_started=true,
                                    retained::Step::Session(video_provision::Step::SupplyInstalled(completion)) if creator_started && completion.runtime.is_ok() && completion.outcome==av_rollover_supplies::Outcome::Ready=>{installed=true;if bootstrap_mode==21 && driver.renew_creator_observation(1) {return Err("renewed before observation was recorded".into());} if bootstrap_mode==20 {break;}},
                                    retained::Step::Reconciled(pin) if installed && pin.sequence==3=>{
                                        reconciled=true;
                                        if bootstrap_mode==21 {
                                            if driver.renew_creator_observation(0) || driver.renew_creator_observation(9) || driver.renew_creator_observation(1) {return Err("renewed before custody handoff or with invalid allowance".into());}
                                            released_custody=driver.take_custody();
                                            if released_custody.is_none() || !driver.renew_creator_observation(1) || driver.renew_creator_observation(1) {return Err("automatic renewal admission failed".into());}
                                        }
                                    },
                                    retained::Step::Reserved(identity) if reconciled && identity.generation==2=>{second=Some(identity);break;},
                                    retained::Step::Session(video_provision::Step::Managed(video_session::ManagedStep::Session(video_session::Step::Supervisor(supervisor::Step::Idle))))=>(),
                                    retained::Step::Session(video_provision::Step::Managed(video_session::ManagedStep::SuppliesRequired(video_session::Step::VideoRetryRequired(supervisor::Step::Idle))))=>(),
                                    retained::Step::Session(video_provision::Step::Managed(video_session::ManagedStep::RolloverBeginning))=>(),
                                    retained::Step::Session(video_provision::Step::Managed(video_session::ManagedStep::Rollover(video_session::AutomaticRolloverStep::Started | video_session::AutomaticRolloverStep::Rollover(video_session::RolloverStep::PreflightReady))))=>(),
                                    retained::Step::Session(video_provision::Step::Managed(video_session::ManagedStep::Rollover(video_session::AutomaticRolloverStep::Rollover(video_session::RolloverStep::Control(supervisor::Step::Idle)))))=>(),
                                    retained::Step::Session(video_provision::Step::Managed(video_session::ManagedStep::Resumed(_)))=>(),
                                    other=>{eprintln!("automatic_retained_step_class={:?}",std::mem::discriminant(&other));return Err("automatic retained session stopped".into());},
                                }
                            }
                            if bootstrap_mode==20 {
                                if !bootstrap_started || !ready || !first || !creator_started || !installed || reconciled || second.is_some() {return Err("automatic cancellation branch incomplete".into());}
                                driver.abort();
                                if driver.join_reservation().await {return Err("unstarted observation unexpectedly joined".into());}
                                let op=OperationId::parse(format!("{}:automatic-cancel",operation.as_str()))?;
                                if !matches!(Box::pin(driver.step(owner,&op,Duration::from_millis(10),task,cx,clock,admission,admission,&BudgetVector::ZERO)).await,retained::Step::Aborted) {return Err("automatic cancellation was advanced".into());}
                                let _=driver.join_rollover().await; let _=driver.join_supply().await;
                                let owners=driver.into_parts();
                                let worker=owners.reservation.ok_or("cancelled observation worker missing")?;
                                let retirement=worker.retire().map_err(|_|"cancelled observation still running")?;
                                if !retirement.fenced || !retirement.aborted || retirement.outcome.is_some()
                                    || retirement.inputs.plan.head().map(|pin|pin.sequence)!=Some(2)
                                    || retirement.inputs.plan.pending().map(|id|id.generation)!=Some(1)
                                    || !matches!(&retirement.inputs.request,generation::ReservationRequest::ObservedCreator(_)) {return Err("cancelled observation changed reservation".into());}
                                let auto=owners.automatic.ok_or("cancelled automatic custody missing")?;
                                if auto.remaining!=1 || auto.custody.len()!=1 {return Err("cancelled automatic custody changed".into());}
                                let inner=owners.inner.into_parts();
                                if inner.worker.is_some() || inner.started {return Err("cancelled automatic session started another creator".into());}
                                let original_bootstrap = owners.bootstrap_retirement.ok_or("bootstrap custody missing after cancellation")?;
                                let probe_plan = generation::Plan::new(generation::Configuration {
                                    namespace: "retained-video-probe".into(), scope_seed: ContentDigest::sha256(b"stopped video fixture"), first: 1, count: 1,
                                    journal_replay: rollover_replay.clone(), pin_replay: rollover_replay.clone(),
                                    journal_io: Arc::new(HostSpoolIo), pin_io: Arc::new(HostSpoolIo), journal_limits: EffectJournalLimits::default(), pin_limits: EffectJournalLimits::default(),
                                    read: rollover_read.clone(), object_limits: archive::StagedAvLimits {max_objects:8192,max_object_bytes:64*1024*1024,max_total_bytes:128*1024*1024}, work_limit:4_000_000_000,
                                }).map_err(|_| "stopped probe plan invalid")?;
                                let probe = generation::BootstrapWorker::new(generation::BootstrapInputs { plan: probe_plan, storage: original_bootstrap.storage })
                                    .map_err(|_| "stopped probe bootstrap invalid")?;
                                let stopped = video_bootstrap::ManagedRecording::from_managed(inner.managed);
                                let (stopped, probe) = match stopped.into_retained_provisioning(probe) {
                                    Err(owners) => owners,
                                    Ok(_) => return Err("stopped recording admitted provisioning".into()),
                                };
                                let probe = probe.retire().map_err(|_| "stopped probe unexpectedly running")?;
                                if probe.journal_attempted || probe.custody_attempted || probe.outcome.is_some() {
                                    return Err("stopped recording performed provisioning work".into());
                                }
                                let managed = match stopped.into_owner() {
                                    video_bootstrap::ManagedRecordingOwner::Recording(managed) => managed.into_parts(),
                                    _ => return Err("stopped recording owner lost".into()),
                                };
                                match managed.owner {
                                    Some(video_session::ManagedOwner::Recording(mut session))=>{
                                        let _=session.join_source().await; let _=session.join_video().await;
                                        let _parts=session.into_parts().map_err(|_|"cancelled automatic recording did not drain")?;
                                    },
                                    Some(video_session::ManagedOwner::Rollover(rollover))=>{
                                        let _parts=rollover.into_rollover().into_parts().map_err(|_|"cancelled automatic rollover did not drain")?;
                                    },
                                    _=>return Err("cancelled automatic managed owner missing".into()),
                                }
                                drop((retirement,auto,probe));
                                println!("automatic_creator_observation=cancelled pending_generation=1 journal_sequence=2");
                                return Ok::<bool, Box<dyn Error>>(true);
                            }
                            let second=second.ok_or("automatic second reservation missing")?;
                            if !bootstrap_started || !ready || !first || !creator_started || !installed || !reconciled || second.journal_root.exists() || second.pin_root.exists() {return Err("automatic generation ordering invalid".into());}
                            driver.abort(); let _=driver.join_rollover().await; let _=driver.join_supply().await;
                            let owners=driver.into_parts();
                            if owners.started || owners.reservation.is_some() || owners.retirement.as_ref().and_then(|r|r.inputs.plan.pending()).map(|id|id.generation)!=Some(2) {return Err("automatic reservation custody lost".into());}
                            let auto=owners.automatic.ok_or("automatic custody missing")?;
                            if auto.remaining!=0 || auto.stopped || auto.custody.len()!=if bootstrap_mode==21 {0} else {1} || (bootstrap_mode==21 && released_custody.is_none()) {return Err("automatic custody state invalid".into());}
                            let mut inner=owners.inner.into_parts();
                            let worker=inner.worker.take().ok_or("unstarted second creator missing")?;
                            let retired=worker.retire().map_err(|_|"second creator unexpectedly running")?;
                            if retired.root_created || retired.pin_root_created || retired.outcome.is_some() {return Err("second creator unexpectedly performed I/O".into());}
                            let managed=inner.managed.into_parts();
                            match managed.owner {
                                Some(video_session::ManagedOwner::Recording(mut session))=>{
                                    let _=session.join_source().await; let _=session.join_video().await;
                                    let _parts=session.into_parts().map_err(|_|"automatic recording did not drain")?;
                                },
                                Some(video_session::ManagedOwner::Rollover(rollover))=>{
                                    let _parts=rollover.into_rollover().into_parts().map_err(|_|"automatic rollover did not drain")?;
                                },
                                _=>return Err("automatic managed owner missing".into()),
                            }
                            let retirement=owners.retirement.ok_or("automatic reservation retirement missing")?;
                            let minimum=retirement.inputs.plan.head().ok_or("automatic journal head missing")?;
                            if minimum.sequence!=4 {return Err("automatic journal sequence invalid".into());}
                            let journal_path=retirement.inputs.journal_resource.clone();
                            let pin_path=retirement.inputs.custody_resource.clone();
                            let (old_plan,journal)=retirement.inputs.plan.into_parts();
                            drop((old_plan,journal));
                            let plan=generation::Plan::new(generation::Configuration {
                                namespace:"retained-video".into(),scope_seed:ContentDigest::sha256(b"retained video fixture"),first:3,count:1,
                                journal_replay:rollover_replay.clone(),pin_replay:rollover_replay.clone(),
                                journal_io:Arc::new(HostSpoolIo),pin_io:Arc::new(HostSpoolIo),journal_limits:EffectJournalLimits::default(),pin_limits:EffectJournalLimits::default(),
                                read:rollover_read.clone(),object_limits:archive::StagedAvLimits {max_objects:8192,max_object_bytes:64*1024*1024,max_total_bytes:128*1024*1024},work_limit:4_000_000_000,
                            }).map_err(|_|"automatic recovery plan invalid")?;
                            let mut reopen=generation::BootstrapWorker::new(generation::BootstrapInputs {plan,storage:generation::BootstrapStorage {
                                mode:generation::BootstrapMode::Recover {minimum},journal_root:journal_path,custody_root:pin_path,
                                journal_replay:rollover_replay.clone(),custody_replay:rollover_replay.clone(),
                                journal_io:Arc::new(HostSpoolIo),custody_io:Arc::new(HostSpoolIo),journal_limits:EffectJournalLimits::default(),custody_limits:EffectJournalLimits::default(),
                                custody_scope:ContentDigest::sha256(b"retained generation pin"),
                            }}).map_err(|_|"automatic recovery bootstrap invalid")?;
                            reopen.start(task,cx,clock,&BudgetVector::ZERO).map_err(|_|"automatic recovery admission refused")?;
                            let completion=reopen.join().await.ok_or("automatic recovery did not join")?;
                            if completion.runtime.is_err() || completion.outcome!=generation::BootstrapOutcome::Ready {return Err("automatic journal recovery refused".into());}
                            let mut reopened=reopen.retire().map_err(|_|"automatic recovery still running")?;
                            let plan=reopened.take_ready().ok_or("automatic recovered plan missing")?;
                            if plan.head()!=Some(minimum) || plan.pending()!=Some(&second) {return Err("automatic recovery changed pending generation".into());}
                            let inventory_replay=rollover_replay.clone();
                            let mut inventory_worker=fss_runtime::drained_blocking::start(cx,move |_child| {
                                let mut plan=plan;
                                let inventory=plan.inventory_page(None,2,32,&mut fss_geometry::WorkBudget::new(100_000),&inventory_replay);
                                (plan,inventory)
                            }).map_err(|_|"automatic inventory worker refused")?;
                            let receipt=inventory_worker.join().await.ok_or("automatic inventory did not drain")?;
                            if receipt.runtime.is_err() {return Err("automatic inventory runtime failed".into());}
                            let (plan,inventory)=match receipt.work {fss_runtime::drained_blocking::WorkOutcome::Finished(value)=>value,_=>return Err("automatic inventory did not finish".into())};
                            let inventory=inventory.map_err(|_|"automatic inventory refused")?;
                            if inventory.entries.len()!=2 || inventory.entries[0].identity.generation!=1 || inventory.entries[1].identity!=second
                                || inventory.entries[0].disposition!=generation::InventoryDisposition::CreatorObserved
                                || inventory.entries[1].disposition!=generation::InventoryDisposition::Pending || inventory.next.is_some() {
                                return Err("automatic inventory changed creator observation or pending reservation".into());
                            }
                            drop((auto,owners.bootstrap_retirement,retired,plan,reopened));
                            println!("automatic_creator_observation=recorded next_generation=2 second_creator_started=false same_process_reopen=verified");
                            return Ok::<bool, Box<dyn Error>>(true);
                        }
                        if bootstrap_mode == 17 {
                            let op=OperationId::parse(format!("{}:bootstrap-video-cancel",operation.as_str()))?;
                            if !matches!(Box::pin(driver.step(owner,&op,Duration::from_millis(10),task,cx,clock,admission,admission,&BudgetVector::ZERO)).await,retained::Step::BootstrapStarted) {return Err("bootstrap did not start".into());}
                            driver.abort();
                            if driver.control().is_some() || !driver.join_bootstrap().await {return Err("cancelled bootstrap did not drain".into());}
                            if !matches!(Box::pin(driver.step(owner,&op,Duration::from_millis(10),task,cx,clock,admission,admission,&BudgetVector::ZERO)).await,retained::Step::BootstrapStopped(_)) {return Err("cancelled bootstrap was advanced".into());}
                            let retirement=driver.take_bootstrap().ok_or("cancelled bootstrap retirement missing")?;
                            if !retirement.fenced {return Err("cancelled bootstrap plan not fenced".into());}
                            let owners=driver.into_parts();
                            if !owners.aborted || owners.bootstrap.is_some() || owners.bootstrap_started || owners.reservation.is_some() || owners.started {return Err("cancelled bootstrap ownership unresolved".into());}
                            let inner=owners.inner.into_parts();
                            if inner.worker.is_some() || inner.started || inner.ready.is_some() || inner.custody.is_some() {return Err("cancelled bootstrap started a creator".into());}
                            let parts=inner.managed.into_parts();
                            if parts.capacity != Some(candidate) {return Err("cancelled bootstrap lost pending video".into());}
                            drop((parts,retirement));
                            println!("retained_video_bootstrap_cancelled reservation_started=false");
                            return Ok::<bool, Box<dyn Error>>(true);
                        }
                        if bootstrap_mode == 14 {
                            let op=OperationId::parse(format!("{}:retained-video-cancel",operation.as_str()))?;
                            if !matches!(Box::pin(driver.step(owner,&op,Duration::from_millis(10),task,cx,clock,admission,admission,&BudgetVector::ZERO)).await,retained::Step::ReservationStarted) {return Err("reservation did not start".into());}
                            driver.abort();
                            if driver.control().is_some() || !driver.join_reservation().await {return Err("cancelled reservation did not drain".into());}
                            if !matches!(Box::pin(driver.step(owner,&op,Duration::from_millis(10),task,cx,clock,admission,admission,&BudgetVector::ZERO)).await,retained::Step::ReservationStopped(_)) {return Err("cancelled reservation was advanced".into());}
                            let mut retirement=driver.take_reservation().ok_or("cancelled reservation retirement missing")?;
                            if !retirement.fenced || !retirement.aborted {return Err("cancelled reservation did not fence plan".into());}
                            let unstarted=match retirement.outcome.take() {
                                Some(generation::ReservationOutcome::Reserved {identity,worker})=>Some((identity,worker)),
                                Some(generation::ReservationOutcome::ReservationRefused(refusal))=>refusal.candidate,
                                None=>None,
                                _=>return Err("unexpected cancelled reservation outcome".into()),
                            };
                            if let Some((identity,creator))=unstarted {
                                if identity.journal_root.exists() || identity.pin_root.exists() {return Err("cancelled reservation started creator".into());}
                                assert!(creator.retire().map_err(|_|"cancelled creator unexpectedly running")?.inputs.is_some());
                            }
                            let owners=driver.into_parts();
                            if !owners.aborted || owners.started || owners.reservation.is_some() || owners.retirement.is_some() {return Err("cancelled reservation ownership unresolved".into());}
                            let inner=owners.inner.into_parts();
                            if inner.worker.is_some() || inner.started || inner.ready.is_some() || inner.custody.is_some() {return Err("cancelled session started a creator".into());}
                            let parts=inner.managed.into_parts();
                            if parts.capacity != Some(candidate) {return Err("cancelled reservation lost pending video".into());}
                            drop((parts,retirement));
                            println!("retained_video_reservation_cancelled creator_started=false");
                            return Ok::<bool, Box<dyn Error>>(true);
                        }
                        let mut reserved=None; let mut started=false; let mut custody=None; let mut resumed=false;
                        let mut bootstrap_started=false; let mut bootstrap_ready=false;
                        for round in 0..2048u64 {
                            let op=OperationId::parse(format!("{}:retained-video-{round:016x}",operation.as_str()))?;
                            match Box::pin(driver.step(owner,&op,Duration::from_millis(10),task,cx,clock,admission,admission,&BudgetVector::ZERO)).await {
                                retained::Step::BootstrapStarted=>{if bootstrap_started {return Err("bootstrap started twice".into());}bootstrap_started=true;},
                                retained::Step::BootstrapReady=>{if !bootstrap_started || bootstrap_ready {return Err("bootstrap readiness ordering invalid".into());}bootstrap_ready=true;println!("retained_video_bootstrap=ready");},
                                retained::Step::ReservationStarted=>{if matches!(bootstrap_mode,16|18) && !bootstrap_ready {return Err("reservation started before bootstrap".into());}},
                                retained::Step::Reserved(identity)=>{if started || reserved.is_some(){return Err("reservation ordering invalid".into());} assert_eq!(identity.generation,1); reserved=Some(identity);},
                                retained::Step::Session(video_provision::Step::SupplyStarted)=>{if reserved.is_none(){return Err("creator started before durable reservation".into());} started=true;},
                                retained::Step::Session(video_provision::Step::SupplyInstalled(completion)) if completion.runtime.is_ok() && completion.outcome==av_rollover_supplies::Outcome::Ready => {custody=driver.take_custody();},
                                retained::Step::Session(video_provision::Step::Managed(video_session::ManagedStep::SuppliesRequired(video_session::Step::VideoRetryRequired(supervisor::Step::Idle))))=>(),
                                retained::Step::Session(video_provision::Step::Managed(video_session::ManagedStep::RolloverBeginning))=>(),
                                retained::Step::Session(video_provision::Step::Managed(video_session::ManagedStep::Rollover(video_session::AutomaticRolloverStep::Started | video_session::AutomaticRolloverStep::Rollover(video_session::RolloverStep::PreflightReady))))=>(),
                                retained::Step::Session(video_provision::Step::Managed(video_session::ManagedStep::Rollover(video_session::AutomaticRolloverStep::Rollover(video_session::RolloverStep::Control(supervisor::Step::Idle)))))=>(),
                                retained::Step::Session(video_provision::Step::Managed(video_session::ManagedStep::Resumed(receipt))) if receipt.outcome==fss_publication::RootLedgerOutcome::AlreadyLedgered => {resumed=true;break;},
                                other=>{
                                    eprintln!("retained_step_class={:?}",std::mem::discriminant(&other));
                                    if let retained::Step::Session(step)=&other {
                                        eprintln!("retained_session_class={:?}",std::mem::discriminant(step));
                                        if let video_provision::Step::Managed(managed)=step {
                                            eprintln!("retained_managed_class={:?}",std::mem::discriminant(managed));
                                            if let video_session::ManagedStep::Rollover(automatic)=managed {
                                                eprintln!("retained_automatic_class={:?}",std::mem::discriminant(automatic));
                                                if let video_session::AutomaticRolloverStep::Rollover(rollover)=automatic {
                                                    eprintln!("retained_rollover_class={:?}",std::mem::discriminant(rollover));
                                                    if let video_session::RolloverStep::Control(control)=rollover {
                                                        eprintln!("retained_control_class={:?}",std::mem::discriminant(control));
                                                    }
                                                }
                                            }
                                            if let video_session::ManagedStep::Session(video)|video_session::ManagedStep::SuppliesRequired(video)=managed {
                                                eprintln!("retained_video_class={:?}",std::mem::discriminant(video));
                                                if let video_session::Step::VideoRetryRequired(control)|video_session::Step::Supervisor(control)=video {
                                                    eprintln!("retained_control_class={:?}",std::mem::discriminant(control));
                                                }
                                            }
                                        }
                                    }
                                    if matches!(&other,retained::Step::Session(video_provision::Step::Managed(video_session::ManagedStep::Rollover(video_session::AutomaticRolloverStep::Rollover(video_session::RolloverStep::Stopped))))) {
                                        let owners=driver.into_parts();
                                        let inner=owners.inner.into_parts();
                                        let managed=inner.managed.into_parts();
                                        if let Some(video_session::ManagedOwner::Rollover(automatic))=managed.owner {
                                            if let Ok(parts)=automatic.into_rollover().into_parts() {
                                                match &parts.state {
                                                    video_session::RolloverState::PreflightStopped {completion,..} => eprintln!("retained_stopped_stage=preflight outcome={:?}",std::mem::discriminant(&completion.outcome)),
                                                    video_session::RolloverState::TransitionStopped {completion,..} => {
                                                        eprintln!("retained_stopped_stage=transition outcome={:?}",std::mem::discriminant(&completion.outcome));
                                                        if let fss_reference::unifi_direct::video_rollover_worker::Outcome::ReplayRefused {error,..}=&completion.outcome {
                                                            eprintln!("retained_replay_class={:?}",std::mem::discriminant(error));
                                                            if let fss_reference::unifi_direct::av_rollover_worker::ReplayFailure::Readback(failure)|fss_reference::unifi_direct::av_rollover_worker::ReplayFailure::Archive(failure)=error {
                                                                eprintln!("retained_archive_failure={failure:?}");
                                                            }
                                                        }
                                                    },
                                                    other=>eprintln!("retained_stopped_stage=other outcome={:?}",std::mem::discriminant(other)),
                                                }
                                            }
                                        }
                                        return Err("retained video provisioning stopped".into());
                                    }
                                    return Err("retained video provisioning stopped".into());
                                },
                            }
                        }
                        let identity=reserved.ok_or("retained reservation missing")?;
                        if !started || !resumed || custody.is_none() || (matches!(bootstrap_mode,16|18) && (!bootstrap_started || !bootstrap_ready)){return Err("retained provisioning incomplete".into());}
                        let retirement=driver.take_reservation().ok_or("retained reservation custody missing")?;
                        assert_eq!(retirement.inputs.plan.pending(),Some(&identity));
                        assert_eq!(retirement.inputs.plan.head().ok_or("retained journal head missing")?.sequence,2);
                        assert!(retirement.outcome.is_none() && !retirement.fenced);
                        let bootstrap=if matches!(bootstrap_mode,16|18) {Some(driver.take_bootstrap().ok_or("bootstrap custody missing")?)} else {None};
                        if bootstrap.as_ref().is_some_and(|value| value.fenced || value.ready.is_some() || value.outcome!=Some(generation::BootstrapOutcome::Ready)) {return Err("bootstrap custody state invalid".into());}
                        let mut first_retirement=Some(retirement);
                        if bootstrap_mode==16 {
                            let prior=first_retirement.take().ok_or("first retirement missing")?;
                            let inputs=prior.inputs;
                            let mut wrong_identity=identity.clone(); wrong_identity.generation=2;
                            let wrong=generation::ReservationWorker::new(generation::ReservationInputs {
                                plan:inputs.plan,request:generation::ReservationRequest::Reconcile {identity:wrong_identity,evidence:ContentDigest::sha256(b"synthetic caller assessed creator evidence")},
                                journal_resource:inputs.journal_resource,custody_resource:inputs.custody_resource,
                                journal_replay:inputs.journal_replay,custody_replay:inputs.custody_replay,
                            }).map_err(|_|"wrong reconciliation worker invalid")?;
                            if wrong.is_unstarted_reconciliation() {return Err("wrong generation classified as reconcilable".into());}
                            let wrong=driver.offer_reconciliation(wrong).err().ok_or("wrong generation reconciliation accepted")?;
                            let refused=wrong.retire().map_err(|_|"refused reconciliation unexpectedly running")?;
                            if refused.outcome.is_some() || refused.inputs.plan.head().map(|pin|pin.sequence)!=Some(2) || refused.inputs.plan.pending()!=Some(&identity) {return Err("refused reconciliation changed journal".into());}
                            let inputs=refused.inputs;
                            let reconcile=generation::ReservationWorker::new(generation::ReservationInputs {
                                plan:inputs.plan,request:generation::ReservationRequest::Reconcile {identity:identity.clone(),evidence:ContentDigest::sha256(b"synthetic caller assessed creator evidence")},
                                journal_resource:inputs.journal_resource,custody_resource:inputs.custody_resource,
                                journal_replay:inputs.journal_replay,custody_replay:inputs.custody_replay,
                            }).map_err(|_|"reconciliation worker invalid")?;
                            let reconcile=driver.offer_reservation(reconcile).err().ok_or("reconciliation accepted as a reservation")?;
                            driver.offer_reconciliation(reconcile).map_err(|_|"reconciliation offer refused")?;
                            let op=OperationId::parse(format!("{}:retained-reconcile",operation.as_str()))?;
                            if !matches!(Box::pin(driver.step(owner,&op,Duration::from_millis(10),task,cx,clock,admission,admission,&BudgetVector::ZERO)).await,retained::Step::ReservationStarted) {return Err("reconciliation did not start".into());}
                            if !driver.join_reservation().await {return Err("reconciliation did not drain".into());}
                            let pin=match Box::pin(driver.step(owner,&op,Duration::from_millis(10),task,cx,clock,admission,admission,&BudgetVector::ZERO)).await {
                                retained::Step::Reconciled(pin)=>pin,_=>return Err("reconciliation did not complete".into()),
                            };
                            if pin.sequence!=3 {return Err("reconciliation head changed".into());}
                            let reconciled=driver.take_reservation().ok_or("reconciliation custody missing")?;
                            if reconciled.inputs.plan.pending().is_some() || reconciled.inputs.plan.head()!=Some(pin) || reconciled.fenced {return Err("reconciliation custody invalid".into());}
                            let inputs=reconciled.inputs;
                            let mut plan=inputs.plan; plan.extend(1).map_err(|_|"second plan extension refused")?;
                            let reserve=generation::ReservationWorker::new(generation::ReservationInputs {
                                plan,request:generation::ReservationRequest::Reserve,journal_resource:inputs.journal_resource,custody_resource:inputs.custody_resource,
                                journal_replay:inputs.journal_replay,custody_replay:inputs.custody_replay,
                            }).map_err(|_|"second reservation worker invalid")?;
                            let reserve=driver.offer_reconciliation(reserve).err().ok_or("reservation accepted as reconciliation")?;
                            driver.offer_reservation(reserve).map_err(|_|"second reservation offer refused")?;
                            if !matches!(Box::pin(driver.step(owner,&op,Duration::from_millis(10),task,cx,clock,admission,admission,&BudgetVector::ZERO)).await,retained::Step::ReservationStarted) {return Err("second reservation did not start".into());}
                            if !driver.join_reservation().await {return Err("second reservation did not drain".into());}
                            let second=match Box::pin(driver.step(owner,&op,Duration::from_millis(10),task,cx,clock,admission,admission,&BudgetVector::ZERO)).await {
                                retained::Step::Reserved(identity)=>identity,_=>return Err("second reservation did not complete".into()),
                            };
                            if second.generation!=2 || second.journal_root.exists() || second.pin_root.exists() {return Err("second creator unexpectedly started".into());}
                            println!("retained_video_reconciliation=recorded next_generation=2 creator_started=false evidence=synthetic_caller_claim");
                        }
                        let owners=driver.into_parts();
                        if owners.reservation.is_some() || owners.started || (bootstrap_mode!=16 && owners.retirement.is_some()) {return Err("retained owner state unresolved".into());}
                        let mut parts=owners.inner.into_parts();
                        if bootstrap_mode==16 {
                            let retirement=owners.retirement.as_ref().ok_or("second retirement missing")?;
                            if retirement.inputs.plan.pending().map(|value|value.generation)!=Some(2) {return Err("second reservation custody invalid".into());}
                            let worker=parts.worker.take().ok_or("second creator missing")?;
                            let stopped=worker.retire().map_err(|_|"second creator unexpectedly running")?;
                            if stopped.root_created || stopped.pin_root_created || stopped.outcome.is_some() {return Err("second creator performed I/O".into());}
                        }
                        let parts=parts.managed.into_parts();
                        session=Some(match parts.owner {Some(video_session::ManagedOwner::Recording(session))=>*session,_=>return Err("retained session lost".into())});
                        drop((first_retirement,owners.retirement,custody,bootstrap));
                        rollover_count+=1; rollover_candidate=Some(candidate);
                        println!("retained_video_provisioning=verified reservation_pending=true");
                        continue;
                    },
                    video_worker::Outcome::Publication(video_worker::Publication::Refused { pending: Some(candidate), reason: video_worker::Refusal::BeforePublication(fss_reference::unifi_direct::av_worker::FailureReason::JournalCapacity) }) if bootstrap_mode == 11 && rollover_count == 0 => {
                        use fss_reference::unifi_direct::{av_rollover_generation, av_rollover_supplies, video_provision};
                        let current = session.take().ok_or("session missing for provisioning")?;
                        let managed = video_session::ManagedSession::at_capacity(current, candidate).map_err(|_| "provisioning capacity refused")?;
                        let mut plan = av_rollover_generation::Plan::new(av_rollover_generation::Configuration {
                            namespace: "video-fixture".into(), scope_seed: ContentDigest::sha256(b"video fixture scope"), first: 1, count: 1,
                            journal_replay: rollover_replay.clone(), pin_replay: rollover_replay.clone(),
                            journal_io: Arc::new(HostSpoolIo), pin_io: Arc::new(HostSpoolIo), journal_limits: EffectJournalLimits::default(), pin_limits: EffectJournalLimits::default(),
                            read: rollover_read.clone(), object_limits: archive::StagedAvLimits {max_objects:8192,max_object_bytes:64*1024*1024,max_total_bytes:128*1024*1024}, work_limit: 4_000_000_000,
                        }).map_err(|_| "video provisioning plan refused")?;
                        let (_, creator) = plan.next_worker().map_err(|_| "video provisioning generation refused")?.ok_or("video provisioning worker missing")?;
                        let mut driver = video_provision::ProvisioningSession::new(managed, creator);
                        let mut custody = None; let mut supply_started = false; let mut began = false; let mut resumed = false;
                        for round in 0..2048u64 {
                            let op = OperationId::parse(format!("{}:provision-video-{round:016x}", operation.as_str()))?;
                            match Box::pin(driver.step(owner, &op, Duration::from_millis(10), task, cx, clock, admission, admission, &BudgetVector::ZERO)).await {
                                video_provision::Step::SupplyStarted => supply_started = true,
                                video_provision::Step::SupplyInstalled(completion) if completion.runtime.is_ok() && completion.outcome == av_rollover_supplies::Outcome::Ready => { custody = driver.take_custody(); },
                                video_provision::Step::Managed(video_session::ManagedStep::SuppliesRequired(video_session::Step::VideoRetryRequired(supervisor::Step::Idle))) => (),
                                video_provision::Step::Managed(video_session::ManagedStep::RolloverBeginning) => began = true,
                                video_provision::Step::Managed(video_session::ManagedStep::Rollover(video_session::AutomaticRolloverStep::Started | video_session::AutomaticRolloverStep::Rollover(video_session::RolloverStep::PreflightReady))) => (),
                                video_provision::Step::Managed(video_session::ManagedStep::Rollover(video_session::AutomaticRolloverStep::Rollover(video_session::RolloverStep::Control(supervisor::Step::Idle)))) => (),
                                video_provision::Step::Managed(video_session::ManagedStep::Resumed(receipt)) if receipt.outcome == fss_publication::RootLedgerOutcome::AlreadyLedgered => { resumed = true; break; },
                                _ => return Err("video provisioning stopped".into()),
                            }
                        }
                        if !supply_started || !began || !resumed || custody.is_none() { return Err("video provisioning did not complete".into()); }
                        driver.set_plan(plan).map_err(|_| "video exhausted plan not installed")?;
                        let op = OperationId::parse(format!("{}:video-plan-exhausted", operation.as_str()))?;
                        if !matches!(Box::pin(driver.step(owner, &op, Duration::from_millis(10), task, cx, clock, admission, admission, &BudgetVector::ZERO)).await, video_provision::Step::PlanExhausted) { return Err("video plan exhaustion not reported".into()); }
                        assert!(driver.extend_plan(0).is_err());
                        driver.extend_plan(1).map_err(|_| "video plan renewal refused")?;
                        let renewed = match Box::pin(driver.step(owner, &op, Duration::from_millis(10), task, cx, clock, admission, admission, &BudgetVector::ZERO)).await {
                            video_provision::Step::SupplyPlanned(identity) => identity,
                            _ => return Err("renewed video generation not planned".into()),
                        };
                        assert_eq!(renewed.generation, 2);
                        assert!(driver.extend_plan(1).is_err());
                        let mut owners = driver.into_parts();
                        let planned_worker = owners.worker.take().ok_or("renewed video worker lost")?;
                        assert!(planned_worker.retire().map_err(|_| "renewed video worker unexpectedly running")?.inputs.is_some());
                        if owners.started || owners.failed.is_some() || owners.custody.is_some() || owners.ready.is_some() { return Err("video provisioning owners unresolved".into()); }
                        let parts = owners.managed.into_parts();
                        if parts.halted || parts.capacity.is_some() || parts.supplies.is_some() { return Err("provisioned session state unresolved".into()); }
                        session = Some(match parts.owner { Some(video_session::ManagedOwner::Recording(session)) => *session, _ => return Err("provisioned session missing".into()) });
                        drop(custody);
                        rollover_count += 1; rollover_candidate = Some(candidate);
                        println!("video_session_provisioned_rollover=verified");
                        continue;
                    },
                    video_worker::Outcome::Publication(video_worker::Publication::Refused { pending: Some(candidate), reason: video_worker::Refusal::BeforePublication(fss_reference::unifi_direct::av_worker::FailureReason::JournalCapacity) }) if matches!(bootstrap_mode, 5 | 6 | 7 | 8 | 9 | 12) && rollover_count == 0 => {
                        use fss_runtime::effect_journal::PinRetainedEffectJournal;
                        task.checkpoint_for(RuntimeGrant::ObjectStage, rollover_root.to_str().ok_or("rollover path")?, clock.now()?, &BudgetVector::ZERO)?;
                        let create = |name: &str| -> Result<Box<dyn fss_runtime::effect_journal::EffectJournalStore>, Box<dyn Error>> {
                            Ok(Box::new(FileEffectJournal::create(rollover_root.join(name), EffectJournalLimits::default(), Arc::new(HostSpoolIo))?))
                        };
                        let retainer = fss_object::effect_journal::FileTrustedRootPinRetainer::create(rollover_root.join("video-rollover-retainer"), EffectJournalLimits::default(), Arc::new(HostSpoolIo), ContentDigest::sha256(b"video-session-switch"))?;
                        let supplies = fss_reference::unifi_direct::av_rollover_worker::Supplies {
                            next_journal: create("video-rollover-journal")?, next_keeper: create("video-rollover-keeper")?,
                            switch: PinRetainedEffectJournal::new(create("video-rollover-switch")?, Box::new(retainer))?,
                            read: rollover_read.clone(), object_limits: archive::StagedAvLimits {max_objects:8192,max_object_bytes:64*1024*1024,max_total_bytes:128*1024*1024}, work_limit:4_000_000_000,
                        };
                        let current = session.take().ok_or("session missing for rollover")?;
                        if bootstrap_mode == 9 {
                            let wrong = archive::UnknownTimePin { root: ContentDigest::sha256(b"wrong candidate"), ..candidate };
                            let current = match video_session::ManagedSession::at_capacity(current, wrong) {
                                Err(current) => current,
                                Ok(_) => return Err("managed session accepted wrong capacity candidate".into()),
                            };
                            let managed = video_session::ManagedSession::at_capacity(current, candidate).map_err(|_| "managed capacity refused")?;
                            let mut managed = video_bootstrap::ManagedRecording::from_managed(managed);
                            if managed.authorize_source_retry() || managed.authorize_video_retry() || managed.authorize_rollover_retry() { return Err("outer owner armed a retry without a refusal".into()); }
                            if managed.control().is_none() { return Err("managed session lost controller".into()); }
                            match Box::pin(managed.step(owner, &op, Duration::from_millis(10), task, cx, clock, admission, admission)).await {
                                video_bootstrap::ManagedRecordingStep::Recording(video_session::ManagedStep::SuppliesRequired(video_session::Step::VideoRetryRequired(supervisor::Step::Idle))) => (),
                                _ => return Err("managed session did not wait for supplies".into()),
                            }
                            managed.provide(supplies).map_err(|_| "managed supplies refused")?;
                            let mut began = false; let mut starts = 0usize; let mut receipt = None;
                            for round in 0..2048u64 {
                                let op = OperationId::parse(format!("{}:managed-video-{round:016x}", operation.as_str()))?;
                                match Box::pin(managed.step(owner, &op, Duration::from_millis(10), task, cx, clock, admission, admission)).await {
                                    video_bootstrap::ManagedRecordingStep::Recording(video_session::ManagedStep::RolloverBeginning) => began = true,
                                    video_bootstrap::ManagedRecordingStep::Recording(video_session::ManagedStep::Rollover(video_session::AutomaticRolloverStep::Started)) => starts += 1,
                                    video_bootstrap::ManagedRecordingStep::Recording(video_session::ManagedStep::Rollover(video_session::AutomaticRolloverStep::Rollover(video_session::RolloverStep::PreflightReady))) => (),
                                    video_bootstrap::ManagedRecordingStep::Recording(video_session::ManagedStep::Rollover(video_session::AutomaticRolloverStep::Rollover(video_session::RolloverStep::Control(supervisor::Step::Idle)))) => (),
                                    video_bootstrap::ManagedRecordingStep::Recording(video_session::ManagedStep::Resumed(value)) => { receipt = Some(value); break; },
                                    _ => return Err("managed video rollover stopped".into()),
                                }
                            }
                            if !began || starts != 2 || receipt.as_ref().is_none_or(|value| value.outcome != fss_publication::RootLedgerOutcome::AlreadyLedgered) { return Err("managed rollover did not resume".into()); }
                            let managed = match managed.into_owner() {
                                video_bootstrap::ManagedRecordingOwner::Recording(managed) => managed,
                                _ => return Err("outer owner lost managed recording".into()),
                            };
                            let parts = managed.into_parts();
                            if parts.halted || parts.capacity.is_some() || parts.supplies.is_some() { return Err("managed rollover left pending state".into()); }
                            let resumed = match parts.owner { Some(video_session::ManagedOwner::Recording(session)) => *session, _ => return Err("managed session not returned".into()) };
                            session = Some(resumed); rollover_count += 1; rollover_candidate = Some(candidate);
                            println!("video_session_outer_managed_rollover=verified supplies_waited=true");
                            continue;
                        }
                        let mut rollover = current.begin_rollover(supplies).map_err(|_| "session rollover refused")?;
                        if rollover.control().is_none() { return Err("rollover lost controller".into()); }
                        if bootstrap_mode == 8 {
                            let mut auto = video_session::AutomaticRollover::new(rollover).map_err(|_| "automatic rollover refused")?;
                            if auto.authorize_retry() { return Err("automatic retry armed before refusal".into()); }
                            if !matches!(Box::pin(auto.step(owner, &op, Duration::ZERO, task, cx, clock, admission)).await, video_session::AutomaticRolloverStep::Rollover(video_session::RolloverStep::Context)) { return Err("automatic rollover accepted invalid wait".into()); }
                            let mut bad_cost = BudgetVector::ZERO; bad_cost.bytes = 33_000_000;
                            let bad = ArchiveAdmission { resource: admission.resource, cost: &bad_cost };
                            if !matches!(Box::pin(auto.step(owner, &op, Duration::from_millis(10), task, cx, clock, bad)).await, video_session::AutomaticRolloverStep::StartRefused(_)) { return Err("automatic rollover did not report admission refusal".into()); }
                            if !matches!(Box::pin(auto.step(owner, &op, Duration::from_millis(10), task, cx, clock, admission)).await, video_session::AutomaticRolloverStep::Rollover(video_session::RolloverStep::Control(supervisor::Step::Idle))) { return Err("automatic rollover silently retried admission".into()); }
                            if !auto.authorize_retry() || auto.authorize_retry() { return Err("automatic admission retry was not single use".into()); }
                            let mut starts = 0usize;
                            let mut ready = false;
                            for round in 0..2048u64 {
                                let op = OperationId::parse(format!("{}:automatic-rollover-{round:016x}", operation.as_str()))?;
                                match Box::pin(auto.step(owner, &op, Duration::from_millis(10), task, cx, clock, admission)).await {
                                    video_session::AutomaticRolloverStep::Started => starts += 1,
                                    video_session::AutomaticRolloverStep::Rollover(video_session::RolloverStep::PreflightReady) => (),
                                    video_session::AutomaticRolloverStep::Rollover(video_session::RolloverStep::Control(supervisor::Step::Idle)) => (),
                                    video_session::AutomaticRolloverStep::Rollover(video_session::RolloverStep::Ready) => { ready = true; break; },
                                    _ => return Err("automatic rollover stopped".into()),
                                }
                            }
                            if !ready || starts != 2 { return Err("automatic rollover did not start both stages".into()); }
                            let (mut resumed, receipt) = auto.into_rollover().resume().map_err(|_| "automatic rollover not ready")?;
                            if receipt.outcome != fss_publication::RootLedgerOutcome::AlreadyLedgered || !resumed.authorize_video_retry() { return Err("automatic video retry refused".into()); }
                            session = Some(resumed); rollover_count += 1; rollover_candidate = Some(candidate);
                            println!("video_session_automatic_rollover=verified retry_explicit=true");
                            continue;
                        }
                        match Box::pin(rollover.step(owner, &op, Duration::from_millis(10), task, cx, clock)).await {
                            video_session::RolloverStep::Control(supervisor::Step::Idle) => (),
                            _ => return Err("rollover did not service idle control".into()),
                        }
                        rollover.start(task, cx, clock, admission.resource, admission.cost).map_err(|e|format!("preflight start: {e:?}"))?;
                        if matches!(bootstrap_mode, 6 | 12) {
                            rollover.abort();
                            if rollover.control().is_some() || !matches!(rollover.start(task, cx, clock, admission.resource, admission.cost), Err(video_session::RolloverStartError::Cancelled)) { return Err("cancelled rollover accepted work".into()); }
                            let mut stopped = if bootstrap_mode == 12 { rollover.join_cancelled().await } else { false };
                            for round in 0..if stopped { 0 } else { 2048u64 } {
                                let op = OperationId::parse(format!("{}:rollover-cancel-{round:016x}", operation.as_str()))?;
                                match Box::pin(rollover.step(owner, &op, Duration::from_millis(10), task, cx, clock)).await {
                                    video_session::RolloverStep::Draining => asupersync::runtime::yield_now().await,
                                    video_session::RolloverStep::Stopped => { stopped = true; break; },
                                    _ => return Err("cancelled rollover advanced".into()),
                                }
                            }
                            if !stopped { return Err("cancelled rollover did not drain".into()); }
                            let parts = rollover.into_parts().map_err(|_| "cancelled rollover still running")?;
                            if !parts.cancelled || parts.supplies.is_none() { return Err("cancelled rollover lost policy or supplies".into()); }
                            let retirement = match parts.state {
                                video_session::RolloverState::PreflightStopped { retirement, .. } => retirement,
                                _ => return Err("cancelled preflight outcome lost".into()),
                            };
                            if !retirement.original.parts.sink.has_pending() { return Err("cancelled rollover lost pending source".into()); }
                            drop((parts.supervisor, parts.source, parts.supplies, retirement));
                            println!("video_session_cancelled_rollover=pending_source_retained joined_directly={}", bootstrap_mode == 12);
                            return Ok::<bool, Box<dyn Error>>(true);
                        }
                        let mut started_transition = false;
                        for round in 0..2048u64 {
                            let op = OperationId::parse(format!("{}:rollover-{round:016x}", operation.as_str()))?;
                            match Box::pin(rollover.step(owner, &op, Duration::from_millis(10), task, cx, clock)).await {
                                video_session::RolloverStep::Control(supervisor::Step::Idle) => (),
                                video_session::RolloverStep::PreflightReady if !started_transition => {
                                    rollover.start(task, cx, clock, admission.resource, admission.cost).map_err(|e|format!("rollover start: {e:?}"))?;
                                    started_transition = true;
                                }
                                video_session::RolloverStep::Ready if started_transition => break,
                                video_session::RolloverStep::Stopped => {
                                    let parts = rollover.into_parts().map_err(|_| "rollover stopped before draining")?;
                                    let why = match &parts.state {
                                        video_session::RolloverState::PreflightStopped { .. } => "preflight stopped".to_owned(),
                                        video_session::RolloverState::PreflightTransferRefused(_) => "preflight transfer refused".to_owned(),
                                        video_session::RolloverState::TransitionStopped { completion, .. } => match &completion.outcome {
                                            fss_reference::unifi_direct::video_rollover_worker::Outcome::ReplayRefused { error, .. } => format!("replay refused: {error:?}"),
                                            fss_reference::unifi_direct::video_rollover_worker::Outcome::BeginRefused(_) => "transition begin refused".to_owned(),
                                            fss_reference::unifi_direct::video_rollover_worker::Outcome::CommitRefused(_) => "transition commit refused".to_owned(),
                                            fss_reference::unifi_direct::video_rollover_worker::Outcome::AttachRefused { .. } => "transition prepare refused".to_owned(),
                                            _ => "other transition outcome".to_owned(),
                                        },
                                        video_session::RolloverState::AttachRefused { .. } => "attachment refused".to_owned(),
                                        _ => "other stopped state".to_owned(),
                                    };
                                    return Err(format!("rollover stopped: {why}").into());
                                },
                                video_session::RolloverStep::Control(step) => return Err(format!("rollover unexpected control: {:?}", std::mem::discriminant(&step)).into()),
                                _ => return Err("rollover driver unexpected step".into()),
                            }
                        }
                        if bootstrap_mode == 7 {
                            rollover.abort();
                            if !matches!(Box::pin(rollover.step(owner, &op, Duration::from_millis(10), task, cx, clock)).await, video_session::RolloverStep::Stopped) { return Err("cancelled ready rollover reported ready".into()); }
                            let rollover = match rollover.resume() { Err(rollover) => rollover, Ok(_) => return Err("cancelled ready rollover resumed".into()) };
                            let parts = rollover.into_parts().map_err(|_| "cancelled ready rollover still running")?;
                            if !parts.cancelled { return Err("ready cancellation flag lost".into()); }
                            match parts.state {
                                video_session::RolloverState::Ready { video, .. } if video.status() == video_worker::Status::Pending => (),
                                _ => return Err("ready cancellation lost pending video".into()),
                            }
                            drop((parts.supervisor, parts.source, parts.supplies));
                            println!("video_session_cancelled_ready=resume_refused");
                            return Ok::<bool, Box<dyn Error>>(true);
                        }
                        let (mut resumed, receipt) = rollover.resume().map_err(|_| "rollover not ready")?;
                        if receipt.outcome != fss_publication::RootLedgerOutcome::AlreadyLedgered || !resumed.authorize_video_retry() { return Err("rollover retry refused".into()); }
                        session = Some(resumed);
                        rollover_count += 1;
                        rollover_candidate = Some(candidate);
                        if video_pins.contains(&candidate) { return Err("pending candidate already published".into()); }
                    }
                    _ => return Err("video publication failed".into()),
                }
            }
            if video_pins.len() == if bootstrap_mode == 4 { 1 } else if matches!(bootstrap_mode, 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21) { 3 } else { 2 } {
                if matches!(bootstrap_mode,14|17|19|20|21) { return Err("cancelled retained branch was not reached".into()); }
                return Ok::<bool, Box<dyn Error>>(false);
            }
        }
        Err("video session step limit".into())
    }).await??;
    if cancelled { return Ok(()); }
    if let Some(managed) = managed_session {
        let parts = managed.into_parts();
        if parts.halted || parts.capacity.is_some() || parts.supplies.is_some() { return Err("managed automatic ownership incomplete".into()); }
        session = Some(match parts.owner { Some(video_session::ManagedOwner::Recording(session)) => *session, _ => return Err("managed automatic session missing".into()) });
    }
    let mut session = session.ok_or("video session not returned")?;
    if offered_sources < 2 || source_pins.len() != offered_sources || syncs == 0 || (matches!(bootstrap_mode, 5 | 8 | 9 | 10 | 11 | 13 | 15 | 16 | 18) && (rollover_count != 1 || rollover_candidate.is_some())) { return Err("source, rollover, or control accounting incomplete".into()); }
    session.abort();
    if session.control().is_some() { return Err("control available after stop".into()); }
    if session.join_source().await.is_some() || session.join_video().await.is_some() { return Err("unexpected running publication on stop".into()); }
    let parts = session.into_parts().map_err(|_| "video session did not drain")?;
    let retired = parts.supervisor.retire();
    if retired.time_sync.is_some() { return Err("clock attempt remained pending".into()); }
    let held_framing = retired.media.ingress.framing.bytes().len();
    let held_recorder = retired.media.recorder.source_bytes;
    let tail = retirement_source::Plan::new(retired.media).map_err(|refusal| format!("tail plan refused: {:?}", refusal.reason))?;
    if tail.pending_audio.is_some() || tail.recorder_fenced || tail.is_empty() { return Err("unexpected tail ownership state".into()); }
    let tail_start = tail.start.ok_or("tail start missing")?;
    let tail_end = tail.end.ok_or("tail end missing")?;
    if tail_end != tail.received { return Err("tail did not reach received offset".into()); }
    let mut tail_pins = Vec::new();
    let mut driver = retirement_source::Driver::begin(parts.source, tail, key, parts.camera_claim).map_err(|_| "tail driver refused")?;
    if driver.authorize_retry() { return Err("tail retry without pending source".into()); }
    let mut pending = None;
    let mut force_refusal = false;
    let mut awaiting_retry = false;
    let mut tail_retried = false;
    let mut unframed_count = 0usize;
    let mut bad_cost = BudgetVector::ZERO;
    bad_cost.bytes = 33_000_000;
    let bad_admission = ArchiveAdmission { resource: admission.resource, cost: &bad_cost };
    loop {
        let attempt = if force_refusal { bad_admission } else { admission };
        match Box::pin(driver.step(task, cx, clock, attempt)).await {
            retirement_source::DriverStep::Offered { offset, len, disposition } => {
                if disposition == recording::SourceDisposition::Unframed { unframed_count += 1; }
                let start = usize::try_from(offset)?;
                let bytes = expected.get(start..start.checked_add(len).ok_or("tail range overflow")?).ok_or("tail range missing")?;
                pending = Some((offset, len, ContentDigest::sha256(bytes), disposition));
                if bootstrap_mode == 3 && !tail_retried { force_refusal = true; }
            },
            retirement_source::DriverStep::StartRefused(fss_reference::unifi_direct::av_worker::StartError::Task(_)) if force_refusal => {
                force_refusal = false;
                awaiting_retry = true;
            },
            retirement_source::DriverStep::RetryRequired if awaiting_retry => {
                if !driver.authorize_retry() || driver.authorize_retry() { return Err("tail retry authorization failed".into()); }
                awaiting_retry = false;
                tail_retried = true;
            },
            retirement_source::DriverStep::Started => (),
            retirement_source::DriverStep::Completed(completion) => {
                if completion.runtime.is_err() { return Err("tail source runtime failed".into()); }
                let pin = match completion.outcome {
                    source_worker::Outcome::Publication(source_worker::Publication::Published { pin, .. }) => pin,
                    _ => return Err("tail source publication failed".into()),
                };
                let (offset, length, digest, disposition) = pending.take().ok_or("tail completion without source")?;
                tail_pins.push((pin, offset, length, digest, disposition));
            },
            retirement_source::DriverStep::Finished => break,
            _ => return Err("tail driver stopped unexpectedly".into()),
        }
    }
    if pending.is_some() || (bootstrap_mode == 3 && !tail_retried) || (!matches!(bootstrap_mode, 4 | 25 | 27) && unframed_count == 0) { return Err("tail driver did not preserve the unframed suffix or finish its retry".into()); }
    let tail_count = tail_pins.len();
    let tail_parts = driver.into_parts().map_err(|_| "tail driver did not drain")?;
    if !tail_parts.plan.is_empty() { return Err("tail driver left unoffered source".into()); }
    let source = tail_parts.worker.retire().map_err(|_| "source worker did not retire")?;
    if source.fenced || source.pending.is_some() { return Err("source custody unresolved".into()); }
    let mut source = source.parts;
    for pin in source_pins {
        let record = archive::read_unknown_time_source(&mut source.deployment, pin, access, archive::Limits::default(), &mut fss_geometry::WorkBudget::new(4_000_000_000), &source.replay)?;
        let start = usize::try_from(record.offset())?;
        let end = start.checked_add(record.bytes().len()).ok_or("source offset overflow")?;
        if expected.get(start..end) != Some(record.bytes()) { return Err("source bytes changed".into()); }
    }
    for (pin, offset, length, digest, disposition) in tail_pins {
        let record = archive::read_unknown_time_source(&mut source.deployment, pin, access, archive::Limits::default(), &mut fss_geometry::WorkBudget::new(4_000_000_000), &source.replay)?;
        if record.offset() != offset || record.bytes().len() != length || ContentDigest::sha256(record.bytes()) != digest || record.disposition() != disposition { return Err("tail source readback changed".into()); }
    }
    let video = parts.video.retire().map_err(|_| "video worker did not retire")?;
    if video.fenced || video.report.is_some() { return Err("video worker fenced".into()); }
    let mut video = video.parts;
    for pin in video_pins {
        let clip = archive::read_unknown_time_video_clip(&mut video.deployment, pin, access, archive::Limits::default(), &mut fss_geometry::WorkBudget::new(4_000_000_000), &video.replay)?;
        if clip.claimed_source() != key || clip.samples() == 0 { return Err("video source readback failed".into()); }
        if bootstrap_mode == 4 {
            let movie = AvcMp4::parse_inband(clip.bytes(), None, DemuxLimits::default())?;
            let annex = movie.annex_b(0, movie.samples().len().min(3))?;
            let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
            let mut frames = decoder.decode_annex_b(annex.bytes())?;
            frames.extend(decoder.finish()?);
            let frame = frames.first().ok_or("private session video decode missing")?;
            if (frame.width(), frame.height()) != (2688, 1512) { return Err("private session video resolution mismatch".into()); }
            println!("private_bootstrap_replay=passed width={} height={} frames={} held_framing_bytes={held_framing} held_recorder_bytes={held_recorder} capture_bounds=unknown full_coverage=unproven", frame.width(), frame.height(), frames.len());
        }
        if matches!(bootstrap_mode,15|18) {
            let movie=AvcMp4::parse_inband(clip.bytes(),None,DemuxLimits::default())?;
            let annex=movie.annex_b(0,1)?;
            let mut decoder=fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
            let mut frames=decoder.decode_annex_b(annex.bytes())?;
            frames.extend(decoder.finish()?);
            let frame=frames.first().ok_or("private retained video decode missing")?;
            if (frame.width(),frame.height())!=(1280,720) {return Err("private retained video resolution mismatch".into());}
            println!("retained_private_decoded width={} height={} frames={} decode_scope=fragment_idr capture_bounds=unknown",frame.width(),frame.height(),frames.len());
        }
    }
    let retired_sink = video.sink.retire();
    if retired_sink.pending.is_some() || retired_sink.pending_pin.is_some() { return Err("video source left pending".into()); }
    if matches!(bootstrap_mode, 24 | 25 | 26 | 27) {
        use fss_reference::unifi_direct::recording_storage::{self, HistoryMinimum, Retainers};
        use fss_runtime::effect_journal::EffectPinRetainer;
        struct Deny;
        impl archive::ReadAuthority for Deny { fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool { false } }
        let source_minimum = HistoryMinimum { journal: source.journal.anchor(), keeper: source.keeper.anchor() };
        let video_minimum = HistoryMinimum { journal: video.journal.anchor(), keeper: video.keeper.anchor() };
        let video_pin = video.journal.confirmed().ok_or("video root missing")?;
        let objects = archive::StagedAvLimits { max_objects: 8192, max_object_bytes: 64 * 1024 * 1024, max_total_bytes: 256 * 1024 * 1024 };
        assert_eq!(archive::verify_settled_unknown_time_video_anchored(&mut video.deployment, access, retain.as_ref(), archive::Limits::default(), objects, &mut fss_geometry::WorkBudget::new(4_000_000_000), &video.replay, &video.journal, &video.keeper)?, video_pin);
        assert!(archive::verify_settled_unknown_time_av_anchored(&mut video.deployment, access, retain.as_ref(), archive::Limits::default(), objects, &mut fss_geometry::WorkBudget::new(4_000_000_000), &video.replay, &video.journal, &video.keeper).is_err());
        drop(retired_sink);
        drop(source);
        drop(video.deployment);
        drop(video.journal);
        drop(video.keeper);
        let witness = rollover_root.join("witness");
        let open = |name: &str| -> Result<Box<dyn EffectPinRetainer>, Box<dyn Error>> {
            Ok(Box::new(fss_object::effect_journal::FileTrustedRootPinRetainer::open_trusting_storage(witness.join(name), EffectJournalLimits::default(), Arc::new(HostSpoolIo), ContentDigest::sha256(format!("owned-witness:{name}").as_bytes()))?))
        };
        let retainers = Retainers { source_journal: open("source-journal")?, source_keeper: open("source-keeper")?, av_journal: open("av-journal")?, av_keeper: open("av-keeper")? };
        let source_replay = fss_reference::ReplayCx::from_context_authority(replay_authority, rollover_root.to_path_buf())?;
        let video_replay = fss_reference::ReplayCx::from_context_authority(replay_authority, rollover_root.to_path_buf())?;
        let recovered = recording_storage::recover_histories_retained(task, cx, clock, storage_cfg, source_minimum, video_minimum, source_replay, video_replay, retainers)?;
        let recovered = if matches!(bootstrap_mode, 26 | 27) {
            use archive::journal::rollover::{Previous, RecoveredLineage, Staged};
            use fss_runtime::effect_journal::PinRetainedEffectJournal;
            let (old_source, mut video_history, prior_custody) = recovered.into_histories();
            assert!(prior_custody.is_none());
            drop(old_source);
            let mut deployment = fss_reference::ReferenceDeployment::open_with_limits(&storage_cfg.root.join("av"), storage_cfg.site_lineage, storage_cfg.av_deployment_limits, &video_history.replay)?;
            let receipt = archive::replay_confirmed_unknown_time_video_anchored(&mut deployment, access, retain.as_ref(), archive::Limits::default(), objects, &mut fss_geometry::WorkBudget::new(4_000_000_000), &video_history.replay, &mut video_history.journal, &mut video_history.keeper)?;
            assert_eq!(receipt.outcome, fss_publication::RootLedgerOutcome::AlreadyLedgered);
            let recording_storage::RecoveredHistory { journal, keeper, replay: video_replay } = video_history;
            let make_store = |name: &str| -> Result<Box<dyn fss_runtime::effect_journal::EffectJournalStore>, Box<dyn Error>> {
                let file = FileEffectJournal::create(storage_cfg.root.join(name), EffectJournalLimits::default(), Arc::new(HostSpoolIo))?;
                let pin = fss_object::effect_journal::FileTrustedRootPinRetainer::create(witness.join(name), EffectJournalLimits::default(), Arc::new(HostSpoolIo), ContentDigest::sha256(format!("owned-witness:{name}").as_bytes()))?;
                Ok(Box::new(PinRetainedEffectJournal::new(Box::new(file), Box::new(pin))?))
            };
            let staged = Staged::begin(Previous { journal, keeper }, make_store("rolled-video-journal")?, make_store("rolled-video-keeper")?, &video_replay).map_err(|_| "video rollover staging refused")?;
            let file = FileEffectJournal::create(storage_cfg.root.join("rolled-video-switch"), EffectJournalLimits::default(), Arc::new(HostSpoolIo))?;
            let pin = fss_object::effect_journal::FileTrustedRootPinRetainer::create(witness.join("rolled-video-switch"), EffectJournalLimits::default(), Arc::new(HostSpoolIo), ContentDigest::sha256(b"owned-witness:rolled-video-switch"))?;
            let switch = PinRetainedEffectJournal::new(Box::new(file), Box::new(pin))?;
            let mut active = staged.commit(switch, &video_replay).map_err(|_| "video rollover switch refused")?;
            let receipt = active.replay_confirmed_video(&mut deployment, access, retain.as_ref(), archive::Limits::default(), objects, &mut fss_geometry::WorkBudget::new(4_000_000_000), &video_replay)?;
            assert_eq!(receipt.outcome, fss_publication::RootLedgerOutcome::AlreadyLedgered);
            let lineage: RecoveredLineage = active.into_recovered_lineage(&video_replay).map_err(|_| "video rollover lineage refused")?;
            assert_eq!(lineage.transition_count(), 1);
            drop(deployment);
            let source_replay = fss_reference::ReplayCx::from_context_authority(replay_authority, rollover_root.to_path_buf())?;
            let source = recording_storage::recover_source_retained(task, cx, clock, storage_cfg, source_minimum, source_replay, &video_replay, recording_storage::SourceRetainers { journal: open("source-journal")?, keeper: open("source-keeper")? })?;
            recording_storage::join_source_and_av_lineage(storage_cfg, source, lineage, video_replay).map_err(|_| "video rollover lineage join refused")?
        } else { recovered };
        let next = recording_storage::Configuration { source: SourceKey { connection: 2, generation: 1 }, ..storage_cfg };
        let refused = recording_storage::resume_confirmed(task, cx, clock, next, recovered, access, retain.clone(), objects).err().ok_or("A/V profile accepted video graph")?;
        assert!(matches!(refused.reason, recording_storage::Error::AvReadback));
        let refused = recording_storage::resume_confirmed_video(task, cx, clock, next, refused.histories, &Deny, retain.clone(), objects).err().ok_or("denied restart accepted")?;
        let mut resumed = recording_storage::resume_confirmed_video(task, cx, clock, next, refused.histories, access, retain.clone(), objects).map_err(|_| "video graph restart refused")?;
        assert_eq!(resumed.boundary().previous, key);
        assert_eq!(resumed.boundary().next, next.source);
        assert_eq!(resumed.boundary().av_root, video_pin);
        let plan = resumed.prepare_boundary()?;
        let custody_path = witness.join("video-restart-boundary-journal");
        let store = FileEffectJournal::create(&custody_path, EffectJournalLimits::default(), Arc::new(HostSpoolIo))?;
        let retainer = fss_object::effect_journal::FileTrustedRootPinRetainer::create(witness.join("video-restart-boundary-retainer"), EffectJournalLimits::default(), Arc::new(HostSpoolIo), ContentDigest::sha256(b"video restart boundary retainer"))?;
        let wrapped = fss_runtime::effect_journal::PinRetainedEffectJournal::new(Box::new(store), Box::new(retainer))?;
        let replay = fss_reference::ReplayCx::from_context_authority(replay_authority, rollover_root.to_path_buf())?;
        let mut custody = recording_storage::boundary::Custody::create(wrapped, &plan, custody_path.to_str().ok_or("boundary path")?.to_string(), replay, task, cx, clock)?;
        let receipt = resumed.publish_boundary(&plan, &mut custody, task, cx, clock, access, &mut fss_geometry::WorkBudget::new(1_000_000_000))?;
        assert_eq!(receipt.root, plan.pin().root);
        let owners = resumed.into_owners(&plan, &mut custody, task, cx, clock, access, &mut fss_geometry::WorkBudget::new(1_000_000_000)).map_err(|_| "video boundary verification refused")?;

        let bind = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
        let control = controller_listener::Listener::bind(task, cx, clock, admission_policy, bind, "fixture:camera", Duration::from_secs(5)).await?;
        let address = SocketAddr::V4(control.local_addr());
        let wire = expected.to_vec();
        let peer = std::thread::spawn(move || -> io::Result<()> {
            let mut socket = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
            socket.set_read_timeout(Some(Duration::from_secs(90)))?;
            let mut request = HEAD.as_bytes().to_vec(); request.extend(frame(HELLO)); socket.write_all(&request)?;
            let mut header = Vec::new(); let mut byte = [0u8; 1];
            while !header.ends_with(b"\r\n\r\n") { socket.read_exact(&mut byte)?; header.push(byte[0]); if header.len() > 4096 { return Err(io::Error::other("upgrade limit")); } }
            if !header.starts_with(b"HTTP/1.1 101 ") { return Err(io::Error::other("upgrade refused")); }
            if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_hello".len()).any(|w| w == b"ubnt_avclient_hello") { return Err(io::Error::other("hello reply")); }
            socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":10}"#))?;
            if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_timeSync".len()).any(|w| w == b"ubnt_avclient_timeSync") { return Err(io::Error::other("startup clock reply")); }
            if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_paramAgreement".len()).any(|w| w == b"ubnt_avclient_paramAgreement") { return Err(io::Error::other("agreement")); }
            socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_paramAgreement","messageId":8,"inResponseTo":3}"#))?;
            let request = receive_binary(&mut socket)?; let text = std::str::from_utf8(&request).map_err(io::Error::other)?;
            let destination: SocketAddr = text.split_once("tcp://").and_then(|(_,s)| s.split_once('?')).map(|(s,_)| s).ok_or_else(|| io::Error::other("stream destination"))?.parse().map_err(io::Error::other)?;
            if !matches!(destination, SocketAddr::V4(addr) if addr.ip().is_loopback() && addr.port()!=0) { return Err(io::Error::other("stream destination scope")); }
            socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ChangeVideoSettings","messageId":9,"inResponseTo":4}"#))?;
            let mut media = std::net::TcpStream::connect_timeout(&destination, Duration::from_secs(5))?; media.set_write_timeout(Some(Duration::from_secs(90)))?;
            let split = wire.len().min(100); media.write_all(&wire[..split])?;
            socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":11}"#))?;
            if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_timeSync".len()).any(|w| w == b"ubnt_avclient_timeSync") { return Err(io::Error::other("live clock reply")); }
            let writer = std::thread::spawn(move || media.write_all(&wire[split..]));
            let closed = matches!(socket.read(&mut byte), Ok(0));
            match writer.join().map_err(|_| io::Error::other("media writer panic"))? { Ok(()) => (), Err(error) if closed && matches!(error.kind(), io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset) => (), Err(error) => return Err(error) }
            if closed { Ok(()) } else { Err(io::Error::other("controller did not retire")) }
        });
        let operations = [OperationId::parse("operation:video-restart-hello")?, OperationId::parse("operation:video-restart-agreement")?, OperationId::parse("operation:video-restart-stream")?, OperationId::parse("operation:video-restart-clock-startup")?, OperationId::parse("operation:video-restart-clock-live")?];
        let management = Preconditions { session_generation: 2, ..management };
        let stream = intent::Preconditions { stream_generation: 2, ..stream };
        let (io, gate) = control.accept(4096, Duration::from_secs(5)).await?;
        let controller = Controller::new(Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?, 1)?;
        let mut session = owner::accept_guarded(io, ProtocolPolicy::RequireOffer, &FixtureAdmission, gate, controller, Duration::from_secs(5)).await?;
        let start = listener::Start { bind, resource: "fixture:camera", admission: admission_policy, channel: VideoChannel::Video2, video: VideoCodec::H264, audio: AudioCodec::Aac, stream_name: "0123456789abcdef", hello: &operations[0], agreement: &operations[1], stream: &operations[2], time_sync: &operations[3..4], management, stream_conditions: stream, chunk_bytes: 4096, max_bytes: u64::try_from(expected.len())? + 1, bind_wait: Duration::from_secs(5), conversation_wait: Duration::from_secs(5), accept_wait: Duration::from_secs(5) };
        let framer = Framer::with_mode(FlvLimits::default(), fss_packet::extended_flv::stream::MAX_BUFFER_BYTES, SearchMode::ZeroStreamId)?;
        let recorder = if matches!(bootstrap_mode, 25 | 27) { recording::Recorder::new_inband(next.source, recording::Limits::default())? } else { recording::Recorder::new(next.source, recording::Limits::default())? };
        let mut trace = listener::StartTrace::default();
        let started = listener::start_tracked(owner, &mut session, &start, framer, recorder, &mut trace).await?;
        let supervisor = supervisor::Supervisor::new(session, started.pipeline, management);
        let recording_storage::Created { coordinator, av: resources } = owners;
        Box::pin(drive_video_only_session(supervisor, coordinator, resources, expected, owner, &operations[4], access, rollover_read, rollover_root, rollover_replay, task, cx, clock, if matches!(bootstrap_mode, 25 | 27) { 4 } else { 2 }, next, replay_authority, retain, management, stream, admission_policy)).await?;
        peer.join().map_err(|_| "restart peer panic")??;
        println!("video_graph_restart=passed exact_profile=true wrong_profile_refused=true denied_read_refused=true new_connection_archived=true");
        return Ok(());
    }
    println!("video_session_loopback=passed sources={offered_sources} video_segments={} tail_records={tail_count} unframed_records={unframed_count} tail_start={tail_start} tail_end={tail_end} audio_samples=0 capture_bounds=unknown", if bootstrap_mode == 4 { 1 } else if matches!(bootstrap_mode, 5 | 8 | 9 | 10 | 11 | 13 | 15 | 16 | 18) { 3 } else { 2 });
    Ok(())
}

#[test]
#[ignore = "invoked by the bounded separate-process boundary fixture"]
fn owned_boundary_child_reader() -> Test {
    use fss_reference::unifi_direct::{archive,recording_storage::boundary};
    use fss_runtime::effect_journal::{EffectJournalPin,PinRetainedEffectJournal};
    struct Access;
    impl archive::ReadAuthority for Access {fn permits(&self,_:ContentDigest,_:ContentDigest)->bool{true}}
    impl archive::RetainAuthority for Access {fn permits(&self,_:ContentDigest,_:ContentDigest)->bool{true}}
    let root=PathBuf::from(std::env::var("FSS_TEST_BOUNDARY_ROOT")?);
    let expected_head=EffectJournalPin {sequence:1,root:ContentDigest::parse(std::env::var("FSS_TEST_BOUNDARY_HEAD")?)?};
    let expected_root=ContentDigest::parse(std::env::var("FSS_TEST_BOUNDARY_PIN")?)?;
    let expected_retention=ContentDigest::parse(std::env::var("FSS_TEST_BOUNDARY_RETENTION")?)?;
    let replay_authority=fss_core::region::ContextAuthority::new_root(RootAuthoritySpec {trace_id:"trace:boundary-child-replay".into(),operation_id:OperationId::parse("operation:boundary-child-replay")?,principal:"principal:fixture".into(),capabilities:vec!["ADP-REPLAY-001".into()],deadline:None,priority:1,budgets:BudgetVector::builder().bytes(64*1024*1024).build()?,privacy_scope:"privacy:test".into(),retention_scope:"retention:test".into(),anchor_universe:ContentDigest::sha256(b"boundary child fixture"),generation:1})?;
    let mut budget=BudgetVector::ZERO;budget.bytes=64*1024*1024;
    let (mut authority,mut tree)=AuthorityCx::root(RootAuthoritySpec {trace_id:"trace:boundary-child".into(),operation_id:OperationId::parse("operation:boundary-child")?,principal:"principal:fixture".into(),capabilities:vec![RuntimeGrant::ObjectStage.as_str().into(),RuntimeGrant::ObjectPublish.as_str().into(),RuntimeGrant::ReadMedia.as_str().into()],deadline:Some(TimestampNs(60_000_000_000)),priority:1,budgets:budget,privacy_scope:"privacy:test".into(),retention_scope:"retention:test".into(),anchor_universe:ContentDigest::sha256(b"boundary child fixture"),generation:1},RegionId::new("region:boundary-child")?,RegionKind::Process,budget,TimestampNs(1))?;
    let runtime=RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx=asupersync::Cx::current().ok_or("missing runtime")?;
        let result=run_owned_async(&mut authority,&mut tree,TaskSpec {task_id:TaskId::new("task:boundary-child")?,started_at:TimestampNs(3)},&cx,async |task,cx| {
            let clock=MeteredClock::new(task,cx,TimestampNs(4)).expect("fixture clock");
            let output=(|| -> Test {
                let witness=root.join("witness");let journal_path=witness.join("boundary-journal");
                task.checkpoint_for(RuntimeGrant::ObjectStage,journal_path.to_str().ok_or("journal path")?,clock.now()?,&BudgetVector::ZERO)?;
                let store=FileEffectJournal::open(&journal_path,EffectJournalLimits::default(),Arc::new(HostSpoolIo),expected_head)?;
                let retainer=fss_object::effect_journal::FileTrustedRootPinRetainer::open_trusting_storage(witness.join("boundary-retainer"),EffectJournalLimits::default(),Arc::new(HostSpoolIo),ContentDigest::sha256(b"owned-witness:boundary-retainer"))?;
                let wrapped=PinRetainedEffectJournal::for_reconciliation(Box::new(store),Box::new(retainer))?;
                let replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,root.clone())?;
                let custody=boundary::Custody::reopen(wrapped,journal_path.to_str().ok_or("journal path")?.to_string(),replay,task,cx,clock)?;
                if custody.head()!=expected_head || custody.plan().pin()!=(boundary::Pin {root:expected_root,retention:expected_retention}) {return Err("boundary child pin mismatch".into());}
                let replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,root.clone())?;
                let mut deployment=fss_reference::ReferenceDeployment::open_with_limits(&root.join("owned-storage/av"),"site:owned-replay",owned_av_limits(),&replay)?;
                boundary::verify_retained(&mut deployment,&replay,&Access,custody.plan(),task,cx,clock,&Access,&mut fss_geometry::WorkBudget::new(1_000_000_000))?;
                println!("owned_boundary_child=verified");
                Ok(())
            })();
            let outcome=if output.is_ok(){TaskOutcome::Success}else{TaskOutcome::Failed("boundary child refused".into())};
            TaskCompletion {output,outcome,completed_at:TimestampNs(59_000_000_000)}
        }).await?;
        result.receipt?;result.output
    })
}

#[test]
fn owned_boundary_survives_writer_process_exit() -> Test {
    use std::{os::unix::fs::DirBuilderExt,process::{Command,Stdio}};
    let root=std::env::temp_dir().join(format!("fss-boundary-process-{}",std::process::id()));
    std::fs::DirBuilder::new().mode(0o700).create(&root)?;
    let root=std::fs::canonicalize(root)?;let _temp=Temp(root.clone());
    let exe=std::env::current_exe()?;
    let writer=Command::new(&exe).arg("owned_session_camera_fixture_stack_control").arg("--exact").arg("--nocapture").arg("--test-threads=1")
        .env("TMPDIR",&root).env("FSS_TEST_PRESERVE_BOUNDARY","1").stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let writer_pid=writer.id();let output=writer.wait_with_output()?;
    if !output.status.success() || !String::from_utf8_lossy(&output.stdout).contains("owned_restart=second_connection_archived") {return Err(format!("boundary writer failed: {}",String::from_utf8_lossy(&output.stderr)).into());}
    let writer_root=root.join(format!("fss-unifi-owned-replay-{writer_pid}"));
    let receipt=std::fs::read_to_string(writer_root.join("boundary-test-receipt"))?;
    if receipt.len()>1024{return Err("boundary receipt exceeded bound".into());}
    let fields:Vec<_>=receipt.lines().collect();if fields.len()!=3{return Err("boundary receipt shape".into());}
    let run=|head:&str,pin:&str| -> io::Result<std::process::Output> {
        Command::new(&exe).arg("owned_boundary_child_reader").arg("--ignored").arg("--exact").arg("--nocapture").arg("--test-threads=1")
            .env("FSS_TEST_BOUNDARY_ROOT",&writer_root).env("FSS_TEST_BOUNDARY_HEAD",head)
            .env("FSS_TEST_BOUNDARY_PIN",pin).env("FSS_TEST_BOUNDARY_RETENTION",fields[2]).output()
    };
    let child=run(fields[0],fields[1])?;
    if !child.status.success() || !String::from_utf8_lossy(&child.stdout).contains("owned_boundary_child=verified") {return Err(format!("boundary child failed: {}",String::from_utf8_lossy(&child.stderr)).into());}
    let wrong=ContentDigest::sha256(b"wrong boundary pin").to_text();
    if run(fields[0],&wrong)?.status.success() || run(&wrong,fields[1])?.status.success() {return Err("wrong boundary pin or custody head accepted".into());}
    println!("owned_boundary_process=writer_exited_reader_verified wrong_pins_refused=true");
    Ok(())
}

/// Focused owned-session replay. The synthetic peer only supplies transport;
/// the caller's bounded FLV bytes remain the source used for archive checks.
fn lean_owned_session_replay(wire: Vec<u8>, test_refusal: bool, require_distinct: bool, initial_video_only: bool, video_session: u8) -> Test {
    static NEXT_SCENARIO: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let scenario=NEXT_SCENARIO.fetch_add(1,std::sync::atomic::Ordering::Relaxed);
    let path=std::fs::canonicalize(std::env::temp_dir())?.join(format!("fss-unifi-owned-replay-{}-{scenario}",std::process::id()));
    std::fs::create_dir(&path)?;let temp=Temp(path);
    let store=FileEffectJournal::create(temp.0.join("effects"),EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
    let mut effects=EffectCoordinator::with_journal(Box::new(store))?;
    let mut budget=BudgetVector::ZERO;budget.network_bytes=32_000_000;budget.bytes=32_000_000;
    let (mut authority,mut tree)=AuthorityCx::root(RootAuthoritySpec {
        trace_id:"trace:owned-replay".into(),operation_id:OperationId::parse("operation:owned-replay-owner")?,principal:"principal:fixture".into(),
        capabilities:vec![RuntimeGrant::AdapterNet.as_str().into(),RuntimeGrant::CameraManagementPrepare.as_str().into(),RuntimeGrant::CameraManagementCommit.as_str().into(),RuntimeGrant::CameraSettingPrepare.as_str().into(),RuntimeGrant::CameraSettingCommit.as_str().into(),RuntimeGrant::ReadMedia.as_str().into(),RuntimeGrant::ObjectStage.as_str().into(),RuntimeGrant::ObjectPublish.as_str().into()],
        deadline:Some(TimestampNs(60_000_000_000)),priority:1,budgets:budget,privacy_scope:"privacy:test".into(),retention_scope:"retention:test".into(),anchor_universe:ContentDigest::sha256(b"owned replay fixture"),generation:1,
    },RegionId::new("region:owned-replay")?,RegionKind::Process,budget,TimestampNs(1))?;
    let camera=ContentDigest::sha256(b"verified fixture camera");let resource=format!("camera:{}",camera.to_text());
    let mut leases=LeaseRegistry::new();let fence=leases.acquire(&resource,authority.region().as_str(),None,TimestampNs(2))?.fence;let leases=RefCell::new(leases);
    let management=Preconditions {camera,peer_admission:ContentDigest::sha256(b"fixture admission"),session_generation:1,previous_association:None,previous_clock:None,lease_fence:fence};
    let stream=intent::Preconditions {camera,peer_admission:management.peer_admission,stream_generation:1,previous_settings:None,lease_fence:fence};
    let operations=[OperationId::parse("operation:lean-hello")?,OperationId::parse("operation:lean-agreement")?,OperationId::parse("operation:lean-stream")?,OperationId::parse("operation:lean-clock-startup")?,OperationId::parse("operation:lean-clock-live")?];
    let runtime=RuntimeBuilder::current_thread().blocking_threads(1,1).build()?;
    runtime.block_on(async {
        let cx=asupersync::Cx::current().ok_or("missing runtime")?;
        let result=run_owned_async(&mut authority,&mut tree,TaskSpec {task_id:TaskId::new("task:owned-replay")?,started_at:TimestampNs(3)},&cx,async |task,cx| {
            let output=Box::pin(lean_owned_session_task(task,cx,&mut effects,&leases,management,stream,&operations,&temp.0,wire,test_refusal,require_distinct,initial_video_only,video_session)).await;
            let outcome=if output.is_ok(){TaskOutcome::Indeterminate("fixture effects require reconciliation".into())}else{TaskOutcome::Failed("owned replay failed".into())};
            TaskCompletion {output,outcome,completed_at:TimestampNs(59_000_000_000)}
        }).await?;
        result.receipt?;result.output
    })?;
    for operation in &operations[..4] {
        assert_eq!(effects.journal().operation(operation).ok_or("startup effect missing")?.state,fss_core::EffectState::Committed);
    }
    assert!(!authority.finalize_report(&tree)?.is_empty());
    if std::env::var("FSS_TEST_PRESERVE_BOUNDARY").as_deref()==Ok("1") {std::mem::forget(temp);}
    Ok(())
}

async fn lean_owned_session_task<'scope,'task>(
    task:&'scope fss_runtime::execution::TaskCx<'task>,cx:&'scope asupersync::Cx,
    effects:&mut EffectCoordinator,leases:&RefCell<LeaseRegistry>,management:Preconditions,
    stream:intent::Preconditions,operations:&[OperationId],temp:&std::path::Path,wire:Vec<u8>,test_refusal:bool,require_distinct:bool,initial_video_only:bool,video_session:u8,
) -> Test {
    use fss_reference::unifi_direct::{archive,av_bootstrap,av_bootstrap_driver,av_owned_sink,recording_storage};
    struct Retention;
    impl archive::RetainAuthority for Retention {fn permits(&self,_:ContentDigest,_:ContentDigest)->bool{true}}
    impl archive::ReadAuthority for Retention {fn permits(&self,_:ContentDigest,_:ContentDigest)->bool{true}}
    struct Deny;
    impl archive::RetainAuthority for Deny {fn permits(&self,_:ContentDigest,_:ContentDigest)->bool{false}}
    impl archive::ReadAuthority for Deny {fn permits(&self,_:ContentDigest,_:ContentDigest)->bool{false}}
    #[derive(Debug)] struct RejectRetain;
    impl fss_runtime::effect_journal::EffectPinRetainer for RejectRetain {
        fn retained_pin(&mut self)->Result<Option<fss_runtime::effect_journal::EffectJournalPin>,fss_runtime::effect_journal::EffectPersistenceError>{Ok(None)}
        fn reserve_capacity(&mut self,_:usize)->Result<(),fss_runtime::effect_journal::EffectPersistenceError>{Ok(())}
        fn verify_effect_history(&mut self,_:&dyn fss_runtime::effect_journal::EffectJournalStore)->Result<(),fss_runtime::effect_journal::EffectPersistenceError>{Ok(())}
        fn retain(&mut self,_:Option<fss_runtime::effect_journal::EffectJournalPin>,_:fss_runtime::effect_journal::EffectJournalPin)->Result<(),fss_runtime::effect_journal::EffectPersistenceError>{Err(fss_runtime::effect_journal::EffectPersistenceError::Storage("fixture custody failure".into()))}
    }
    let clock=MeteredClock::new(task,cx,TimestampNs(4))?;
    let policy=FixtureMediaAdmission {listen:Cell::new(true),peer:Cell::new(true)};
    let bind=SocketAddrV4::new(Ipv4Addr::LOCALHOST,0);
    let control=controller_listener::Listener::bind(task,cx,clock,&policy,bind,"fixture:camera",Duration::from_secs(5)).await?;
    let address=SocketAddr::V4(control.local_addr());let expected=wire.clone();
    let peer=std::thread::spawn(move || -> io::Result<()> {
        let mut socket=std::net::TcpStream::connect_timeout(&address,Duration::from_secs(5))?;socket.set_read_timeout(Some(Duration::from_secs(if matches!(video_session, 4 | 25 | 27) { 90 } else { 10 })))?;
        let mut request=HEAD.as_bytes().to_vec();request.extend(frame(HELLO));socket.write_all(&request)?;
        let mut header=Vec::new();let mut byte=[0u8;1];while !header.ends_with(b"\r\n\r\n"){socket.read_exact(&mut byte)?;header.push(byte[0]);if header.len()>4096{return Err(io::Error::other("upgrade limit"));}}
        if !header.starts_with(b"HTTP/1.1 101 "){return Err(io::Error::other("upgrade refused"));}
        if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_hello".len()).any(|w|w==b"ubnt_avclient_hello"){return Err(io::Error::other("hello reply"));}
        socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":10}"#))?;
        if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_timeSync".len()).any(|w|w==b"ubnt_avclient_timeSync"){return Err(io::Error::other("startup clock reply"));}
        if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_paramAgreement".len()).any(|w|w==b"ubnt_avclient_paramAgreement"){return Err(io::Error::other("agreement"));}
        socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_paramAgreement","messageId":8,"inResponseTo":3}"#))?;
        let request=receive_binary(&mut socket)?;let text=std::str::from_utf8(&request).map_err(io::Error::other)?;
        let destination:SocketAddr=text.split_once("tcp://").and_then(|(_,s)|s.split_once('?')).map(|(s,_)|s).ok_or_else(||io::Error::other("stream destination"))?.parse().map_err(io::Error::other)?;
        if !matches!(destination,SocketAddr::V4(addr) if addr.ip().is_loopback() && addr.port()!=0){return Err(io::Error::other("stream destination scope"));}
        socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ChangeVideoSettings","messageId":9,"inResponseTo":4}"#))?;
        let mut media=std::net::TcpStream::connect_timeout(&destination,Duration::from_secs(5))?;media.set_write_timeout(Some(Duration::from_secs(if matches!(video_session, 4 | 25 | 27) { 90 } else { 10 })))?;
        let split=wire.len().min(100);media.write_all(&wire[..split])?;
        socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":11}"#))?;
        if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_timeSync".len()).any(|w|w==b"ubnt_avclient_timeSync"){return Err(io::Error::other("live clock reply"));}
        let writer=std::thread::spawn(move || media.write_all(&wire[split..]));
        let closed=matches!(socket.read(&mut byte),Ok(0));
        match writer.join().map_err(|_|io::Error::other("media writer panic"))? {
            Ok(())=>(),Err(error) if closed && matches!(error.kind(),io::ErrorKind::BrokenPipe|io::ErrorKind::ConnectionReset)=>(),Err(error)=>return Err(error),
        }
        if closed{Ok(())}else{Err(io::Error::other("controller did not retire"))}
    });
    let (io,gate)=control.accept(4096,Duration::from_secs(5)).await?;
    let controller=Controller::new(Identity::new("FSS","12345678-1234-4abc-9abc-123456789abc","1.20.0")?,1)?;
    let mut session=owner::accept_guarded(io,ProtocolPolicy::RequireOffer,&FixtureAdmission,gate,controller,Duration::from_secs(5)).await?;
    let guard=Guard {leases,clock};let approval=FixtureApproval {revoke_stream:None};
    let mut owner=conversation::Owner {cx,task,clock,effects,leases,approval:&approval,management_authority:&guard,stream_authority:&guard,wall:&FixtureClock};
    let start=listener::Start {bind,resource:"fixture:camera",admission:&policy,channel:VideoChannel::Video2,video:VideoCodec::H264,audio:AudioCodec::Aac,stream_name:"0123456789abcdef",hello:&operations[0],agreement:&operations[1],stream:&operations[2],time_sync:&operations[3..4],management,stream_conditions:stream,chunk_bytes:4096,max_bytes:u64::try_from(expected.len())?+1,bind_wait:Duration::from_secs(5),conversation_wait:Duration::from_secs(5),accept_wait:Duration::from_secs(5)};
    let framer=Framer::with_mode(FlvLimits::default(),fss_packet::extended_flv::stream::MAX_BUFFER_BYTES,fss_packet::extended_flv::stream::SearchMode::ZeroStreamId)?;
    let recorder=if matches!(video_session, 4 | 25 | 27) { recording::Recorder::new_inband(SourceKey {connection:1,generation:1},recording::Limits::default())? } else { recording::Recorder::new(SourceKey {connection:1,generation:1},recording::Limits::default())? };
    let mut trace=listener::StartTrace::default();
    let started=listener::start_tracked(&mut owner,&mut session,&start,framer,recorder,&mut trace).await?;
    let pipeline=started.pipeline;
    let collector=av_bootstrap::Collector::new(Some([0x14,0x08]),ContentDigest::sha256(b"worker guard retention"),av_owned_sink::BootstrapPolicy {allow_initial_video_only: initial_video_only, max_separation_ms:5_000,jitter_ms:5,max_epoch_frames:1_000_000,max_audio_frames:fss_container::Mp4Limits::default().max_samples,media_limits:fss_container::Mp4Limits::default(),evidence_limits:fss_reference::unifi_direct::evidence::Limits::default()});
    let replay_authority=fss_core::region::ContextAuthority::new_root(RootAuthoritySpec {trace_id:"trace:owned-replay-storage".into(),operation_id:OperationId::parse("operation:owned-replay-storage")?,principal:"principal:fixture".into(),capabilities:vec!["ADP-REPLAY-001".into()],deadline:None,priority:1,budgets:BudgetVector::builder().bytes(64*1024*1024).build()?,privacy_scope:"privacy:test".into(),retention_scope:"retention:test".into(),anchor_universe:ContentDigest::sha256(b"site:owned-replay"),generation:1})?;
    let access=Arc::new(Retention);
    let replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let av_replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let root=temp.join("owned-storage");
    let storage_cfg=recording_storage::Configuration {
        root:&root,site_lineage:"site:owned-replay",source:SourceKey {connection:1,generation:1},
        camera_claim:if matches!(video_session, 0 | 23) { management.camera } else { ContentDigest::sha256(b"fixture camera") },source_retention:ContentDigest::sha256(b"owned retention"),
        source_scope:ContentDigest::sha256(b"owned source scope"),av_scope:ContentDigest::sha256(b"owned av scope"),
        source_deployment_limits:owned_source_limits(),av_deployment_limits:owned_av_limits(),
        source_history_limits:EffectJournalLimits {max_records:512,..EffectJournalLimits::default()},av_history_limits:EffectJournalLimits {max_records:if matches!(video_session, 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21) {5} else {256},..EffectJournalLimits::default()},
        limits:archive::Limits::default(),max_source_bytes:1024*1024,work_limit:4_000_000_000,
    };
    let bad_source=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let bad_av=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let bad_cfg=recording_storage::Configuration {av_history_limits:EffectJournalLimits {max_records:0,..storage_cfg.av_history_limits},..storage_cfg};
    assert!(matches!(recording_storage::create(task,cx,clock,bad_cfg,bad_source,bad_av,access.clone()),Err(recording_storage::Error::Configuration)));
    assert!(!root.exists());
    let bad_source=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let bad_av=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let bad_cfg=recording_storage::Configuration {av_scope:storage_cfg.source_scope,..storage_cfg};
    assert!(matches!(recording_storage::create(task,cx,clock,bad_cfg,bad_source,bad_av,access.clone()),Err(recording_storage::Error::Configuration)));
    assert!(!root.exists());
    let bad_source=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let bad_av=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let bad_cfg=recording_storage::Configuration {limits:archive::Limits {maximum_spool_object_bytes:64*1024*1024+1,maximum_ledger_deltas:65_536},..storage_cfg};
    assert!(matches!(recording_storage::create(task,cx,clock,bad_cfg,bad_source,bad_av,access.clone()),Err(recording_storage::Error::Configuration)));
    assert!(!root.exists());
    let bad_source=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let bad_av=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let bad_limits=fss_reference::DeploymentLimits {max_roots:0,..owned_source_limits()};
    let bad_cfg=recording_storage::Configuration {source_deployment_limits:bad_limits,..storage_cfg};
    assert!(matches!(recording_storage::create(task,cx,clock,bad_cfg,bad_source,bad_av,access.clone()),Err(recording_storage::Error::Configuration)));
    assert!(!root.exists());
    let cancelled=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    cancelled.request_cancellation();
    let other=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    assert!(matches!(recording_storage::create(task,cx,clock,storage_cfg,cancelled,other,access.clone()),Err(recording_storage::Error::Admission)));
    assert!(!root.exists());
    let failed_root=temp.join("refused-storage");
    let failed_cfg=recording_storage::Configuration {root:&failed_root,..storage_cfg};
    let failed_source=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let failed_av=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let reject=recording_storage::Retainers {source_journal:Box::new(RejectRetain),source_keeper:Box::new(RejectRetain),av_journal:Box::new(RejectRetain),av_keeper:Box::new(RejectRetain)};
    assert!(matches!(recording_storage::create_retained(task,cx,clock,failed_cfg,failed_source,failed_av,access.clone(),reject),Err(recording_storage::Error::Storage)));
    assert!(failed_root.is_dir());
    let failed_source=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let failed_av=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    assert!(matches!(recording_storage::create(task,cx,clock,failed_cfg,failed_source,failed_av,access.clone()),Err(recording_storage::Error::Root)));
    let witness=temp.join("witness");
    task.checkpoint_for(RuntimeGrant::ObjectStage,witness.to_str().ok_or("witness path")?,clock.now()?,&BudgetVector::ZERO)?;
    std::fs::create_dir(&witness)?;
    let scope=|name:&str| ContentDigest::sha256(format!("owned-witness:{name}").as_bytes());
    let retainer=|name:&str| -> Result<Box<dyn fss_runtime::effect_journal::EffectPinRetainer>,Box<dyn std::error::Error>> {
        Ok(Box::new(fss_object::effect_journal::FileTrustedRootPinRetainer::create(witness.join(name),EffectJournalLimits::default(),Arc::new(HostSpoolIo),scope(name))?))
    };
    let retainers=recording_storage::Retainers {source_journal:retainer("source-journal")?,source_keeper:retainer("source-keeper")?,av_journal:retainer("av-journal")?,av_keeper:retainer("av-keeper")?};
    let storage=recording_storage::create_retained(task,cx,clock,storage_cfg,replay,av_replay,access.clone(),retainers)?;
    if video_session != 0 && video_session != 23 {
        let supervisor=supervisor::Supervisor::new(session,pipeline,management);
        let recording_storage::Created {coordinator,av:resources}=storage;
        Box::pin(drive_video_only_session(supervisor, coordinator, resources, &expected, &mut owner, &operations[4], access.as_ref(), access.clone(), temp, Arc::new(fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?), task, cx, clock, if video_session >= 2 { video_session } else { 0 }, storage_cfg, &replay_authority, access.clone(), management, stream, &policy)).await?;
        peer.join().map_err(|_|"video session peer panicked")??;
        return Ok(());
    }
    assert_eq!(*storage.av.deployment.limits(),owned_av_limits());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&root)?.permissions().mode() & 0o077,0);
    }
    let retry_source=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let retry_av=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    assert!(matches!(recording_storage::create(task,cx,clock,storage_cfg,retry_source,retry_av,access.clone()),Err(recording_storage::Error::Root)));
    let owned=if test_refusal {
        use fss_reference::unifi_direct::recording_session::{BeginRefusal,Session};
        let mut supervisor=supervisor::Supervisor::new(session,pipeline,management);
        let recording_storage::Created {coordinator,av:resources}=storage;
        supervisor.enable_audio_tracking()?;
        let refusal=match Session::begin(supervisor,collector,coordinator,resources) {Err(refusal)=>refusal,Ok(_)=>return Err("duplicate audio setup unexpectedly accepted".into())};
        let BeginRefusal::Audio {supervisor,collector,coordinator,resources,error:pipeline::AudioSetupError::AlreadyEnabled}=refusal else {return Err("wrong begin refusal".into());};
        let driver=av_bootstrap_driver::Driver::attach(supervisor,collector).map_err(|_|"recovered bootstrap driver refused")?;
        Session::new(coordinator,Box::new(driver),resources)
    } else {
        use fss_reference::unifi_direct::recording_session::{SelectedRecording, SelectedRefusal, Session};
        let selected=SelectedRecording { session, pipeline, management:Preconditions {camera:ContentDigest::sha256(b"wrong selected camera"),..management}, storage, collector };
        let mut selected=match Session::begin_selected(selected) {
            Err(SelectedRefusal::Binding(selected))=>selected,
            _=>return Err("selected A/V accepted wrong camera binding".into()),
        };
        if selected.pipeline.source_key()!=storage_cfg.source {return Err("selected A/V lost its source".into());}
        selected.management=management;
        Session::begin_selected(selected).map_err(|_|"selected A/V session refused")?
    };
    let (coordinator,pins,av_minimum,av_pin)=drive_owned_recording(owned,&mut owner,&operations[4],stream,None,true,initial_video_only,false,if video_session==23 {2} else {1},access.as_ref(),task,cx,clock).await?;
    let retired=coordinator.into_worker().retire().map_err(|_|"source worker retirement refused")?;
    if retired.fenced || retired.pending.is_some(){return Err("source custody unresolved".into());}
    let mut parts=retired.parts;
    assert_eq!(*parts.deployment.limits(),owned_source_limits());
    let mut archived_stream_start=false;
    let last_source_pin=*pins.last().ok_or("source pin missing")?;
    let first_source_pin=*pins.first().ok_or("first source pin missing")?;
    for pin in &pins {
        let recovered=archive::read_unknown_time_source(&mut parts.deployment,*pin,access.as_ref(),archive::Limits::default(),&mut fss_geometry::WorkBudget::new(4_000_000_000),&parts.replay)?;
        let start=usize::try_from(recovered.offset())?;let end=start.checked_add(recovered.bytes().len()).ok_or("source offset overflow")?;
        if expected.get(start..end)!=Some(recovered.bytes()){return Err("source bytes mismatch".into());}
        archived_stream_start |= start==0 && !recovered.bytes().is_empty();
    }
    if !archived_stream_start{return Err("stream start was not archived".into());}
    println!("owned_source_readback stream_start=matched");
    let source_minimum=recording_storage::HistoryMinimum {journal:parts.journal.anchor(),keeper:parts.keeper.anchor()};
    drop(parts);
    use fss_runtime::effect_journal::EffectPinRetainer;
    let retained=|name:&str| -> Result<fss_runtime::effect_journal::EffectJournalPin,Box<dyn std::error::Error>> {
        let mut root=fss_object::effect_journal::FileTrustedRootPinRetainer::open_trusting_storage(witness.join(name),EffectJournalLimits::default(),Arc::new(HostSpoolIo),scope(name))?;
        root.retained_pin()?.ok_or_else(||"missing witness anchor".into())
    };
    let durable_source=recording_storage::HistoryMinimum {journal:retained("source-journal")?,keeper:retained("source-keeper")?};
    let durable_av=recording_storage::HistoryMinimum {journal:retained("av-journal")?,keeper:retained("av-keeper")?};
    assert_eq!((durable_source.journal,durable_source.keeper),(source_minimum.journal,source_minimum.keeper));
    assert_eq!((durable_av.journal,durable_av.keeper),(av_minimum.journal,av_minimum.keeper));
    let source_minimum=durable_source;let av_minimum=durable_av;
    let bad=fss_runtime::effect_journal::EffectJournalPin {sequence:av_minimum.journal.sequence,root:ContentDigest::sha256(b"wrong retained anchor")};
    let bad_av=recording_storage::HistoryMinimum {journal:bad,keeper:av_minimum.keeper};
    let replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let av_replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    assert!(matches!(recording_storage::recover_histories(task,cx,clock,storage_cfg,source_minimum,bad_av,replay,av_replay),Err(recording_storage::Error::MinimumMismatch)));
    let bad_keeper=fss_runtime::effect_journal::EffectJournalPin {sequence:source_minimum.keeper.sequence,root:ContentDigest::sha256(b"wrong keeper anchor")};
    let bad_source=recording_storage::HistoryMinimum {journal:source_minimum.journal,keeper:bad_keeper};
    let replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let av_replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    assert!(matches!(recording_storage::recover_histories(task,cx,clock,storage_cfg,bad_source,av_minimum,replay,av_replay),Err(recording_storage::Error::MinimumMismatch)));
    let cancelled=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    cancelled.request_cancellation();
    let av_replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    assert!(matches!(recording_storage::recover_histories(task,cx,clock,storage_cfg,source_minimum,av_minimum,cancelled,av_replay),Err(recording_storage::Error::Admission)));
    let replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let av_replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let recovered=recording_storage::recover_histories(task,cx,clock,storage_cfg,source_minimum,av_minimum,replay,av_replay)?;
    assert!(recovered.source.keeper_caught_up() && recovered.av.keeper_caught_up());
    assert_eq!(recovered.source.journal.pending(),None);
    assert_eq!(recovered.av.journal.pending(),None);
    assert_eq!(recovered.source.journal.confirmed(),Some(last_source_pin));
    assert_eq!(recovered.av.journal.confirmed(),Some(av_pin));
    assert_eq!(recovered.source.journal.replay_pin(),Some(last_source_pin));
    assert_eq!(recovered.av.journal.replay_pin(),Some(av_pin));
    println!("owned_history_recovery=verified replay_required=true");
    let without_custody=match recording_storage::resume_confirmed(task,cx,clock,storage_cfg,recovered,access.as_ref(),access.clone(),archive::StagedAvLimits {max_objects:8192,max_object_bytes:64*1024*1024,max_total_bytes:256*1024*1024}) {Err(refusal)=>refusal,Ok(_)=>return Err("restart without retained custody accepted".into())};
    assert_eq!(without_custody.reason,recording_storage::Error::Custody);
    drop(without_custody);
    let open_retainer=|name:&str| -> Result<Box<dyn fss_runtime::effect_journal::EffectPinRetainer>,Box<dyn std::error::Error>> {
        Ok(Box::new(fss_object::effect_journal::FileTrustedRootPinRetainer::open_trusting_storage(witness.join(name),EffectJournalLimits::default(),Arc::new(HostSpoolIo),scope(name))?))
    };
    let bad_retainers=recording_storage::Retainers {source_journal:Box::new(RejectRetain),source_keeper:open_retainer("source-keeper")?,av_journal:open_retainer("av-journal")?,av_keeper:open_retainer("av-keeper")?};
    let replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let av_replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    assert!(matches!(recording_storage::recover_histories_retained(task,cx,clock,storage_cfg,source_minimum,av_minimum,replay,av_replay,bad_retainers),Err(recording_storage::Error::MinimumMismatch)));
    let retainers=recording_storage::Retainers {source_journal:open_retainer("source-journal")?,source_keeper:open_retainer("source-keeper")?,av_journal:open_retainer("av-journal")?,av_keeper:open_retainer("av-keeper")?};
    let replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let av_replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let mut recovered=recording_storage::recover_histories_retained(task,cx,clock,storage_cfg,source_minimum,av_minimum,replay,av_replay,retainers)?;
    let mut av_deployment=fss_reference::ReferenceDeployment::open_with_limits(&root.join("av"),"site:owned-replay",owned_av_limits(),&recovered.av.replay)?;
    let object_limits=archive::StagedAvLimits {max_objects:8192,max_object_bytes:64*1024*1024,max_total_bytes:256*1024*1024};
    assert!(matches!(archive::replay_confirmed_unknown_time_av_anchored(&mut av_deployment,&Deny,access.as_ref(),archive::Limits::default(),object_limits,&mut fss_geometry::WorkBudget::new(100_000_000_000),&recovered.av.replay,&mut recovered.av.journal,&mut recovered.av.keeper),Err(archive::ConfirmedAvReplayError::Readback(archive::Error::Denied))));
    assert_eq!(recovered.av.journal.replay_pin(),Some(av_pin));
    assert!(matches!(archive::replay_confirmed_unknown_time_av_anchored(&mut av_deployment,access.as_ref(),&Deny,archive::Limits::default(),object_limits,&mut fss_geometry::WorkBudget::new(100_000_000_000),&recovered.av.replay,&mut recovered.av.journal,&mut recovered.av.keeper),Err(archive::ConfirmedAvReplayError::Publication(archive::UnknownTimePublishError::Archive(archive::Error::Denied)))));
    assert_eq!(recovered.av.journal.replay_pin(),Some(av_pin));
    let av_receipt=archive::replay_confirmed_unknown_time_av_anchored(&mut av_deployment,access.as_ref(),access.as_ref(),archive::Limits::default(),object_limits,&mut fss_geometry::WorkBudget::new(100_000_000_000),&recovered.av.replay,&mut recovered.av.journal,&mut recovered.av.keeper)?;
    assert_eq!(av_receipt.outcome,fss_publication::RootLedgerOutcome::AlreadyLedgered);
    assert_eq!(av_receipt.root,av_pin.root);
    assert_eq!(recovered.av.journal.replay_pin(),None);
    assert_eq!(recovered.av.journal.confirmed(),Some(av_pin));
    assert!(recovered.av.keeper_caught_up());
    let av_heads=(recovered.av.journal.anchor(),recovered.av.keeper.anchor());
    let checked=archive::verify_settled_unknown_time_av_anchored(&mut av_deployment,access.as_ref(),access.as_ref(),archive::Limits::default(),object_limits,&mut fss_geometry::WorkBudget::new(100_000_000_000),&recovered.av.replay,&recovered.av.journal,&recovered.av.keeper)?;
    assert_eq!(checked,av_pin);
    assert_eq!((recovered.av.journal.anchor(),recovered.av.keeper.anchor()),av_heads);
    assert!(matches!(archive::replay_confirmed_unknown_time_av_anchored(&mut av_deployment,access.as_ref(),access.as_ref(),archive::Limits::default(),object_limits,&mut fss_geometry::WorkBudget::new(100_000_000_000),&recovered.av.replay,&mut recovered.av.journal,&mut recovered.av.keeper),Err(archive::ConfirmedAvReplayError::History)));
    drop(av_deployment);
    let mut deployment=fss_reference::ReferenceDeployment::open_with_limits(&root.join("source"),"site:owned-replay",owned_source_limits(),&recovered.source.replay)?;
    let last=archive::read_unknown_time_source(&mut deployment,last_source_pin,access.as_ref(),archive::Limits::default(),&mut fss_geometry::WorkBudget::new(4_000_000_000),&recovered.source.replay)?;
    let old=archive::read_unknown_time_source(&mut deployment,first_source_pin,access.as_ref(),archive::Limits::default(),&mut fss_geometry::WorkBudget::new(4_000_000_000),&recovered.source.replay)?;
    let old_plan=fss_reference::unifi_direct::source_evidence::Prepared::from_recovered(&old);
    let distinct_source=first_source_pin!=last_source_pin;
    if require_distinct && !distinct_source {return Err("distinct source roots required".into());}
    if distinct_source {
        assert!(matches!(archive::publish_unknown_time_source_anchored(&old_plan,&mut deployment,access.as_ref(),archive::Limits::default(),&mut fss_geometry::WorkBudget::new(4_000_000_000),&recovered.source.replay,&mut recovered.source.journal,&mut recovered.source.keeper),Err(archive::UnknownTimePublishError::Candidate)));
    }
    let last_plan=fss_reference::unifi_direct::source_evidence::Prepared::from_recovered(&last);
    let receipt=archive::publish_unknown_time_source_anchored(&last_plan,&mut deployment,access.as_ref(),archive::Limits::default(),&mut fss_geometry::WorkBudget::new(4_000_000_000),&recovered.source.replay,&mut recovered.source.journal,&mut recovered.source.keeper)?;
    assert_eq!(receipt.outcome,fss_publication::RootLedgerOutcome::AlreadyLedgered);
    assert_eq!(recovered.source.journal.replay_pin(),None);
    if distinct_source {
        archive::publish_unknown_time_source_anchored(&old_plan,&mut deployment,access.as_ref(),archive::Limits::default(),&mut fss_geometry::WorkBudget::new(4_000_000_000),&recovered.source.replay,&mut recovered.source.journal,&mut recovered.source.keeper)?;
        assert_eq!(recovered.source.journal.confirmed(),Some(first_source_pin));
    }
    assert!(recovered.source.keeper_caught_up());
    assert_eq!(recovered.av.journal.replay_pin(),None);
    let source_after=recording_storage::HistoryMinimum {journal:recovered.source.journal.anchor(),keeper:recovered.source.keeper.anchor()};
    if distinct_source {
        assert!(source_after.journal.sequence>source_minimum.journal.sequence && source_after.keeper.sequence>source_minimum.keeper.sequence);
    } else {
        assert_eq!((source_after.journal,source_after.keeper),(source_minimum.journal,source_minimum.keeper));
    }
    drop(deployment);drop(recovered);
    let retainers=recording_storage::Retainers {source_journal:open_retainer("source-journal")?,source_keeper:open_retainer("source-keeper")?,av_journal:open_retainer("av-journal")?,av_keeper:open_retainer("av-keeper")?};
    let replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let av_replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let reopened=recording_storage::recover_histories_retained(task,cx,clock,storage_cfg,source_after,av_minimum,replay,av_replay,retainers)?;
    let reopened=if video_session==23 {
        use fss_reference::unifi_direct::archive::journal::rollover::{Previous, RecoveredLineage, Staged};
        use fss_runtime::effect_journal::PinRetainedEffectJournal;
        let (old_source, mut av, prior_custody)=reopened.into_histories();
        assert!(prior_custody.is_none());
        drop(old_source);
        let mut av_deployment=fss_reference::ReferenceDeployment::open_with_limits(&root.join("av"),"site:owned-replay",owned_av_limits(),&av.replay)?;
        let receipt=archive::replay_confirmed_unknown_time_av_anchored(&mut av_deployment,access.as_ref(),access.as_ref(),archive::Limits::default(),object_limits,&mut fss_geometry::WorkBudget::new(100_000_000_000),&av.replay,&mut av.journal,&mut av.keeper)?;
        assert_eq!(receipt.outcome,fss_publication::RootLedgerOutcome::AlreadyLedgered);
        let recording_storage::RecoveredHistory {journal,keeper,replay:av_replay}=av;
        let make_store=|name:&str| -> Result<Box<dyn fss_runtime::effect_journal::EffectJournalStore>,Box<dyn std::error::Error>> {
            let file=FileEffectJournal::create(root.join(name),EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
            Ok(Box::new(PinRetainedEffectJournal::new(Box::new(file),retainer(name)?)?))
        };
        let staged=Staged::begin(Previous {journal,keeper},make_store("rolled-av-journal")?,make_store("rolled-av-keeper")?,&av_replay).map_err(|r|format!("rolled restart stage refused: {:?}; journal_sequence={} replay_pending={} keeper_caught_up={}",r.reason,r.previous.journal.anchor().sequence,r.previous.journal.replay_pin().is_some(),r.previous.keeper.target()==r.previous.journal.anchor()))?;
        let switch_file=FileEffectJournal::create(root.join("rolled-av-switch"),EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
        let switch=PinRetainedEffectJournal::new(Box::new(switch_file),retainer("rolled-av-switch")?)?;
        let mut active=staged.commit(switch,&av_replay).map_err(|_|"rolled restart switch refused")?;
        let receipt=active.replay_confirmed_av(&mut av_deployment,access.as_ref(),access.as_ref(),archive::Limits::default(),object_limits,&mut fss_geometry::WorkBudget::new(100_000_000_000),&av_replay)?;
        assert_eq!(receipt.outcome,fss_publication::RootLedgerOutcome::AlreadyLedgered);
        let lineage:RecoveredLineage=active.into_recovered_lineage(&av_replay).map_err(|_|"rolled restart lineage refused")?;
        drop(av_deployment);
        let source_replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
        let source=recording_storage::recover_source_retained(task,cx,clock,storage_cfg,source_after,source_replay,&av_replay,recording_storage::SourceRetainers {journal:open_retainer("source-journal")?,keeper:open_retainer("source-keeper")?})?;
        let wrong_scope=recording_storage::Configuration {av_scope:ContentDigest::sha256(b"wrong av recovery scope"),..storage_cfg};
        let refusal=match recording_storage::join_source_and_av_lineage(wrong_scope,source,lineage,av_replay) {Err(refusal)=>refusal,Ok(_)=>return Err("wrong lineage scope accepted".into())};
        assert_eq!(refusal.reason,recording_storage::Error::Configuration);
        let valid_av_replay=refusal.av_replay;
        let cancelled=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
        cancelled.request_cancellation();
        let refusal=match recording_storage::join_source_and_av_lineage(storage_cfg,refusal.source,refusal.lineage,cancelled) {Err(refusal)=>refusal,Ok(_)=>return Err("cancelled lineage join accepted".into())};
        assert_eq!(refusal.reason,recording_storage::Error::Reconciliation);
        recording_storage::join_source_and_av_lineage(storage_cfg,refusal.source,refusal.lineage,valid_av_replay).map_err(|_|"rolled restart join refused")?
    } else { reopened };
    assert_eq!(reopened.av.journal.replay_pin(),if video_session==23 {None} else {Some(av_pin)});
    assert!(reopened.av.keeper_caught_up());
    let restart_av_head=reopened.av.journal.anchor();
    assert_eq!(reopened.source.journal.replay_pin(),reopened.source.journal.confirmed());
    let wrong_source_cfg=recording_storage::Configuration {source_deployment_limits:fss_reference::DeploymentLimits::standard(),..storage_cfg};
    assert!(matches!(recording_storage::readback_confirmed(task,cx,clock,wrong_source_cfg,&reopened,access.as_ref()),Err(recording_storage::Error::SourceReadbackOpen)));
    let wrong_av_cfg=recording_storage::Configuration {av_deployment_limits:fss_reference::DeploymentLimits::standard(),..storage_cfg};
    assert!(matches!(recording_storage::readback_confirmed(task,cx,clock,wrong_av_cfg,&reopened,access.as_ref()),Err(recording_storage::Error::AvReadbackOpen)));
    let refused=match recording_storage::resume_confirmed(task,cx,clock,wrong_source_cfg,reopened,access.as_ref(),access.clone(),object_limits) {Err(refusal)=>refusal,Ok(_)=>return Err("wrong source limits accepted".into())};
    assert_eq!(refused.reason,recording_storage::Error::SourceReadbackOpen);
    let refused=match recording_storage::resume_confirmed(task,cx,clock,wrong_av_cfg,refused.histories,access.as_ref(),access.clone(),object_limits) {Err(refusal)=>refusal,Ok(_)=>return Err("wrong av limits accepted".into())};
    assert_eq!(refused.reason,recording_storage::Error::AvReadbackOpen);
    let refused=match recording_storage::resume_confirmed(task,cx,clock,storage_cfg,refused.histories,access.as_ref(),access.clone(),object_limits) {Err(refusal)=>refusal,Ok(_)=>return Err("old connection reused".into())};
    assert_eq!(refused.reason,recording_storage::Error::RestartBoundary);
    let next_key=SourceKey {connection:2,generation:1};
    let resumed_cfg=recording_storage::Configuration {source:next_key,work_limit:100_000_000_000,..storage_cfg};
    let refused=match recording_storage::resume_confirmed(task,cx,clock,resumed_cfg,refused.histories,&Deny,access.clone(),object_limits) {Err(refusal)=>refusal,Ok(_)=>return Err("unauthorized restart accepted".into())};
    assert_eq!(refused.reason,recording_storage::Error::SourceReadback);
    let resumed=recording_storage::resume_confirmed(task,cx,clock,resumed_cfg,refused.histories,access.as_ref(),access.clone(),object_limits)?;
    let boundary=resumed.boundary();
    assert_eq!(boundary.previous,storage_cfg.source);
    assert_eq!(boundary.next,next_key);
    assert_eq!(boundary.av_root,av_pin);
    let plan=resumed.prepare_boundary()?;
    let boundary_pin=plan.pin();
    let failed_path=witness.join("failed-boundary-journal");
    let failed_store=FileEffectJournal::create(&failed_path,EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
    let failed_wrapped=fss_runtime::effect_journal::PinRetainedEffectJournal::new(Box::new(failed_store),Box::new(RejectRetain))?;
    let failed_replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    assert!(matches!(recording_storage::boundary::Custody::create(failed_wrapped,&plan,failed_path.to_str().ok_or("failed custody path")?.to_string(),failed_replay,task,cx,clock),Err(recording_storage::boundary::Error::CustodyIndeterminate)));
    let custody_path=witness.join("boundary-journal");
    let custody_store=FileEffectJournal::create(&custody_path,EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
    let custody_retainer=fss_object::effect_journal::FileTrustedRootPinRetainer::create(witness.join("boundary-retainer"),EffectJournalLimits::default(),Arc::new(HostSpoolIo),scope("boundary-retainer"))?;
    let wrapped=fss_runtime::effect_journal::PinRetainedEffectJournal::new(Box::new(custody_store),Box::new(custody_retainer))?;
    let custody_replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let custody_resource=custody_path.to_str().ok_or("boundary custody path")?.to_string();
    let mut custody=recording_storage::boundary::Custody::create(wrapped,&plan,custody_resource.clone(),custody_replay,task,cx,clock)?;
    let custody_head=custody.head();
    let refused=match resumed.into_owners(&plan,&mut custody,task,cx,clock,access.as_ref(),&mut fss_geometry::WorkBudget::new(1_000_000_000)) {Err(refused)=>refused,Ok(_)=>return Err("unpublished boundary admitted".into())};
    assert_eq!(refused.reason,recording_storage::boundary::Error::NotLedgered);
    let mut resumed=refused.resumed;
    assert_eq!(resumed.boundary(),boundary);
    assert!(matches!(resumed.publish_boundary(&plan,&mut custody,task,cx,clock,&Deny,&mut fss_geometry::WorkBudget::new(1_000_000_000)),Err(recording_storage::boundary::Error::Denied)));
    let boundary_receipt=resumed.publish_boundary(&plan,&mut custody,task,cx,clock,access.as_ref(),&mut fss_geometry::WorkBudget::new(1_000_000_000))?;
    assert_eq!(boundary_receipt.root,boundary_pin.root);
    let refused=match resumed.into_owners(&plan,&mut custody,task,cx,clock,&Deny,&mut fss_geometry::WorkBudget::new(1_000_000_000)) {Err(refused)=>refused,Ok(_)=>return Err("unauthorized boundary admitted".into())};
    assert_eq!(refused.reason,recording_storage::boundary::Error::Denied);
    let owners=match refused.resumed.into_owners(&plan,&mut custody,task,cx,clock,access.as_ref(),&mut fss_geometry::WorkBudget::new(1_000_000_000)) {Ok(owners)=>owners,Err(refusal)=>return Err(format!("boundary verification refused: {:?}",refusal.reason).into())};
    peer.join().map_err(|_|"peer panic")??;
    let control=controller_listener::Listener::bind(task,cx,clock,&policy,bind,"fixture:camera",Duration::from_secs(5)).await?;
    let address=SocketAddr::V4(control.local_addr());let restart_expected=if initial_video_only {media_fixture()?} else {expected.clone()};let wire=restart_expected.clone();
    let peer=std::thread::spawn(move || -> io::Result<()> {
        let mut socket=std::net::TcpStream::connect_timeout(&address,Duration::from_secs(5))?;socket.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut request=HEAD.as_bytes().to_vec();request.extend(frame(HELLO));socket.write_all(&request)?;
        let mut header=Vec::new();let mut byte=[0u8;1];while !header.ends_with(b"\r\n\r\n"){socket.read_exact(&mut byte)?;header.push(byte[0]);if header.len()>4096{return Err(io::Error::other("upgrade limit"));}}
        if !header.starts_with(b"HTTP/1.1 101 "){return Err(io::Error::other("upgrade refused"));}
        if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_hello".len()).any(|w|w==b"ubnt_avclient_hello"){return Err(io::Error::other("hello reply"));}
        socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":10}"#))?;
        if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_timeSync".len()).any(|w|w==b"ubnt_avclient_timeSync"){return Err(io::Error::other("startup clock reply"));}
        if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_paramAgreement".len()).any(|w|w==b"ubnt_avclient_paramAgreement"){return Err(io::Error::other("agreement"));}
        socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_paramAgreement","messageId":8,"inResponseTo":3}"#))?;
        let request=receive_binary(&mut socket)?;let text=std::str::from_utf8(&request).map_err(io::Error::other)?;
        let destination:SocketAddr=text.split_once("tcp://").and_then(|(_,s)|s.split_once('?')).map(|(s,_)|s).ok_or_else(||io::Error::other("stream destination"))?.parse().map_err(io::Error::other)?;
        if !matches!(destination,SocketAddr::V4(addr) if addr.ip().is_loopback() && addr.port()!=0){return Err(io::Error::other("stream destination scope"));}
        socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ChangeVideoSettings","messageId":9,"inResponseTo":4}"#))?;
        let mut media=std::net::TcpStream::connect_timeout(&destination,Duration::from_secs(5))?;media.set_write_timeout(Some(Duration::from_secs(10)))?;
        let split=wire.len().min(100);media.write_all(&wire[..split])?;
        socket.write_all(&frame(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":11}"#))?;
        if !receive_binary(&mut socket)?.windows(b"ubnt_avclient_timeSync".len()).any(|w|w==b"ubnt_avclient_timeSync"){return Err(io::Error::other("live clock reply"));}
        let writer=std::thread::spawn(move || media.write_all(&wire[split..]));let closed=matches!(socket.read(&mut byte),Ok(0));
        match writer.join().map_err(|_|io::Error::other("media writer panic"))? {Ok(())=>(),Err(error) if closed && matches!(error.kind(),io::ErrorKind::BrokenPipe|io::ErrorKind::ConnectionReset)=>(),Err(error)=>return Err(error)}
        if closed{Ok(())}else{Err(io::Error::other("controller did not retire"))}
    });
    let restart_operations=[OperationId::parse("operation:restart-hello")?,OperationId::parse("operation:restart-agreement")?,OperationId::parse("operation:restart-stream")?,OperationId::parse("operation:restart-clock-startup")?,OperationId::parse("operation:restart-clock-live")?];
    let restart_management=Preconditions {session_generation:2,..management};
    let restart_stream=intent::Preconditions {stream_generation:2,..stream};
    let (io,gate)=control.accept(4096,Duration::from_secs(5)).await?;
    let controller=Controller::new(Identity::new("FSS","12345678-1234-4abc-9abc-123456789abc","1.20.0")?,1)?;
    let mut session=owner::accept_guarded(io,ProtocolPolicy::RequireOffer,&FixtureAdmission,gate,controller,Duration::from_secs(5)).await?;
    let start=listener::Start {bind,resource:"fixture:camera",admission:&policy,channel:VideoChannel::Video2,video:VideoCodec::H264,audio:AudioCodec::Aac,stream_name:"0123456789abcdef",hello:&restart_operations[0],agreement:&restart_operations[1],stream:&restart_operations[2],time_sync:&restart_operations[3..4],management:restart_management,stream_conditions:restart_stream,chunk_bytes:4096,max_bytes:u64::try_from(restart_expected.len())?+1,bind_wait:Duration::from_secs(5),conversation_wait:Duration::from_secs(5),accept_wait:Duration::from_secs(5)};
    let framer=Framer::with_mode(FlvLimits::default(),fss_packet::extended_flv::stream::MAX_BUFFER_BYTES,fss_packet::extended_flv::stream::SearchMode::ZeroStreamId)?;
    let recorder=recording::Recorder::new(next_key,recording::Limits::default())?;let mut trace=listener::StartTrace::default();
    let started=listener::start_tracked(&mut owner,&mut session,&start,framer,recorder,&mut trace).await?;
    let supervisor=supervisor::Supervisor::new(session,started.pipeline,restart_management);
    let collector=av_bootstrap::Collector::new(Some([0x14,0x08]),boundary.av_root.retention,av_owned_sink::BootstrapPolicy {allow_initial_video_only: false, max_separation_ms:5_000,jitter_ms:5,max_epoch_frames:1_000_000,max_audio_frames:fss_container::Mp4Limits::default().max_samples,media_limits:fss_container::Mp4Limits::default(),evidence_limits:fss_reference::unifi_direct::evidence::Limits::default()});
    let recording_storage::Created {coordinator,av}=owners;
    let session=fss_reference::unifi_direct::recording_session::Session::begin(supervisor,collector,coordinator,av).map_err(|_|"resumed recording session refused")?;
    let (coordinator,new_pins,new_av_minimum,new_av_pin)=drive_owned_recording(session,&mut owner,&restart_operations[4],restart_stream,None,true,false,video_session==23,1,access.as_ref(),task,cx,clock).await?;
    let mut retired=coordinator.into_worker().retire().map_err(|_|"resumed source retirement refused")?;
    if retired.fenced || retired.pending.is_some(){return Err("resumed source unresolved".into());}
    for pin in &new_pins {
        let source=archive::read_unknown_time_source(&mut retired.parts.deployment,*pin,access.as_ref(),archive::Limits::default(),&mut fss_geometry::WorkBudget::new(4_000_000_000),&retired.parts.replay)?;
        let start=usize::try_from(source.offset())?;let end=start.checked_add(source.bytes().len()).ok_or("restart source offset overflow")?;
        if source.key()!=next_key || restart_expected.get(start..end)!=Some(source.bytes()){return Err("resumed source readback mismatch".into());}
    }
    let source_final=recording_storage::HistoryMinimum {journal:retired.parts.journal.anchor(),keeper:retired.parts.keeper.anchor()};
    assert!(!new_pins.is_empty() && new_pins.iter().all(|pin|*pin!=boundary.source_root));
    assert_ne!(new_av_pin,boundary.av_root);
    assert!(source_final.journal.sequence>source_after.journal.sequence);
    assert!(new_av_minimum.journal.sequence>restart_av_head.sequence);
    drop(retired);peer.join().map_err(|_|"restart peer panic")??;
    drop(custody);
    let wrong_head=fss_runtime::effect_journal::EffectJournalPin {sequence:custody_head.sequence,root:ContentDigest::sha256(b"wrong boundary custody head")};
    assert!(matches!(FileEffectJournal::open(&custody_path,EffectJournalLimits::default(),Arc::new(HostSpoolIo),wrong_head),Err(fss_runtime::effect_journal::EffectPersistenceError::PinMismatch)));
    let custody_store=FileEffectJournal::open(&custody_path,EffectJournalLimits::default(),Arc::new(HostSpoolIo),custody_head)?;
    let custody_retainer=fss_object::effect_journal::FileTrustedRootPinRetainer::open_trusting_storage(witness.join("boundary-retainer"),EffectJournalLimits::default(),Arc::new(HostSpoolIo),scope("boundary-retainer"))?;
    let wrapped=fss_runtime::effect_journal::PinRetainedEffectJournal::for_reconciliation(Box::new(custody_store),Box::new(custody_retainer))?;
    let custody_replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let custody=recording_storage::boundary::Custody::reopen(wrapped,custody_resource,custody_replay,task,cx,clock)?;
    assert_eq!(custody.head(),custody_head);
    assert_eq!(custody.plan().pin(),boundary_pin);
    assert_eq!(custody.plan().boundary(),boundary);
    let cold_replay=fss_reference::ReplayCx::from_context_authority(&replay_authority,temp.to_path_buf())?;
    let mut cold=fss_reference::ReferenceDeployment::open_with_limits(&root.join("av"),"site:owned-replay",owned_av_limits(),&cold_replay)?;
    assert!(matches!(recording_storage::boundary::verify_retained(&mut cold,&cold_replay,access.as_ref(),custody.plan(),task,cx,clock,&Deny,&mut fss_geometry::WorkBudget::new(1_000_000_000)),Err(recording_storage::boundary::Error::Denied)));
    recording_storage::boundary::verify_retained(&mut cold,&cold_replay,access.as_ref(),custody.plan(),task,cx,clock,access.as_ref(),&mut fss_geometry::WorkBudget::new(1_000_000_000))?;
    let wrong=recording_storage::boundary::prepare(recording_storage::RestartBoundary {next:SourceKey {connection:3,generation:1},..boundary})?;
    assert!(matches!(recording_storage::boundary::verify_retained(&mut cold,&cold_replay,access.as_ref(),&wrong,task,cx,clock,access.as_ref(),&mut fss_geometry::WorkBudget::new(1_000_000_000)),Err(recording_storage::boundary::Error::NotLedgered)));
    drop(cold);
    assert_eq!(retained("source-journal")?,source_final.journal);
    assert_eq!(retained("source-keeper")?,source_final.keeper);
    assert_eq!(retained(if video_session==23 {"rolled-av-journal"} else {"av-journal"})?,new_av_minimum.journal);
    assert_eq!(retained(if video_session==23 {"rolled-av-keeper"} else {"av-keeper"})?,new_av_minimum.keeper);
    if std::env::var("FSS_TEST_PRESERVE_BOUNDARY").as_deref()==Ok("1") {
        use std::os::unix::fs::OpenOptionsExt;
        let receipt_path=temp.join("boundary-test-receipt");
        task.checkpoint_for(RuntimeGrant::ObjectStage,receipt_path.to_str().ok_or("receipt path")?,clock.now()?,&BudgetVector::ZERO)?;
        let mut file=std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(receipt_path)?;
        writeln!(file,"{}\n{}\n{}",custody_head.root.to_text(),boundary_pin.root.to_text(),boundary_pin.retention.to_text())?;
    }
    println!("owned_retained_recovery=source_replayed source_reanchored={distinct_source} av_replayed=true old_muxer_state=not_reconstructed");
    println!("owned_restart=second_connection_archived boundary_time=unknown boundary_custody=reopened boundary_evidence=cold_verified controller_effects=unsettled");
    Ok(())
}

#[test]
fn asynchronous_guard_cancels_drains_and_retries_source() -> Test {
    conversation_scenario_with_worker_guard(false, false, false, false, false, false, 0, false, true, true, true, false)
}

#[test]
fn bootstrap_driver_fences_unreconciled_audio_configuration() -> Test {
    conversation_scenario_with_worker_guard(false, false, false, false, false, false, 0, false, true, true, false, true)
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
    clock_requests_reach_stream(false, false)
}

#[test]
fn mixed_clock_requests_reach_hello_and_stream_with_distinct_effects() -> Test {
    clock_requests_reach_stream(true, false)
}

#[test]
fn continuing_clock_chain_remains_journaled_after_stream_start() -> Test {
    clock_requests_reach_stream(false, true)
}

/// Exercise clock requests through the owned conversation, local TCP,
/// per-reply effect journal and the camera-shaped peer.
fn clock_requests_reach_stream(mixed: bool, continuing: bool) -> Test {
    let path = std::fs::canonicalize(std::env::temp_dir())?
        .join(format!("fss-unifi-clock-chain-{}-{mixed}-{continuing}", std::process::id()));
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
    let syncs: Vec<_> = (0..42)
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
                        if continuing {
                            for camera_id in 400..430u64 {
                                let response_to = if camera_id == 410 || camera_id == 420 { 0 } else { correlation };
                                let message = format!("{{\"from\":\"ubnt_avclient\",\"to\":\"UniFiVideo\",\"functionName\":\"ubnt_avclient_timeSync\",\"messageId\":{camera_id},\"inResponseTo\":{response_to},\"responseExpected\":true}}");
                                socket.write_all(&frame(message.as_bytes()))?;
                                let reply = receive_binary(&mut socket)?;
                                if field(&reply, "inResponseTo")? != camera_id { return Err(io::Error::other("continuing clock correlation")); }
                                correlation = field(&reply, "messageId")?;
                            }
                        }
                        let mut last = [0u8; 1];
                        match socket.read(&mut last) { Ok(0) => Ok(()), _ => Err(io::Error::other("controller did not retire")) }
                    });
                    let (io, gate) = listener.accept(4096, Duration::from_secs(10)).await?;
                    let controller = Controller::new_with_time_sync_policy(
                        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
                        1,
                        if continuing { fss_reference::unifi_direct::TimeSyncPolicy::BoundedContinuingClockExchange } else { fss_reference::unifi_direct::TimeSyncPolicy::BoundedPreHelloClockExchange },
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
                        hello: &hello, agreement: &agreement, stream: &stream, time_sync: &syncs[..12],
                        management, stream_conditions, request: &request, wait: Duration::from_secs(20),
                    };
                    let reply = owner.start(&mut session, &cfg).await?;
                    assert_eq!(reply.time_syncs, 12);
                    if continuing {
                        for operation in &syncs[12..] {
                            assert_eq!(session.next(Duration::from_secs(10)).await?, Step::Observation(Observation::TimeSyncRequested));
                            let mut trace = conversation::TimeSyncTrace::default();
                            owner.answer_time_sync_tracked(&mut session, operation, management, Duration::from_secs(10), &mut trace).await?;
                            assert_eq!(trace.operation(), Some(operation));
                            assert!(trace.dispatch_started());
                            match trace.take_written() {
                                Some(ManagementWrite::Written { permit }) if permit.journal_backed() => (),
                                _ => return Err("continuing clock write did not retain its journaled permit".into()),
                            }
                        }
                    }
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
    let used = if continuing { syncs.len() } else { 12 };
    for operation in [&hello, &agreement, &stream].into_iter().chain(syncs[..used].iter()) {
        assert_eq!(effects.journal().operation(operation).ok_or("missing effect")?.state, fss_core::EffectState::Committed);
    }
    for operation in &syncs[used..] {
        assert!(effects.journal().operation(operation).is_none());
    }
    assert!(!authority.finalize_report(&tree)?.is_empty());
    Ok(())
}
