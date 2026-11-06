#![forbid(unsafe_code)]
#![cfg(unix)]
//! Bounded, owner-authorized direct UniFi interoperability trial.
//! This is a laboratory executable, not a continuous recorder or enrolled
//! service. It uses experimental TLS and unverified IP/MAC admission.
use asupersync::{runtime::RuntimeBuilder, time::timeout_at};
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
use fss_reference::{
    onvif::wire::UtcDateTime,
    unifi_direct::{
        AudioCodec, Controller, Identity, TimeSyncPolicy, VideoChannel, VideoCodec, controller_listener,
        conversation, intent, listener, management,
        metered::{MeteredClock, MeteredIo},
        owner, pipeline, receive, recording, supervisor,
        upgrade::ProtocolPolicy,
    },
};
use fss_runtime::{
    authority::AuthorityCx,
    effect::{CommitApproval, CommittedEffect, EffectCoordinator, PreparedEffect},
    execution::{TaskCompletion, TaskSpec, run_owned_async},
    lease::LeaseRegistry,
};
use rustls::{
    ServerConfig, ServerConnection,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use std::{
    cell::{Cell, RefCell},
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    net::{Ipv4Addr, SocketAddrV4},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use unifi_tls_05_server_lab::server::Server;

type ResultBox<T> = Result<T, Box<dyn Error>>;
const USAGE: &str = "usage: unifi_direct_trial LISTEN_IPV4:PORT CAMERA_IPV4 CAMERA_MAC_HEX CERT_DER KEY_DER JOURNAL_DIR OUTPUT_MP4 CONTROLLER_UUID [WAIT_SECONDS] [--allow-correlated-timesync] --owner-authorized";
const MAX_SOURCE: u64 = 32 * 1024 * 1024;
const MAX_INITIAL_CONNECTIONS: usize = 8;
const MAX_IO_WAIT: Duration = Duration::from_secs(30);

struct Options {
    listen: SocketAddrV4,
    camera: Ipv4Addr,
    mac: [u8; 6],
    cert: PathBuf,
    key: PathBuf,
    journal: PathBuf,
    output: PathBuf,
    uuid: String,
    wait: Duration,
    time_sync_policy: TimeSyncPolicy,
}
fn options() -> ResultBox<Options> {
    let mut args: Vec<_> = std::env::args().skip(1).collect();
    if args.pop().as_deref() != Some("--owner-authorized") {
        return Err(USAGE.into());
    }
    let time_sync_policy = if args.last().is_some_and(|arg| arg == "--allow-correlated-timesync") {
        args.pop();
        TimeSyncPolicy::ExplicitCorrelatedRequests
    } else {
        TimeSyncPolicy::UncorrelatedOnly
    };
    if !(args.len() == 8 || args.len() == 9) { return Err(USAGE.into()); }
    let listen: SocketAddrV4 = args[0].parse()?;
    let camera: Ipv4Addr = args[1].parse()?;
    if listen.port() == 0
        || !(camera.is_private() || camera.is_loopback() || camera.is_link_local())
    {
        return Err("invalid scoped addresses".into());
    }
    let raw = args[2].as_bytes();
    if raw.len() != 12 || !raw.iter().all(u8::is_ascii_hexdigit) {
        return Err("MAC must be twelve hexadecimal digits".into());
    }
    let mut mac = [0u8; 6];
    for (index, byte) in mac.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&args[2][index * 2..index * 2 + 2], 16)?;
    }
    let cert = PathBuf::from(&args[3]);
    let key = PathBuf::from(&args[4]);
    let journal = PathBuf::from(&args[5]);
    let output = PathBuf::from(&args[6]);
    if [&cert, &key, &journal, &output]
        .iter()
        .any(|p| !p.is_absolute())
    {
        return Err("paths must be absolute".into());
    }
    if output.exists() || journal.exists() {
        return Err("output and journal paths must not exist".into());
    }
    let wait_seconds = if args.len() == 9 {
        args[8].parse::<u64>()?
    } else {
        30
    };
    if !(1..=90).contains(&wait_seconds) {
        return Err("wait must be 1 to 90 seconds".into());
    }
    Ok(Options {
        listen,
        camera,
        mac,
        cert,
        key,
        journal,
        output,
        uuid: args[7].clone(),
        wait: Duration::from_secs(wait_seconds),
        time_sync_policy,
    })
}
fn bounded_read(path: &Path, private: bool) -> ResultBox<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_file()
        || meta.len() == 0
        || meta.len() > 16 * 1024
        || (private && meta.mode() & 0o077 != 0)
    {
        return Err("invalid certificate or private-key file".into());
    }
    Ok(fs::read(path)?)
}
fn epoch() -> ResultBox<(TimestampNs, u64)> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok((
        TimestampNs(i128::try_from(now.as_nanos())?),
        u64::try_from(now.as_millis())?,
    ))
}
struct Policy {
    local: Ipv4Addr,
    camera: Ipv4Addr,
    mac: [u8; 6],
}
impl listener::Admission for Policy {
    fn listener(&self, requested: SocketAddrV4, bound: Option<SocketAddrV4>) -> bool {
        *requested.ip() == self.local
            && bound.is_none_or(|addr| *addr.ip() == self.local && addr.port() != 0)
    }
    fn peer(&self, bound: SocketAddrV4, source: SocketAddrV4) -> bool {
        *bound.ip() == self.local && *source.ip() == self.camera
    }
}
impl owner::PeerAdmission for Policy {
    fn permits(&self, mac: [u8; 6]) -> bool {
        mac == self.mac
    }
}
struct Approval(Cell<bool>);
impl conversation::Approval for Approval {
    fn approve(&self, prepared: &PreparedEffect) -> Option<CommitApproval> {
        // Once any management effect is prepared, a new controller session
        // must not reuse this trial's operation identities automatically.
        self.0.set(true);
        Some(CommitApproval {
            prepared_digest: prepared.digest(),
            current_precondition_digest: prepared.precondition_digest(),
        })
    }
}
struct Guard<'a, 'scope, 'task> {
    leases: &'a RefCell<LeaseRegistry>,
    clock: MeteredClock<'scope, 'task>,
    mac: [u8; 6],
    management_gate_passed: Cell<bool>,
}
impl receive::ManagementAuthority for Guard<'_, '_, '_> {
    fn permits(&self, mac: [u8; 6], intent: management::Intent, permit: &CommittedEffect) -> bool {
        let permitted = self.clock.now().ok().is_some_and(|now| {
            mac == self.mac
                && permit.fence() == intent.fence()
                && self
                    .leases
                    .borrow_mut()
                    .check_fence(&intent.resource(), intent.fence(), now)
                    .is_ok()
        });
        if permitted {
            self.management_gate_passed.set(true);
        }
        permitted
    }
}
impl receive::StreamAuthority for Guard<'_, '_, '_> {
    fn permits(&self, mac: [u8; 6], intent: intent::Intent, permit: &CommittedEffect) -> bool {
        self.clock.now().ok().is_some_and(|now| {
            mac == self.mac
                && permit.fence() == intent.fence()
                && self
                    .leases
                    .borrow_mut()
                    .check_fence(&intent.resource(), intent.fence(), now)
                    .is_ok()
        })
    }
}
struct Wall<'scope, 'task> {
    task: &'scope fss_runtime::execution::TaskCx<'task>,
    clock: MeteredClock<'scope, 'task>,
}
impl conversation::WallClock for Wall<'_, '_> {
    fn observe(&self) -> Option<conversation::WallTime> {
        let now = self.clock.now().ok()?;
        self.task.checkpoint(now, &BudgetVector::ZERO).ok()?;
        let millis = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()?
                .as_millis(),
        )
        .ok()?;
        let utc = UtcDateTime::new(1970, 1, 1, 0, 0, 0)
            .ok()?
            .checked_add_seconds(millis / 1000)
            .ok()?
            .to_rfc3339();
        let timestamp = format!("{}.{:03}Z", utc.strip_suffix('Z')?, millis % 1000);
        Some(conversation::WallTime {
            unix_ms: millis,
            timestamp,
        })
    }
}
fn write_clip(path: &Path, bytes: &[u8]) -> ResultBox<()> {
    let parent = path.parent().ok_or("output requires parent")?;
    let meta = fs::symlink_metadata(parent)?;
    if !meta.file_type().is_dir() || meta.mode() & 0o077 != 0 {
        return Err("output parent must be a private directory".into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let copy = fs::read(path)?;
    if ContentDigest::sha256(&copy) != ContentDigest::sha256(bytes) {
        return Err("clip readback mismatch".into());
    }
    Ok(())
}
fn run(args: Options) -> ResultBox<()> {
    println!("trial_time_sync_policy={:?}", args.time_sync_policy);
    let (start, _) = epoch()?;
    let deadline = TimestampNs(
        start
            .0
            .checked_add(180_000_000_000)
            .ok_or("deadline overflow")?,
    );
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 128 * 1024 * 1024;
    budget.bytes = 128 * 1024 * 1024;
    budget.storage_operations = 5;
    let caps = [
        RuntimeGrant::AdapterNet,
        RuntimeGrant::AdapterAuth,
        RuntimeGrant::ReadMedia,
        RuntimeGrant::MediaDecode,
        RuntimeGrant::ObjectStage,
        RuntimeGrant::CameraManagementPrepare,
        RuntimeGrant::CameraManagementCommit,
        RuntimeGrant::CameraSettingPrepare,
        RuntimeGrant::CameraSettingCommit,
    ];
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:unifi-direct-trial".into(),
            operation_id: OperationId::parse("operation:unifi-direct-trial")?,
            principal: "principal:owner".into(),
            capabilities: caps.iter().map(|g| g.as_str().into()).collect(),
            deadline: Some(deadline),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:owner".into(),
            retention_scope: "retention:trial".into(),
            anchor_universe: ContentDigest::sha256(b"owner-authorized unifi direct trial"),
            generation: 1,
        },
        RegionId::new("region:unifi-direct-trial")?,
        RegionKind::Process,
        budget,
        start,
    )?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx=asupersync::Cx::current().ok_or("missing runtime")?;
        let task_start=TimestampNs(start.0+1);
        let result=run_owned_async(&mut authority,&mut tree,TaskSpec {task_id:TaskId::new("task:unifi-direct-trial")?,started_at:task_start},&cx,async |task,cx| {
            let clock=match MeteredClock::new(task,cx,TimestampNs(start.0+2)) {
                Ok(clock)=>clock,
                Err(error)=>return TaskCompletion { output:Err(Box::new(error) as Box<dyn Error>), outcome:TaskOutcome::Failed("trial clock unavailable".into()), completed_at:task_start },
            };
            let output:ResultBox<()> = async {
                task.checkpoint_for(RuntimeGrant::AdapterAuth,"trial:tls-key",clock.now()?,&BudgetVector::ZERO)?;
                let cert=bounded_read(&args.cert,false)?; let key=bounded_read(&args.key,true)?;
                let config=ServerConfig::builder_with_provider(Arc::new(rustls_pure::provider())).with_protocol_versions(&[&rustls::version::TLS13])?.with_no_client_auth().with_single_cert(vec![CertificateDer::from(cert)],PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))?;
                let journal=FileEffectJournal::create(&args.journal,EffectJournalLimits::default(),Arc::new(HostSpoolIo))?;
                let mut effects=EffectCoordinator::with_journal(Box::new(journal))?;
                let mut binding=Vec::from(args.mac); binding.extend_from_slice(&args.camera.octets());
                let camera=ContentDigest::sha256(&binding); let resource=format!("camera:{}",camera.to_text());
                let mut leases=LeaseRegistry::new();
                let fence=leases.acquire(&resource,"region:unifi-direct-trial",None,clock.now()?)?.fence;
                let leases=RefCell::new(leases);
                let admission=ContentDigest::sha256(b"owner-selected network address and camera MAC; not cryptographic identity");
                let management=management::Preconditions {camera,peer_admission:admission,session_generation:1,previous_association:None,previous_clock:None,lease_fence:fence};
                let stream_conditions=intent::Preconditions {camera,peer_admission:admission,stream_generation:1,previous_settings:None,lease_fence:fence};
                let policy=Policy {local:*args.listen.ip(),camera:args.camera,mac:args.mac};
                let mut controller_listener=controller_listener::Listener::bind(task,cx,clock,&policy,args.listen,&resource,args.wait.min(MAX_IO_WAIT)).await?;
                println!("controller_listener_ready identity=network_claim tls=experimental timeout_seconds={}",args.wait.as_secs());
                let deadline=cx.now()+args.wait;
                let config=Arc::new(config);
                let guard=Guard {leases:&leases,clock,mac:args.mac,management_gate_passed:Cell::new(false)};
                let wall=Wall {task,clock}; let approval=Approval(Cell::new(false));
                let mut owner=conversation::Owner {cx,task,clock,effects:&mut effects,leases:&leases,approval:&approval,management_authority:&guard,stream_authority:&guard,wall:&wall};
                let hello=OperationId::parse("operation:unifi-trial-hello")?; let agreement=OperationId::parse("operation:unifi-trial-agreement")?; let stream=OperationId::parse("operation:unifi-trial-stream")?;
                let syncs:Vec<_>=(0..128).map(|i|OperationId::parse(format!("operation:unifi-trial-sync-{i:04}"))).collect::<Result<_,_>>()?;
                let mut attempts=0;
                let (session,started)=loop {
                    let remaining=Duration::from_nanos(deadline.as_nanos().saturating_sub(cx.now().as_nanos()));
                    if remaining.is_zero() { return Err("controller TLS deadline elapsed".into()); }
                    let (raw,gate)=match controller_listener.accept_next(16*1024,remaining.min(MAX_IO_WAIT)).await {
                        Ok(connection)=>connection,
                        Err(listener::Error::Deadline) if cx.now()<deadline=>{println!("trial_stage=accept_window_elapsed"); continue},
                        Err(error)=>return Err(error.into()),
                    };
                    attempts+=1;
                    println!("trial_stage=tcp_accepted");
                    let tls=match timeout_at(deadline,Server::new(ServerConnection::new(config.clone())?,raw).handshake(cx)).await {
                        Ok(Ok(tls))=>tls,
                        Ok(Err(error)) if error.kind()==std::io::ErrorKind::UnexpectedEof && attempts<MAX_INITIAL_CONNECTIONS=>{println!("trial_stage=handshake_eof_retry"); continue},
                        Ok(Err(error))=>return Err(error.into()),
                        Err(_)=>return Err("controller TLS deadline elapsed".into()),
                    };
                    println!("trial_stage=tls_handshake_completed");
                    let plaintext=MeteredIo::with_clock(gate.wrap(tls),clock,&resource,16*1024)?;
                    let controller=Controller::new_with_time_sync_policy(Identity::new("FSS",&args.uuid,"1.20.0")?,1,args.time_sync_policy)?;
                    let remaining=Duration::from_nanos(deadline.as_nanos().saturating_sub(cx.now().as_nanos()));
                    if remaining.is_zero() {return Err("controller startup deadline elapsed".into());}
                    let mut session=owner::accept_guarded(plaintext,ProtocolPolicy::RequireOffer,&policy,gate,controller,remaining.min(MAX_IO_WAIT)).await?;
                    println!("trial_stage=websocket_accepted");
                    let remaining=Duration::from_nanos(deadline.as_nanos().saturating_sub(cx.now().as_nanos()));
                    if remaining.is_zero() {return Err("controller startup deadline elapsed".into());}
                    let io_wait=remaining.min(MAX_IO_WAIT);
                    let request=listener::Start {bind:SocketAddrV4::new(*args.listen.ip(),0),resource:&resource,admission:&policy,channel:VideoChannel::Video2,video:VideoCodec::H264,audio:AudioCodec::Aac,stream_name:"0123456789abcdef",hello:&hello,agreement:&agreement,stream:&stream,time_sync:&syncs[..8],management,stream_conditions,chunk_bytes:16*1024,max_bytes:MAX_SOURCE,bind_wait:io_wait,conversation_wait:io_wait,accept_wait:io_wait};
                    let framer=Framer::new(FlvLimits::default(),1024*1024)?; let recorder=recording::Recorder::new(SourceKey {connection:attempts as u64,generation:1},recording::Limits::default())?;
                    match timeout_at(deadline,listener::start(&mut owner,&mut session,&request,framer,recorder)).await {
                        Ok(Ok(started))=>break (session,started),
                        Ok(Err(error @ listener::StartError::Conversation(conversation::Error::Deadline)))=>{
                            let counts=session.time_sync_counts();
                            println!("trial_stage=conversation_deadline phase={:?} effect_prepared={} attempts={} management_gate_passed={} sync_uncorrelated={} sync_correlated={} sync_correlated_expected={}",session.phase(),approval.0.get(),attempts,guard.management_gate_passed.get(),counts.uncorrelated,counts.correlated,counts.correlated_response_expected);
                            return Err(error.into());
                        },
                        Ok(Err(listener::StartError::Conversation(conversation::Error::SessionRetired {reason:receive::Stop::TransportDetail(receive::TransportFailure::Io(std::io::ErrorKind::UnexpectedEof)),phase:fss_reference::unifi_direct::Phase::AwaitHello,..}))) if !approval.0.get() && attempts<MAX_INITIAL_CONNECTIONS && cx.now()<deadline=>println!("trial_stage=pre_effect_websocket_eof_retry"),
                        Ok(Err(error @ listener::StartError::Conversation(conversation::Error::SessionRetired {reason:receive::Stop::TransportDetail(receive::TransportFailure::Io(std::io::ErrorKind::UnexpectedEof)),phase:fss_reference::unifi_direct::Phase::AwaitHello,..})))=>{
                            let counts=session.time_sync_counts();
                            println!("trial_stage=pre_hello_eof_stop effect_prepared={} attempts={} deadline_elapsed={} sync_uncorrelated={} sync_correlated={} sync_correlated_expected={}",approval.0.get(),attempts,cx.now()>=deadline,counts.uncorrelated,counts.correlated,counts.correlated_response_expected);
                            return Err(error.into());
                        },
                        Ok(Err(error))=>return Err(error.into()),
                        Err(_)=>{
                            let counts=session.time_sync_counts();
                            println!("trial_stage=startup_deadline phase={:?} effect_prepared={} attempts={} management_gate_passed={} sync_uncorrelated={} sync_correlated={} sync_correlated_expected={}",session.phase(),approval.0.get(),attempts,guard.management_gate_passed.get(),counts.uncorrelated,counts.correlated,counts.correlated_response_expected);
                            return Err("controller startup deadline elapsed; effects may require reconciliation".into());
                        },
                    }
                };
                drop(controller_listener);
                let mut supervisor=supervisor::Supervisor::new(session,started.pipeline,management);
                let mut sync_index=8usize; let mut source_omitted=0usize; let mut steps=0u32;
                let capture:ResultBox<(usize,usize,u32,u32)> = async {
                    loop {
                        steps=steps.checked_add(1).ok_or("step count overflow")?; if steps>200_000 { return Err("step limit reached".into()); }
                        let operation=syncs.get(sync_index).ok_or("time-sync limit reached")?;
                        match supervisor.step(&mut owner,operation,args.wait.min(MAX_IO_WAIT)).await {
                            supervisor::Step::TimeSyncWritten=>sync_index+=1,
                            supervisor::Step::Media(pipeline::Step::Progress {..}) | supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Buffered))=>(),
                            supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {record,..}))=>source_omitted=source_omitted.saturating_add(record.bytes().len()),
                            supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Segment(segment)))=>{
                                for record in segment.source() {source_omitted=source_omitted.saturating_add(record.bytes().len());}
                                let initialization=supervisor.initialization().ok_or("missing initialization")?;
                                let mut movie=initialization.bytes().to_vec(); movie.extend_from_slice(segment.fragment().bytes());
                                let demux=AvcMp4::parse(&movie,None,DemuxLimits::default())?;
                                let count=demux.samples().len().min(3); if count==0 {return Err("no video samples".into());}
                                let annex=demux.annex_b(0,count)?;
                                task.checkpoint_for(RuntimeGrant::MediaDecode,&resource,clock.now()?,&BudgetVector::ZERO)?;
                                let mut decoder=fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                                let mut frames=decoder.decode_annex_b(annex.bytes())?; frames.extend(decoder.finish()?);
                                let frame=frames.first().ok_or("no decoded frame")?;
                                let mut cost=BudgetVector::ZERO; cost.bytes=u64::try_from(movie.len())?; cost.storage_operations=5;
                                task.checkpoint_for(RuntimeGrant::ObjectStage,&args.output.to_string_lossy(),clock.now()?,&cost)?;
                                write_clip(&args.output,&movie)?;
                                return Ok((movie.len(),frames.len(),frame.width(),frame.height()));
                            }
                            supervisor::Step::Idle=>return Err("camera media timed out".into()),
                            other=>return Err(format!("controller or media stopped: {other:?}").into()),
                        }
                    }
                }.await;
                let retirement=supervisor.retire();
                for record in retirement.media.recorder.pending { source_omitted=source_omitted.saturating_add(record.bytes().len()); }
                source_omitted=source_omitted.saturating_add(retirement.media.ingress.framing.bytes().len());
                if let Some(buffered)=retirement.media.ingress.buffered {source_omitted=source_omitted.saturating_add(buffered.source.bytes().len().saturating_sub(buffered.appended));}
                if let Some(pending)=retirement.media.ingress.source.pending {source_omitted=source_omitted.saturating_add(pending.bytes().len());}
                let (clip_bytes,frames,width,height)=capture?;
                println!("trial_complete clip_bytes={clip_bytes} decoded_frames={frames} width={width} height={height} source_bytes_omitted={source_omitted} identity=network_claim effects=reconciliation_required continuous_recording=false");
                Ok(())
            }.await;
            let completed_at=clock.now().unwrap_or(deadline);
            let outcome=if output.is_ok() {TaskOutcome::Indeterminate("camera settings and protocol effects require reconciliation".into())} else {TaskOutcome::Failed("trial failed; effect journal may require reconciliation".into())};
            TaskCompletion {output,outcome,completed_at}
        }).await?;
        result.receipt?; result.output
    })
}
fn main() {
    if let Err(error) = options().and_then(run) {
        eprintln!("trial stopped: {error}; effect journal may require reconciliation");
        std::process::exit(1);
    }
}
