#![forbid(unsafe_code)]
#![cfg(unix)]
//! Bounded, owner-authorized direct UniFi interoperability trial.
//! This is a laboratory executable, not a continuous recorder or enrolled
//! service. It uses experimental TLS and unverified IP/MAC admission.
use asupersync::{runtime::RuntimeBuilder, time::timeout_at};
#[cfg(target_os = "linux")]
#[path = "../../../unifi_https_snapshot_lab/src/auth.rs"]
mod auth;
#[path = "trial_checkpoint/mod.rs"]
mod trial_checkpoint;
use fss_container::{
    Mp4Limits,
    demux::{AvcMp4, DemuxLimits},
    flv_av,
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
use fss_packet::extended_flv::{
    Limits as FlvLimits, aac, aac_track,
    stream::{Framer, SearchMode},
};
#[cfg(target_os = "linux")]
use fss_reference::unifi_direct::{camera_api, camera_http, discovery, handoff, setup};
use fss_reference::{
    onvif::wire::UtcDateTime,
    unifi_direct::{
        AudioCodec, Controller, Identity, Observation, TimeSyncPolicy, VideoChannel, VideoCodec,
        av_recording, controller_listener, conversation, intent, listener, management,
        metered::{MeteredClock, MeteredIo},
        owner, pipeline, receive, recording, supervisor,
        upgrade::ProtocolPolicy,
    },
};
use fss_runtime::{
    authority::AuthorityCx,
    effect::{CommitApproval, CommittedEffect, EffectCoordinator, PrepareSpec, PreparedEffect},
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
#[cfg(target_os = "linux")]
use unifi_tls_05_server_lab::{camera_tls, setup_upgrade};

type ResultBox<T> = Result<T, Box<dyn Error>>;
const USAGE: &str = "usage: unifi_direct_trial LISTEN_IPV4:PORT CAMERA_IPV4|auto CAMERA_MAC_HEX CERT_DER KEY_DER JOURNAL_DIR OUTPUT_MP4 CONTROLLER_UUID [WAIT_SECONDS] [--allow-correlated-timesync|--bounded-prehello-clock|--bounded-any-prehello-clock] [--media-before-reply] [--reply-events] [--reply-startup-requests] [--lab-aac-config=HEX|--lab-aac-source] [--lab-trailer16-av-flag|--lab-zero-stream-id] [--lab-segments=N] [--auto-discovery=PREFIX] [--anchored-journal=KEEPER_DIR,TRUSTED_ROOT_DIR] [--setup-camera=DISCOVERY_PORT,HTTPS_PORT,CAMERA_CERT_DER,CREDENTIAL_FILE[,chunked]] --owner-authorized";
const RECOVERY_USAGE: &str = "usage: unifi_direct_trial --inspect-anchored JOURNAL_DIR KEEPER_DIR TRUSTED_ROOT_DIR CONTROLLER_UUID CAMERA_MAC_HEX --owner-authorized";
const MAX_SOURCE: u64 = 32 * 1024 * 1024;
const MAX_CLIP: usize = 32 * 1024 * 1024;
const MAX_INITIAL_CONNECTIONS: usize = 8;
const MAX_IO_WAIT: Duration = Duration::from_secs(30);

struct Options {
    listen: SocketAddrV4,
    camera: Option<Ipv4Addr>,
    discovery_prefix: Option<u8>,
    mac: [u8; 6],
    cert: PathBuf,
    key: PathBuf,
    journal: PathBuf,
    anchored_journal: Option<(PathBuf, PathBuf)>,
    output: PathBuf,
    uuid: String,
    wait: Duration,
    time_sync_policy: TimeSyncPolicy,
    media_before_reply: bool,
    reply_events: bool,
    reply_startup_requests: bool,
    lab_aac_config: Option<[u8; 2]>,
    lab_aac_source: bool,
    lab_g4_trailer: bool,
    lab_zero_stream_id: bool,
    lab_segments: usize,
    setup: Option<SetupOptions>,
}
struct SetupOptions {
    discovery_port: u16,
    https_port: u16,
    cert: PathBuf,
    credential: PathBuf,
    chunked: bool,
}
fn options() -> ResultBox<Options> {
    let mut args: Vec<_> = std::env::args().skip(1).collect();
    if args.pop().as_deref() != Some("--owner-authorized") {
        return Err(USAGE.into());
    }
    let setup = if let Some(value) = args.last().and_then(|s| s.strip_prefix("--setup-camera=")) {
        if !cfg!(target_os = "linux") {
            return Err("camera setup trial requires Linux".into());
        }
        let fields: Vec<_> = value.split(',').collect();
        if !(fields.len() == 4 || (fields.len() == 5 && fields[4] == "chunked")) {
            return Err(USAGE.into());
        }
        let discovery_port = fields[0].parse::<u16>()?;
        let https_port = fields[1].parse::<u16>()?;
        let cert = PathBuf::from(fields[2]);
        let credential = PathBuf::from(fields[3]);
        if discovery_port == 0
            || https_port == 0
            || !cert.is_absolute()
            || !credential.is_absolute()
        {
            return Err("invalid camera setup arguments".into());
        }
        let value = SetupOptions {
            discovery_port,
            https_port,
            cert,
            credential,
            chunked: fields.len() == 5,
        };
        args.pop();
        Some(value)
    } else {
        None
    };
    let anchored_journal = if let Some(value) = args
        .last()
        .and_then(|s| s.strip_prefix("--anchored-journal="))
    {
        let (keeper, root) = value.split_once(',').ok_or(USAGE)?;
        if keeper.is_empty() || root.is_empty() || root.contains(',') {
            return Err(USAGE.into());
        }
        let paths = (PathBuf::from(keeper), PathBuf::from(root));
        args.pop();
        Some(paths)
    } else {
        None
    };
    let discovery_prefix = if let Some(value) = args.last().and_then(|s| s.strip_prefix("--auto-discovery=")) {
        let prefix = value.parse::<u8>()?;
        if !(8..=30).contains(&prefix) {
            return Err("automatic discovery prefix must be 8 to 30".into());
        }
        args.pop();
        Some(prefix)
    } else {
        None
    };
    let lab_segments =
        if let Some(value) = args.last().and_then(|s| s.strip_prefix("--lab-segments=")) {
            let count = value
                .parse::<usize>()
                .map_err(|_| "laboratory segment count must be 1 to 8")?;
            if !(1..=8).contains(&count) {
                return Err("laboratory segment count must be 1 to 8".into());
            }
            args.pop();
            count
        } else {
            1
        };
    let lab_zero_stream_id = args.last().is_some_and(|s| s == "--lab-zero-stream-id");
    if lab_zero_stream_id {
        args.pop();
    }
    let lab_g4_trailer = args.last().is_some_and(|s| s == "--lab-trailer16-av-flag");
    if lab_g4_trailer {
        args.pop();
    }
    if lab_zero_stream_id && lab_g4_trailer {
        return Err("choose one laboratory framing policy".into());
    }
    let lab_aac_source = args.last().is_some_and(|s| s == "--lab-aac-source");
    if lab_aac_source {
        args.pop();
    }
    let lab_aac_config = if let Some(hex) = args
        .last()
        .and_then(|s| s.strip_prefix("--lab-aac-config="))
    {
        if hex.len() != 4 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("laboratory AAC configuration must be four hexadecimal digits".into());
        }
        let config = [
            u8::from_str_radix(&hex[..2], 16)?,
            u8::from_str_radix(&hex[2..], 16)?,
        ];
        aac::Configuration::parse_explicit(&config)?;
        args.pop();
        Some(config)
    } else {
        None
    };
    if lab_aac_source && lab_aac_config.is_some() {
        return Err("choose one laboratory AAC configuration source".into());
    }
    let reply_startup_requests = args.last().is_some_and(|s| s == "--reply-startup-requests");
    if reply_startup_requests {
        args.pop();
    }
    let reply_events = args.last().is_some_and(|s| s == "--reply-events");
    if reply_events {
        args.pop();
    }
    let media_before_reply = args.last().is_some_and(|s| s == "--media-before-reply");
    if media_before_reply {
        args.pop();
    }
    if (reply_events || reply_startup_requests) && !media_before_reply {
        return Err("startup replies require --media-before-reply in this trial".into());
    }
    let time_sync_policy = match args.last().map(String::as_str) {
        Some("--allow-correlated-timesync") => {
            args.pop();
            TimeSyncPolicy::ExplicitCorrelatedRequests
        }
        Some("--bounded-prehello-clock") => {
            args.pop();
            TimeSyncPolicy::BoundedPreHelloClockExchange
        }
        Some("--bounded-any-prehello-clock") => {
            args.pop();
            TimeSyncPolicy::BoundedAnyPreHelloClockExchange
        }
        _ => TimeSyncPolicy::UncorrelatedOnly,
    };
    if !(args.len() == 8 || args.len() == 9) {
        return Err(USAGE.into());
    }
    let listen: SocketAddrV4 = args[0].parse()?;
    let camera: Option<Ipv4Addr> = if args[1] == "auto" { None } else { Some(args[1].parse()?) };
    if listen.port() == 0
        || camera.is_some_and(|ip| !(ip.is_private() || ip.is_loopback() || ip.is_link_local()))
    {
        return Err("invalid scoped addresses".into());
    }
    if camera.is_none() != discovery_prefix.is_some()
        || (discovery_prefix.is_some() && (setup.is_none() || !cfg!(target_os = "linux")))
    {
        return Err("automatic discovery requires auto, a scope prefix and Linux camera setup".into());
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
    if let Some((keeper, root)) = &anchored_journal {
        let paths = [&journal, keeper, root, &output];
        if paths
            .iter()
            .any(|path| !path.is_absolute() || std::fs::symlink_metadata(path).is_ok())
            || paths.iter().enumerate().any(|(i, path)| {
                paths
                    .iter()
                    .skip(i + 1)
                    .any(|other| path.starts_with(other) || other.starts_with(path))
            })
        {
            return Err(
                "anchored journal and output paths must be distinct, absolute and absent".into(),
            );
        }
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
        discovery_prefix,
        mac,
        cert,
        key,
        journal,
        anchored_journal,
        output,
        uuid: args[7].clone(),
        wait: Duration::from_secs(wait_seconds),
        time_sync_policy,
        media_before_reply,
        reply_events,
        reply_startup_requests,
        lab_aac_config,
        lab_aac_source,
        lab_g4_trailer,
        lab_zero_stream_id,
        lab_segments,
        setup,
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
#[cfg(target_os = "linux")]
struct SetupPolicy<'a, F> {
    base: &'a Policy,
    lease: &'a auth::Lease,
    check: F,
    camera: ContentDigest,
    peer_admission: ContentDigest,
    fence: u64,
}
#[cfg(target_os = "linux")]
impl<F: Fn() -> Result<(), &'static str>> camera_http::Authority for SetupPolicy<'_, F> {
    fn permits(&self, peer: Ipv4Addr, generation: u64, _: camera_http::Operation) -> bool {
        peer == self.base.camera && generation == 1 && self.lease.revalidate(&self.check).is_ok()
    }
}
#[cfg(target_os = "linux")]
impl<F: Fn() -> Result<(), &'static str>> setup::Admission for SetupPolicy<'_, F> {
    fn permits(
        &self,
        candidate: &discovery::CameraCandidate,
        camera: ContentDigest,
        admission: ContentDigest,
        generation: u64,
        fence: u64,
    ) -> bool {
        *candidate.source().ip() == self.base.camera
            && candidate.mac() == Some(self.base.mac)
            && camera == self.camera
            && admission == self.peer_admission
            && generation == 1
            && fence == self.fence
            && self.lease.revalidate(&self.check).is_ok()
    }
}
#[cfg(target_os = "linux")]
impl<F: Fn() -> Result<(), &'static str>> camera_api::HandoffAuthority for SetupPolicy<'_, F> {
    fn permits(
        &self,
        plan: &handoff::Plan,
        current: handoff::Preconditions,
        permit: &CommittedEffect,
    ) -> bool {
        plan.check_current(current).is_ok()
            && permit.fence() == self.fence
            && self.lease.revalidate(&self.check).is_ok()
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
    reply_events: bool,
    reply_startup_requests: bool,
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
    fn permits_event_reply(
        &self,
        mac: [u8; 6],
        intent: management::Intent,
        permit: &CommittedEffect,
    ) -> bool {
        self.reply_events
            && intent.source_digest().is_some()
            && receive::ManagementAuthority::permits(self, mac, intent, permit)
    }
    fn permits_startup_request_reply(
        &self,
        mac: [u8; 6],
        intent: management::Intent,
        permit: &CommittedEffect,
    ) -> bool {
        self.reply_startup_requests
            && intent.source_digest().is_some()
            && receive::ManagementAuthority::permits(self, mac, intent, permit)
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
struct TrialAv {
    initialization: flv_av::Initialization,
    muxer: av_recording::Muxer,
    configuration: [u8; 2],
    source_label: &'static str,
}

fn append_bounded(output: &mut Vec<u8>, bytes: &[u8]) -> ResultBox<()> {
    if output
        .len()
        .checked_add(bytes.len())
        .is_none_or(|size| size > MAX_CLIP)
    {
        return Err("laboratory clip byte limit exceeded".into());
    }
    output.try_reserve(bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn derive_av_fragment(
    init: &flv_av::Initialization,
    config: &aac::Configuration<'_>,
    muxer: &mut av_recording::Muxer,
    segment: &recording::Segment,
    video_movie: &[u8],
    source_label: &str,
) -> ResultBox<Vec<u8>> {
    let limits = Mp4Limits::default();
    let fragment = muxer.fragment(init, segment)?;
    flv_av::verify_archived_initialization(video_movie, init.bytes(), config, limits)?;
    flv_av::verify_archived_fragment(
        segment.fragment().bytes(),
        fragment.bytes(),
        fragment.audio(),
        limits,
    )?;
    let mut output = Vec::new();
    append_bounded(&mut output, fragment.bytes())?;
    println!(
        "trial_stage=av_fragment audio_samples={} configuration_source={source_label} av_alignment=unverified",
        fragment.audio().len()
    );
    Ok(output)
}
fn run(args: Options) -> ResultBox<()> {
    println!("trial_time_sync_policy={:?}", args.time_sync_policy);
    println!("trial_media_before_reply={}", args.media_before_reply);
    println!("trial_event_replies={}", args.reply_events);
    println!(
        "trial_startup_request_replies={}",
        args.reply_startup_requests
    );
    println!("trial_segment_limit={}", args.lab_segments);
    println!(
        "trial_framing={}",
        if args.lab_zero_stream_id {
            "zero_stream_id_heuristic"
        } else if args.lab_g4_trailer {
            "trailer16_av_flag_heuristic"
        } else {
            "conservative"
        }
    );
    if args.lab_aac_config.is_some() {
        println!(
            "trial_audio=experimental_explicit_config configuration_epoch=unverified av_alignment=unverified"
        );
    }
    if args.lab_aac_source {
        println!(
            "trial_audio=experimental_in_band_config configuration_epoch=connection_claim av_alignment=unverified"
        );
    }
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
        RuntimeGrant::ObserveStatus,
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
            // Keep setup and later controller effects distinct for reconnect
            // decisions, while retaining both through task completion.
            let setup_approval=Approval(Cell::new(false));
            let approval=Approval(Cell::new(false));
            let output:ResultBox<()> = async {
                task.checkpoint_for(RuntimeGrant::AdapterAuth,"trial:tls-key",clock.now()?,&BudgetVector::ZERO)?;
                let cert=bounded_read(&args.cert,false)?; let key=bounded_read(&args.key,true)?;
                let config=ServerConfig::builder_with_provider(Arc::new(rustls_pure::provider())).with_protocol_versions(&[&rustls::version::TLS13])?.with_no_client_auth().with_single_cert(vec![CertificateDer::from(cert)],PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))?;
                #[cfg(target_os="linux")]
                let discovered=if let Some(prefix)=args.discovery_prefix {
                    let setup_args=args.setup.as_ref().ok_or("automatic discovery requires setup")?;
                    let broadcast=Ipv4Addr::from(u32::from(*args.listen.ip()) | (u32::MAX >> prefix));
                    let cfg=discovery::Config::new(*args.listen.ip(),prefix,SocketAddrV4::new(broadcast,setup_args.discovery_port),"unifi:discovery",Duration::from_secs(2),64)?;
                    let report=discovery::discover(task,cx,clock.now()?,&cfg).await?;
                    let index=report.select_mac_claim(args.mac)?;
                    Some((report,index))
                } else { None };
                #[cfg(target_os="linux")]
                let camera_address=args.camera.or_else(|| discovered.as_ref().map(|(report,index)| *report.cameras[*index].source().ip())).ok_or("camera address unavailable")?;
                #[cfg(not(target_os="linux"))]
                let camera_address=args.camera.ok_or("camera address unavailable")?;
                let journal:Box<dyn fss_runtime::effect_journal::EffectJournalStore>=if let Some((keeper,root))=&args.anchored_journal {
                    for path in [&args.journal,keeper,root] {
                        task.checkpoint_for(RuntimeGrant::ObjectStage,&path.to_string_lossy(),clock.now()?,&BudgetVector::ZERO)?;
                    }
                    let journal=trial_checkpoint::create(&args.journal,keeper,root,&args.uuid,args.mac)?;
                    println!("trial_journal=anchored root_trust=operator_selected independence=unverified");
                    journal
                } else {
                    Box::new(FileEffectJournal::create(&args.journal,EffectJournalLimits::default(),Arc::new(HostSpoolIo))?)
                };
                let mut effects=EffectCoordinator::with_journal(journal)?;
                let mut binding=Vec::from(args.mac); binding.extend_from_slice(&camera_address.octets());
                let camera=ContentDigest::sha256(&binding); let resource=format!("camera:{}",camera.to_text());
                let mut leases=LeaseRegistry::new();
                let fence=leases.acquire(&resource,"region:unifi-direct-trial",None,clock.now()?)?.fence;
                let leases=RefCell::new(leases);
                let camera_pin=match &args.setup {Some(setup)=>Some(bounded_read(&setup.cert,false)?),None=>None};
                let admission=match &camera_pin {Some(pin)=>ContentDigest::sha256(pin),None=>ContentDigest::sha256(b"owner-selected network address and camera MAC; not cryptographic identity")};
                let management=management::Preconditions {camera,peer_admission:admission,session_generation:1,previous_association:None,previous_clock:None,lease_fence:fence};
                let stream_conditions=intent::Preconditions {camera,peer_admission:admission,stream_generation:1,previous_settings:None,lease_fence:fence};
                let policy=Policy {local:*args.listen.ip(),camera:camera_address,mac:args.mac};
                let mut controller_listener=controller_listener::Listener::bind(task,cx,clock,&policy,args.listen,&resource,args.wait.min(MAX_IO_WAIT)).await?;
                println!("controller_listener_ready identity=network_claim tls=experimental timeout_seconds={}",args.wait.as_secs());
                let config=Arc::new(config);
                let guard=Guard {leases:&leases,clock,mac:args.mac,management_gate_passed:Cell::new(false),reply_events:args.reply_events,reply_startup_requests:args.reply_startup_requests};
                let wall=Wall {task,clock};
                #[cfg(target_os="linux")]
                let mut setup_session=if let Some(setup_args)=&args.setup {
                    let (report,index)=if let Some(found)=discovered {found} else {
                        let prefix=(u32::from(*args.listen.ip()) ^ u32::from(camera_address)).leading_zeros().min(32) as u8;
                        if prefix==0 {return Err("camera and listener are outside the scoped discovery network".into());}
                        let discovery_config=discovery::Config::new(*args.listen.ip(),prefix,SocketAddrV4::new(camera_address,setup_args.discovery_port),"unifi:discovery",Duration::from_secs(2),64)?;
                        let report=discovery::discover(task,cx,clock.now()?,&discovery_config).await?;
                        let index=report.select_mac_claim(args.mac)?;
                        if *report.cameras[index].source().ip()!=camera_address {return Err("selected discovery address mismatch".into());}
                        (report,index)
                    };
                    let pin=camera_pin.as_ref().ok_or("missing camera certificate pin")?;
                    let tls=camera_tls::connect(cx,task,clock,SocketAddrV4::new(camera_address,setup_args.https_port),pin,&resource,Duration::from_secs(10)).await?;
                    let check_auth=||->Result<(), &'static str> {
                        cx.checkpoint().map_err(|_| "runtime cancelled")?;
                        task.checkpoint_for(RuntimeGrant::AdapterAuth,&resource,clock.now().map_err(|_| "clock unavailable")?,&BudgetVector::ZERO).map_err(|_| "camera authorization unavailable")
                    };
                    let lease=auth::Lease::load(&setup_args.credential,&check_auth)?;
                    let setup_policy=SetupPolicy {base:&policy,lease:&lease,check:check_auth,camera,peer_admission:admission,fence};
                    let plaintext=MeteredIo::with_clock(tls,clock,&resource,4096)?;
                    let mut http=camera_http::Owner::new(plaintext,task,cx,clock,&setup_policy,camera_address,1,&resource)?;
                    let operation=OperationId::parse("operation:unifi-trial-handoff")?;
                    let setup_config=setup::Config {report:&report,index,camera,peer_admission:admission,generation:1,fence,destination:*args.listen.ip(),operation:&operation,credential:&lease.secret.0,wait:Duration::from_secs(20)};
                    let mut trace=setup::AcceptTrace::default();
                    let controller=Controller::new_with_time_sync_policy(Identity::new("FSS",&args.uuid,"1.20.0")?,1,args.time_sync_policy)?;
                    let mut setup_owner=setup::Owner {cx,task,clock,effects:&mut effects,leases:&leases,approval:&setup_approval,admission:&setup_policy,handoff_authority:&setup_policy};
                    let framing=if setup_args.chunked {handoff::Framing::Chunked} else {handoff::Framing::ContentLength};
                    let setup_result=setup_upgrade::setup_and_upgrade_with_retries(cx,&mut setup_owner,&mut controller_listener,args.listen.port(),&mut http,&setup_config,framing,16*1024,args.wait.min(MAX_IO_WAIT),Duration::from_secs(20),MAX_INITIAL_CONNECTIONS,&mut trace,config.clone(),ProtocolPolicy::RequireOffer,&policy,controller).await;
                    let outcome=match trace.outcome() {
                        None=>"unavailable",
                        Some(setup::Outcome::AlreadyAssociated {..})=>"already_associated",
                        Some(setup::Outcome::Refused {..})=>"refused",
                        Some(setup::Outcome::Indeterminate {..})=>"indeterminate",
                        Some(setup::Outcome::Observed {readback,..})=>match readback {
                            handoff::Readback::Requested=>"requested",
                            handoff::Readback::Previous=>"previous",
                            handoff::Readback::Different=>"different",
                            handoff::Readback::Unset=>"unset",
                            handoff::Readback::Missing=>"missing",
                            handoff::Readback::Unsupported=>"unsupported",
                        },
                    };
                    let accept_started=trace.accept_started();
                    let dispatch_started=trace.setup_mut().dispatch_started();
                    println!("trial_stage=setup_trace outcome={outcome} dispatch_started={dispatch_started} accept_started={accept_started} claims_unverified=true");
                    let session=setup_result?;
                    let handoff=if matches!(trace.outcome(),Some(setup::Outcome::AlreadyAssociated {..})) {"no_effect_observed"} else {"requires_reconciliation"};
                    println!("trial_stage=setup_websocket_accepted https_pin=matched controller_peer=network_claim handoff={handoff}");
                    Some(session)
                } else {None};
                #[cfg(not(target_os="linux"))]
                let mut setup_session:Option<unifi_tls_05_server_lab::setup_upgrade::Session<'_, '_, '_>>=None;
                let deadline=cx.now()+args.wait;
                let mut owner=conversation::Owner {cx,task,clock,effects:&mut effects,leases:&leases,approval:&approval,management_authority:&guard,stream_authority:&guard,wall:&wall};
                let hello=OperationId::parse("operation:unifi-trial-hello")?; let agreement=OperationId::parse("operation:unifi-trial-agreement")?; let stream=OperationId::parse("operation:unifi-trial-stream")?;
                let syncs:Vec<_>=(0..128).map(|i|OperationId::parse(format!("operation:unifi-trial-sync-{i:04}"))).collect::<Result<_,_>>()?;
                let event_ops:Vec<_>=(0..64).map(|i|OperationId::parse(format!("operation:unifi-trial-event-{i:04}"))).collect::<Result<_,_>>()?;
                let event_replies=conversation::StartupEventReplies {operations:&event_ops};
                let startup_events=fss_reference::unifi_direct::events::StartupInbox::new(8,8*fss_reference::unifi_direct::MAX_MESSAGE_BYTES)?;
                let startup_sync_limit=if matches!(args.time_sync_policy, TimeSyncPolicy::BoundedPreHelloClockExchange | TimeSyncPolicy::BoundedAnyPreHelloClockExchange) { fss_reference::unifi_direct::MAX_PRE_HELLO_TIME_SYNC_REPLIES } else { 8 };
                let mut attempts=0;
                let (session,started,event_trace,startup_trace)=loop {
                    let remaining=Duration::from_nanos(deadline.as_nanos().saturating_sub(cx.now().as_nanos()));
                    if remaining.is_zero() { return Err("controller TLS deadline elapsed".into()); }
                    let mut session=if let Some(session)=setup_session.take() {
                        attempts+=1;
                        session
                    } else {
                    if args.setup.is_some() && approval.0.get() {return Err("controller effect started; reconcile before another attempt".into());}
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
                    owner::accept_guarded(plaintext,ProtocolPolicy::RequireOffer,&policy,gate,controller,remaining.min(MAX_IO_WAIT)).await?
                    };
                    if args.reply_startup_requests {session.bind_startup_events_and_requests(&startup_events)?;} else {session.bind_startup_events(&startup_events)?;}
                    println!("trial_stage=websocket_accepted");
                    let remaining=Duration::from_nanos(deadline.as_nanos().saturating_sub(cx.now().as_nanos()));
                    if remaining.is_zero() {return Err("controller startup deadline elapsed".into());}
                    let io_wait=remaining.min(MAX_IO_WAIT);
                    let request=listener::Start {bind:SocketAddrV4::new(*args.listen.ip(),0),resource:&resource,admission:&policy,channel:VideoChannel::Video2,video:VideoCodec::H264,audio:AudioCodec::Aac,stream_name:"0123456789abcdef",hello:&hello,agreement:&agreement,stream:&stream,time_sync:&syncs[..startup_sync_limit],management,stream_conditions,chunk_bytes:16*1024,max_bytes:MAX_SOURCE,bind_wait:io_wait,conversation_wait:io_wait,accept_wait:io_wait};
                    let framing=if args.lab_zero_stream_id {SearchMode::ZeroStreamId} else if args.lab_g4_trailer {SearchMode::StructuredTrailer16AvFlag} else {SearchMode::Conservative};
                    let framer=Framer::with_mode(FlvLimits::default(),1024*1024,framing)?; let recorder=recording::Recorder::new(SourceKey {connection:attempts as u64,generation:1},recording::Limits::default())?;
                    let mut startup_trace=listener::StartTrace::default();
                    let mut event_trace=conversation::StartupEventTrace::default();
                    let startup=async {
                        if args.media_before_reply {
                            let result=if args.reply_events || args.reply_startup_requests {
                                listener::start_before_reply_with_events_tracked(&mut owner,&mut session,&request,framer,recorder,&mut startup_trace,None,&event_replies,&mut event_trace).await
                            } else {
                                listener::start_before_reply_tracked(&mut owner,&mut session,&request,framer,recorder,&mut startup_trace).await
                            };
                            result.and_then(|started| {
                                for observation in started.observations_during_accept {
                                    if let Observation::StreamSettingsReply {success,..}=observation {
                                        if success==Some(false) {return Err(listener::StartError::Conversation(conversation::Error::Unexpected));}
                                        println!("trial_stage=stream_reply_observed success_claim_present={}",success.is_some());
                                    }
                                }
                                Ok(started.pipeline)
                            })
                        } else {
                            listener::start_tracked(&mut owner,&mut session,&request,framer,recorder,&mut startup_trace).await.map(|started| started.pipeline)
                        }
                    };
                    let startup_result=timeout_at(deadline,startup).await;
                    if event_trace.attempted() {
                        println!("trial_stage=startup_event_replies attempts={} effects_require_reconciliation=true",event_trace.attempts().len());
                    }
                    if !matches!(&startup_result,Ok(Ok(_))) && !startup_events.is_empty() {
                        println!("trial_stage=startup_events_omitted frames={} source_bytes={} identity=network_claim",startup_events.len(),startup_events.source_bytes());
                    }
                    if startup_trace.attempted() && !matches!(&startup_result,Ok(Ok(_))) {
                        let settings_replies=startup_trace.observations().iter().filter(|observation|matches!(observation,Observation::StreamSettingsReply {..})).count();
                        println!("trial_stage=startup_trace dispatch_observed={} clock_requests={} clock_replies_written={} settings_replies={} effects_require_reconciliation=true",startup_trace.dispatched().is_some(),startup_trace.clock_requests(),startup_trace.clock_replies_written(),settings_replies);
                    }
                    let unhandled=session.unhandled_request_counts();
                    println!("trial_stage=unhandled_response_requests pre_hello={} later={} correlated={} claims_unverified=true",unhandled.pre_hello,unhandled.later,unhandled.correlated);
                    match startup_result {
                        Ok(Ok(pipeline))=>break (session,pipeline,event_trace,startup_trace),
                        Ok(Err(error @ listener::StartError::Conversation(conversation::Error::Deadline)))=>{
                            let counts=session.time_sync_counts();
                            println!("trial_stage=conversation_deadline phase={:?} effect_prepared={} attempts={} management_gate_passed={} sync_uncorrelated={} sync_correlated={} sync_correlated_expected={} sync_to_last_written={} sync_expected_to_last_written={}",session.phase(),approval.0.get(),attempts,guard.management_gate_passed.get(),counts.uncorrelated,counts.correlated,counts.correlated_response_expected,counts.correlated_to_last_written_reply,counts.correlated_expected_to_last_written_reply);
                            return Err(error.into());
                        },
                        Ok(Err(listener::StartError::Conversation(conversation::Error::SessionRetired {reason:receive::Stop::TransportDetail(receive::TransportFailure::Io(std::io::ErrorKind::UnexpectedEof)),phase:fss_reference::unifi_direct::Phase::AwaitHello,..}))) if !approval.0.get() && startup_events.is_empty() && attempts<MAX_INITIAL_CONNECTIONS && cx.now()<deadline=>println!("trial_stage=pre_effect_websocket_eof_retry"),
                        Ok(Err(error @ listener::StartError::Conversation(conversation::Error::SessionRetired {reason:receive::Stop::TransportDetail(receive::TransportFailure::Io(std::io::ErrorKind::UnexpectedEof)),phase:fss_reference::unifi_direct::Phase::AwaitHello,..})))=>{
                            let counts=session.time_sync_counts();
                            println!("trial_stage=pre_hello_eof_stop effect_prepared={} attempts={} deadline_elapsed={} sync_uncorrelated={} sync_correlated={} sync_correlated_expected={} sync_to_last_written={} sync_expected_to_last_written={}",approval.0.get(),attempts,cx.now()>=deadline,counts.uncorrelated,counts.correlated,counts.correlated_response_expected,counts.correlated_to_last_written_reply,counts.correlated_expected_to_last_written_reply);
                            return Err(error.into());
                        },
                        Ok(Err(error))=>return Err(error.into()),
                        Err(_)=>{
                            let counts=session.time_sync_counts();
                            println!("trial_stage=startup_deadline phase={:?} effect_prepared={} attempts={} management_gate_passed={} sync_uncorrelated={} sync_correlated={} sync_correlated_expected={} sync_to_last_written={} sync_expected_to_last_written={}",session.phase(),approval.0.get(),attempts,guard.management_gate_passed.get(),counts.uncorrelated,counts.correlated,counts.correlated_response_expected,counts.correlated_to_last_written_reply,counts.correlated_expected_to_last_written_reply);
                            return Err("controller startup deadline elapsed; effects may require reconciliation".into());
                        },
                    }
                };
                drop(controller_listener);
                println!("trial_stage=startup_protocol_trace clocks={} effects_require_reconciliation=true",startup_trace.protocol().clocks().len());
                let mut startup_answered:Vec<ContentDigest>=event_trace.attempts().iter().map(|attempt|attempt.source()).collect();
                let mut event_index=event_trace.attempts().len();
                let mut supervisor=supervisor::Supervisor::new(session,started,management);
                let mut sync_index=startup_sync_limit; let mut source_omitted=0usize; let mut steps=0u32;
                let mut sync_traces=Vec::new(); sync_traces.try_reserve_exact(syncs.len())?;
                let mut audio_track=aac_track::Track::new(FlvLimits::default(),aac::Limits::default());
                let mut in_band_config=None;
                let mut assembled=Vec::new(); let mut av_owner:Option<TrialAv>=None;
                let mut segments_completed=0usize; let mut decoded_total=0usize; let mut dimensions=None;
                let capture:ResultBox<(usize,usize,u32,u32)> = async {
                    loop {
                        steps=steps.checked_add(1).ok_or("step count overflow")?; if steps>200_000 { return Err("step limit reached".into()); }
                        let operation=syncs.get(sync_index).ok_or("time-sync limit reached")?;
                        match supervisor.step(&mut owner,operation,args.wait.min(MAX_IO_WAIT)).await {
                            supervisor::Step::TimeSyncWritten { trace }=>{sync_traces.push(trace);sync_index+=1;},
                            supervisor::Step::TimeSyncStopped {error,trace}=>{sync_traces.push(trace);return Err(format!("time sync stopped: {error:?}; reconcile its journaled effect").into());},
                            supervisor::Step::TimeSyncInterrupted {trace}=>{sync_traces.push(trace);return Err("time sync interrupted; reconcile its journaled effect".into());},
                            supervisor::Step::StartupRequest(frame)=>{
                                println!("trial_stage=startup_request source_bytes_omitted={} identity=network_claim",frame.source().len());
                                if let Some(index)=startup_answered.iter().position(|digest|*digest==frame.digest()) {startup_answered.remove(index);} else {return Err("unknown startup request requires reconciliation".into());}
                            },
                            supervisor::Step::CameraEvent(frame)=>{
                                println!("trial_stage=camera_event kind={:?} source_bytes_omitted={} response_expected={}",frame.kind(),frame.source().len(),frame.response_expected());
                                if let Some(index)=startup_answered.iter().position(|digest|*digest==frame.digest()) {
                                    startup_answered.remove(index);
                                    println!("trial_stage=startup_event_already_answered");
                                } else if frame.response_expected() {
                                    if !args.reply_events {return Err("camera event reply required; reconcile before continuing".into());}
                                    let operation=event_ops.get(event_index).ok_or("event reply limit reached")?;
                                    let wall=owner.wall.observe().ok_or("event reply clock unavailable")?;
                                    let intent=supervisor.prepare_event_reply(&owner,&frame,&wall.timestamp)?;
                                    let prepared=task.prepare_effect(cx,&mut *owner.effects,&mut leases.borrow_mut(),PrepareSpec {
                                        operation,idempotency_key:IdempotencyKey::parse(operation.as_str())?,request_digest:intent.request_digest(),precondition_digest:intent.precondition_digest(),resource:&resource,fence,
                                        prepare_grant:RuntimeGrant::CameraManagementPrepare,commit_grant:RuntimeGrant::CameraManagementCommit,terminal_predicate:"independent event-reply reconciliation",
                                    },clock.now()?)?;
                                    let approval=owner.approval.approve(&prepared).ok_or("event reply approval refused")?;
                                    let permit=task.commit_effect(cx,&mut *owner.effects,&mut leases.borrow_mut(),prepared,clock.now()?,approval)?;
                                    match supervisor.dispatch_event_reply(&owner,intent,management,permit,args.wait.min(MAX_IO_WAIT)).await {
                                        Ok(receive::ManagementWrite::Written {..})=>{event_index+=1;println!("trial_stage=event_reply_written effects_require_reconciliation=true");},
                                        Ok(receive::ManagementWrite::Indeterminate {..})=>return Err("event reply indeterminate; reconcile before continuing".into()),
                                        Err(_)=>return Err("event reply refused; reconcile before continuing".into()),
                                    }
                                }
                            },
                            supervisor::Step::Observation(Observation::StreamSettingsReply {success,..}) if args.media_before_reply=>{
                                if success==Some(false) {return Err("camera reported stream-setting failure".into());}
                                println!("trial_stage=stream_reply_observed success_claim_present={}",success.is_some());
                            },
                            supervisor::Step::Media(pipeline::Step::Progress {..}) | supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Buffered))=>(),
                            supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {record,..}))=>{
                                source_omitted=source_omitted.saturating_add(record.bytes().len());
                                if args.lab_aac_source {
                                    let observation=audio_track.observe(&record)?;
                                    if matches!(observation,aac_track::Observation::Configuration {..}) {
                                        let bound=observation.bind_configuration(&record,FlvLimits::default(),aac::Limits::default())?;
                                        if bound.provisional() {return Err("provisional AAC source configuration".into());}
                                        in_band_config=Some((observation,record));
                                    }
                                }
                            },
                            supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Segment(segment)))=>{
                                for record in segment.source() {source_omitted=source_omitted.saturating_add(record.bytes().len());}
                                let initialization=supervisor.initialization().ok_or("missing initialization")?;
                                let mut video_movie=initialization.bytes().to_vec(); video_movie.extend_from_slice(segment.fragment().bytes());
                                let demux=AvcMp4::parse(&video_movie,None,DemuxLimits::default())?;
                                let count=demux.samples().len().min(3); if count==0 {return Err("no video samples".into());}
                                let annex=demux.annex_b(0,count)?;
                                task.checkpoint_for(RuntimeGrant::MediaDecode,&resource,clock.now()?,&BudgetVector::ZERO)?;
                                let mut decoder=fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                                let mut frames=decoder.decode_annex_b(annex.bytes())?; frames.extend(decoder.finish()?);
                                let frame=frames.first().ok_or("no decoded frame")?;
                                let current_dimensions=(frame.width(),frame.height());
                                if dimensions.is_some_and(|previous|previous!=current_dimensions) {return Err("video dimensions changed".into());}
                                dimensions=Some(current_dimensions);
                                decoded_total=decoded_total.checked_add(frames.len()).ok_or("decoded frame count overflow")?;
                                if av_owner.is_none() && (args.lab_aac_config.is_some() || args.lab_aac_source) {
                                    let limits=Mp4Limits::default();
                                    let owner=if let Some(config_bytes)=args.lab_aac_config {
                                        let config=aac::Configuration::parse_explicit(&config_bytes)?;
                                        let initialization=supervisor.av_initialization(&config)?.ok_or("missing A/V initialization")?;
                                        let origin=av_recording::segment_sender_clock_origin(&segment,&config,2000)?;
                                        println!("trial_stage=sender_clock_hypothesis audio_minus_video_ms={} fractional_tick_thousandths={} sync=unverified",origin.audio_minus_video_ms,origin.fractional_tick_thousandths);
                                        let muxer=av_recording::Muxer::new(&initialization,&config,origin.audio_ticks,5,1_000_000,limits.max_samples,limits)?;
                                        TrialAv {initialization,muxer,configuration:config_bytes,source_label:"external_unverified"}
                                    } else {
                                        let (observation,record)=in_band_config.as_ref().ok_or("no pre-video in-band AAC configuration")?;
                                        let bound=observation.bind_configuration(record,FlvLimits::default(),aac::Limits::default())?;
                                        let config=bound.configuration();
                                        let configuration:[u8;2]=config.bytes().try_into().map_err(|_|"invalid AAC configuration")?;
                                        let initialization=supervisor.av_initialization(config)?.ok_or("missing A/V initialization")?;
                                        let origin=av_recording::segment_sender_clock_origin(&segment,config,2000)?;
                                        println!("trial_stage=sender_clock_hypothesis audio_minus_video_ms={} fractional_tick_thousandths={} sync=unverified",origin.audio_minus_video_ms,origin.fractional_tick_thousandths);
                                        let muxer=av_recording::Muxer::from_source(&initialization,&bound,origin.audio_ticks,5,1_000_000,limits.max_samples,limits)?;
                                        TrialAv {initialization,muxer,configuration,source_label:"in_band_connection_claim"}
                                    };
                                    append_bounded(&mut assembled,owner.initialization.bytes())?;
                                    av_owner=Some(owner);
                                }
                                if let Some(owner)=av_owner.as_mut() {
                                    let config=aac::Configuration::parse_explicit(&owner.configuration)?;
                                    let fragment=derive_av_fragment(&owner.initialization,&config,&mut owner.muxer,&segment,&video_movie,owner.source_label)?;
                                    append_bounded(&mut assembled,&fragment)?;
                                } else {
                                    if segments_completed==0 {append_bounded(&mut assembled,initialization.bytes())?;}
                                    append_bounded(&mut assembled,segment.fragment().bytes())?;
                                }
                                segments_completed+=1;
                                println!("trial_stage=segment_assembled count={segments_completed}");
                                if segments_completed==args.lab_segments {
                                    let mut cost=BudgetVector::ZERO; cost.bytes=u64::try_from(assembled.len())?; cost.storage_operations=5;
                                    task.checkpoint_for(RuntimeGrant::ObjectStage,&args.output.to_string_lossy(),clock.now()?,&cost)?;
                                    write_clip(&args.output,&assembled)?;
                                    return Ok((assembled.len(),decoded_total,current_dimensions.0,current_dimensions.1));
                                }
                            }
                            supervisor::Step::Idle=>return Err("camera media timed out".into()),
                            other=>return Err(format!("controller or media stopped: {other:?}").into()),
                        }
                    }
                }.await;
                let retirement=supervisor.retire();
                if let Some(trace)=retirement.time_sync {sync_traces.push(trace);}
                if !sync_traces.is_empty() {println!("trial_stage=time_sync_traces_retained count={} effects_require_reconciliation=true",sync_traces.len());}
                if !startup_events.is_empty() {
                    println!("trial_stage=startup_events_omitted frames={} source_bytes={} identity=network_claim",startup_events.len(),startup_events.source_bytes());
                }
                for record in retirement.media.recorder.pending { source_omitted=source_omitted.saturating_add(record.bytes().len()); }
                source_omitted=source_omitted.saturating_add(retirement.media.ingress.framing.bytes().len());
                if let Some(buffered)=retirement.media.ingress.buffered {source_omitted=source_omitted.saturating_add(buffered.source.bytes().len().saturating_sub(buffered.appended));}
                if let Some(pending)=retirement.media.ingress.source.pending {source_omitted=source_omitted.saturating_add(pending.bytes().len());}
                let (clip_bytes,frames,width,height)=capture?;
                println!("trial_complete clip_bytes={clip_bytes} decoded_frames={frames} width={width} height={height} source_bytes_omitted={source_omitted} identity=network_claim effects=reconciliation_required continuous_recording=false");
                Ok(())
            }.await;
            let completed_at=clock.now().unwrap_or(deadline);
            let outcome=if setup_approval.0.get() || approval.0.get() {
                TaskOutcome::Indeterminate("camera settings or protocol effects require reconciliation".into())
            } else if output.is_ok() {
                TaskOutcome::Success
            } else {
                TaskOutcome::Failed("trial stopped before effect approval; inspect journal for preparation failure".into())
            };
            TaskCompletion {output,outcome,completed_at}
        }).await?;
        let receipt=result.receipt?;
        let outcome=match receipt.outcome {
            TaskOutcome::Success=>"success_no_effect",
            TaskOutcome::Indeterminate(_)=>"effect_unsettled",
            TaskOutcome::Failed(_)=>"failed_before_approval",
            TaskOutcome::Cancelled=>"cancelled",
        };
        println!("trial_task_outcome={outcome}");
        result.output
    })
}
fn inspect_anchored_journal(args: &[String]) -> ResultBox<()> {
    if args.len() != 7 || args[0] != "--inspect-anchored" || args[6] != "--owner-authorized" {
        return Err(RECOVERY_USAGE.into());
    }
    let paths = [
        PathBuf::from(&args[1]),
        PathBuf::from(&args[2]),
        PathBuf::from(&args[3]),
    ];
    if paths.iter().any(|path| !path.is_absolute())
        || paths.iter().enumerate().any(|(i, path)| {
            paths
                .iter()
                .skip(i + 1)
                .any(|other| path.starts_with(other) || other.starts_with(path))
        })
    {
        return Err("recovery paths must be distinct and absolute".into());
    }
    let uuid = &args[4];
    Identity::new("FSS", uuid, "1.20.0")?;
    let raw = args[5].as_bytes();
    if raw.len() != 12 || !raw.iter().all(u8::is_ascii_hexdigit) {
        return Err("MAC must be twelve hexadecimal digits".into());
    }
    let mut mac = [0u8; 6];
    for (index, byte) in mac.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&args[5][index * 2..index * 2 + 2], 16)?;
    }
    let (start, _) = epoch()?;
    let deadline = TimestampNs(
        start
            .0
            .checked_add(30_000_000_000)
            .ok_or("deadline overflow")?,
    );
    let mut budget = BudgetVector::ZERO;
    budget.storage_operations = 32;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:unifi-recovery-inspection".into(),
            operation_id: OperationId::parse("operation:unifi-recovery-inspection")?,
            principal: "principal:owner".into(),
            capabilities: vec![RuntimeGrant::ObjectStage.as_str().into()],
            deadline: Some(deadline),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:owner".into(),
            retention_scope: "retention:trial".into(),
            anchor_universe: ContentDigest::sha256(b"owner-authorized unifi recovery inspection"),
            generation: 1,
        },
        RegionId::new("region:unifi-recovery-inspection")?,
        RegionKind::Process,
        budget,
        start,
    )?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let task_start = TimestampNs(start.0 + 1);
        let result = run_owned_async(&mut authority, &mut tree, TaskSpec {
            task_id: TaskId::new("task:unifi-recovery-inspection")?,
            started_at: task_start,
        }, &cx, async |task, cx| {
            let clock = match MeteredClock::new(task, cx, TimestampNs(start.0 + 2)) {
                Ok(clock) => clock,
                Err(error) => return TaskCompletion { output: Err(Box::new(error) as Box<dyn Error>), outcome: TaskOutcome::Failed("recovery clock unavailable".into()), completed_at: task_start },
            };
            let output: ResultBox<()> = (|| {
                for path in &paths {
                    task.checkpoint_for(RuntimeGrant::ObjectStage, &path.to_string_lossy(), clock.now()?, &BudgetVector::ZERO)?;
                }
                let (journal, minimum) = trial_checkpoint::reopen(&paths[0], &paths[1], &paths[2], uuid, mac)?;
                let recovered = EffectCoordinator::recover(journal, minimum)?;
                let total = recovered.journal().operations().count();
                let unresolved = recovered.journal().operations().filter(|receipt| !receipt.state.is_terminal()).count();
                println!("trial_recovery=reconciliation_only operations={total} unresolved={unresolved} root_trust=operator_selected independence=unverified");
                Ok(())
            })();
            let outcome = if output.is_ok() { TaskOutcome::Success } else { TaskOutcome::Failed("recovery inspection refused".into()) };
            TaskCompletion { output, outcome, completed_at: clock.now().unwrap_or(deadline) }
        }).await?;
        result.receipt?;
        result.output
    })
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = if args.first().is_some_and(|arg| arg == "--inspect-anchored") {
        inspect_anchored_journal(&args)
    } else {
        options().and_then(run)
    };
    if let Err(error) = result {
        eprintln!("trial stopped: {error}; effect journal may require reconciliation");
        std::process::exit(1);
    }
}
