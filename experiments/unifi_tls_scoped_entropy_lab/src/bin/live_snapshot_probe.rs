#![forbid(unsafe_code)]
//! Bounded, read-only, experimental authenticated snapshot; not production TLS.
//! The caller-supplied network-observed pin is not physical identity evidence.
#[path = "../snapshot_auth.rs"]
mod auth;
use asupersync::{runtime::RuntimeBuilder, time::timeout};
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_reference::unifi_direct::{
    camera_api::{VideoMetric, VideoProfile, VideoProfileLimits, select_reported_video_profile},
    camera_http,
    metered::{MeteredClock, MeteredIo},
};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};
use fss_unifi_scoped_tls_entropy_lab::{camera_tls_owned, owned::offload::Acquisition};
use rustls::{
    NamedGroup,
    crypto::{ActiveKeyExchange, GetRandomFailed, SecureRandom, SupportedKxGroup},
};
use std::{
    collections::BTreeSet,
    error::Error,
    io::Read,
    net::{Ipv4Addr, SocketAddrV4},
    path::Path,
    sync::Arc,
    time::Duration,
};

#[derive(Debug)]
struct NoAmbientRandom;
impl SecureRandom for NoAmbientRandom {
    fn fill(&self, _: &mut [u8]) -> Result<(), GetRandomFailed> {
        panic!("ambient randomness used")
    }
}
#[derive(Debug)]
struct NoAmbientKx;
impl SupportedKxGroup for NoAmbientKx {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        panic!("ambient key exchange used")
    }
    fn name(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}
static NO_RANDOM: NoAmbientRandom = NoAmbientRandom;
static NO_KX: NoAmbientKx = NoAmbientKx;
struct Policy<'a, F> {
    lease: &'a auth::Lease,
    check: F,
    peer: Ipv4Addr,
    profiles: bool,
}
impl<F: Fn() -> Result<(), &'static str>> camera_http::Authority for Policy<'_, F> {
    fn permits(&self, peer: Ipv4Addr, generation: u64, operation: camera_http::Operation) -> bool {
        peer == self.peer
            && generation == 1
            && (matches!(
                operation,
                camera_http::Operation::Login
                    | camera_http::Operation::Status
                    | camera_http::Operation::Snapshot
            ) || (self.profiles && matches!(operation, camera_http::Operation::Settings)))
            && self.lease.revalidate(&self.check).is_ok()
    }
}
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let profiles =
        args.len() == 6 && args[4] == "--observe-profiles" && args[5] == "--owner-authorized";
    if !(profiles || (args.len() == 5 && args[4] == "--owner-authorized")) {
        return Err("usage: live_snapshot_probe PRIVATE_IPV4:PORT CERT_DER CREDENTIAL_FILE [--observe-profiles] --owner-authorized".into());
    }
    let peer: SocketAddrV4 = args[1].parse()?;
    let address = *peer.ip();
    if peer.port() == 0
        || !(address.is_private() || address.is_link_local() || address.is_loopback())
    {
        return Err("local IPv4 and nonzero port required".into());
    }
    let mut certificate = Vec::new();
    std::fs::File::open(&args[2])?
        .take(8193)
        .read_to_end(&mut certificate)?;
    if certificate.is_empty() || certificate.len() > 8192 {
        return Err("certificate size refused".into());
    }
    let mut budget = BudgetVector::ZERO;
    budget.bytes = 8 * 1024 * 1024;
    budget.network_bytes = 8 * 1024 * 1024;
    let capabilities = [
        RuntimeGrant::AdapterNet,
        RuntimeGrant::AdapterAuth,
        RuntimeGrant::ObserveStatus,
        RuntimeGrant::ReadMedia,
        RuntimeGrant::MediaDecode,
    ];
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:unifi-snapshot-observe".into(),
            operation_id: OperationId::parse("operation:unifi-snapshot-observe")?,
            principal: "principal:owner".into(),
            capabilities: capabilities.iter().map(|g| g.as_str().into()).collect(),
            deadline: Some(TimestampNs(50_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:unifi-snapshot-observe".into(),
            retention_scope: "retention:none".into(),
            anchor_universe: ContentDigest::sha256(b"unifi-snapshot-observe").with_laboratory(true),
            generation: 1,
        },
        RegionId::new("region:unifi-snapshot-observe")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let resource = "camera:unifi-snapshot-observe";
    let mut grants = authority.grants().clone();
    for grant in capabilities {
        grants = grants.with_scope(grant, BTreeSet::from([resource.to_owned()]));
    }
    authority.narrow_grants(grants)?;
    RuntimeBuilder::current_thread().blocking_threads(1,1).build()?.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(&mut authority, &mut tree, TaskSpec {
            task_id: TaskId::new("task:unifi-snapshot-observe")?, started_at: TimestampNs(2),
        }, &cx, async |task, cx| {
            let output: Result<([u32; 2], Option<[VideoProfile; 4]>), Box<dyn Error>> = async {
                let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                let mut acquisition = Acquisition::begin(task, cx, clock, resource, 128)?;
                let entropy = match timeout(cx.now(), Duration::from_secs(5), acquisition.join()).await {
                    Ok(result) => result?,
                    Err(_) => { acquisition.abort(); let _ = acquisition.join().await; return Err("entropy acquisition deadline".into()); }
                };
                let mut provider = rustls_pure::provider(); provider.secure_random = &NO_RANDOM; provider.kx_groups = vec![&NO_KX];
                let tls = camera_tls_owned::connect_with_lease(cx, task, clock, peer, &certificate, resource, Duration::from_secs(8), Arc::new(provider), entropy).await?;
                // The credential is not opened until pin and TLS signature have succeeded.
                let check = || -> Result<(), &'static str> {
                    cx.checkpoint().map_err(|_| "runtime cancelled")?;
                    let now = clock.now().map_err(|_| "task clock unavailable")?;
                    task.checkpoint_for(RuntimeGrant::AdapterAuth, resource, now, &BudgetVector::ZERO).map_err(|_| "authentication authority refused")
                };
                let credential = auth::Lease::load(Path::new(&args[3]), &check)?;
                let policy = Policy { lease: &credential, check, peer: address, profiles };
                let plaintext = MeteredIo::with_clock(tls, clock, resource, 4096)?;
                let mut api = camera_http::Owner::new(plaintext, task, cx, clock, &policy, address, 1, resource)?;
                api.login(&credential.secret.0, Duration::from_secs(10)).await?;
                let _ = api.status(Duration::from_secs(10)).await?;
                let reported = if profiles {
                    let settings = api.settings(Duration::from_secs(10)).await?;
                    Some([settings.video_profiles[0], settings.video_profiles[1], settings.video_profiles[2], settings.snapshot_profile])
                } else { None };
                let snapshot = api.snapshot(Duration::from_secs(10)).await?;
                task.checkpoint_for(RuntimeGrant::MediaDecode, resource, clock.now()?, &BudgetVector::ZERO)?;
                let limits = fss_codec_mjpeg::DecodeLimits { maximum_bytes: 4*1024*1024, ..Default::default() };
                let mut decode_budget = fss_codec_mjpeg::DecodeBudget::new(limits.luma_work_bound().min(1_500_000_000));
                let decoded = fss_codec_mjpeg::decode_luma(snapshot.bytes(), snapshot.digest().bytes(), fss_codec_mjpeg::ComponentInterpretation::YCbCr, limits, &mut decode_budget)?;
                let dimensions = decoded.dimensions();
                if decoded.pixels().len() != dimensions[0] as usize * dimensions[1] as usize { return Err("decoded dimensions inconsistent".into()); }
                Ok((dimensions, reported))
            }.await;
            let outcome = if output.is_ok() { TaskOutcome::Success } else { TaskOutcome::Failed("snapshot observation failed".into()) };
            TaskCompletion { output, outcome, completed_at: TimestampNs(49_000_000_000) }
        }).await?;
        result.receipt?;
        let ([width, height], reported) = result.output?;
        println!("tls13=completed observed_pin=matched login=ok status=ok snapshot=decoded dimensions={}x{} media_persisted=false", width, height);
        if let Some(reported) = reported {
            fn metric(value: VideoMetric) -> String {
                match value { VideoMetric::Reported(value) => value.to_string(), VideoMetric::NotReported => "not_reported".into(), VideoMetric::Unsupported => "unsupported".into() }
            }
            for (name, profile) in ["video1", "video2", "video3", "snapshot"].into_iter().zip(reported) {
                println!("profile={name} width={} height={} fps={} provenance=camera_claim", metric(profile.width), metric(profile.height), metric(profile.fps));
            }
            let selection = select_reported_video_profile([reported[0], reported[1], reported[2]], VideoProfileLimits {
                max_width: u32::MAX, max_height: u32::MAX, min_fps: 1, max_fps: u32::MAX, max_pixels_per_second: u64::MAX,
            })?;
            let channel = match selection.selected.map(|(channel, _)| channel) {
                Some(fss_reference::unifi_direct::VideoChannel::Video1) => "video1",
                Some(fss_reference::unifi_direct::VideoChannel::Video2) => "video2",
                Some(fss_reference::unifi_direct::VideoChannel::Video3) => "video3",
                None => "none",
            };
            println!("highest_complete_reported_profile={channel} resource_limits=not_applied provenance=camera_claim");
        }
        Ok::<(), Box<dyn Error>>(())
    })
}
