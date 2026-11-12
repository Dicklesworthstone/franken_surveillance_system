#![forbid(unsafe_code)]
//! One explicitly scoped TLS handshake; no HTTP, credentials, or camera control.
//! Laboratory only: the supplied pin does not independently identify a camera.
use asupersync::{runtime::RuntimeBuilder, time::timeout};
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_reference::unifi_direct::metered::MeteredClock;
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
    error::Error,
    io::Read,
    net::{Ipv4Addr, SocketAddrV4},
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

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 || args[3] != "--owner-authorized" {
        return Err("usage: live_tls_probe PRIVATE_IPV4:PORT CERT_DER --owner-authorized".into());
    }
    let peer: SocketAddrV4 = args[1].parse()?;
    let address: Ipv4Addr = *peer.ip();
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
    budget.bytes = 1_000_000;
    budget.network_bytes = 1_000_000;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:unifi-tls-observe".into(),
            operation_id: OperationId::parse("operation:unifi-tls-observe")?,
            principal: "principal:owner".into(),
            capabilities: [RuntimeGrant::AdapterNet, RuntimeGrant::AdapterAuth]
                .iter()
                .map(|g| g.as_str().into())
                .collect(),
            deadline: Some(TimestampNs(30_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:unifi-tls-observe".into(),
            retention_scope: "retention:none".into(),
            anchor_universe: ContentDigest::sha256(b"unifi-tls-observe"),
            generation: 1,
        },
        RegionId::new("region:unifi-tls-observe")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    RuntimeBuilder::current_thread().blocking_threads(1, 1).build()?.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(&mut authority, &mut tree, TaskSpec {
            task_id: TaskId::new("task:unifi-tls-observe")?, started_at: TimestampNs(2),
        }, &cx, async |task, cx| {
            let output: Result<(), Box<dyn Error>> = async {
                let resource = "camera:unifi-tls-observe";
                let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                let mut acquisition = Acquisition::begin(task, cx, clock, resource, 128)?;
                let lease = match timeout(cx.now(), Duration::from_secs(5), acquisition.join()).await {
                    Ok(result) => result?,
                    Err(_) => {
                        acquisition.abort();
                        let _ = acquisition.join().await;
                        return Err("entropy acquisition deadline".into());
                    }
                };
                let mut provider = rustls_pure::provider();
                provider.secure_random = &NO_RANDOM;
                provider.kx_groups = vec![&NO_KX];
                let mut session = camera_tls_owned::connect_with_lease(
                    cx, task, clock, peer, &certificate, resource, Duration::from_secs(8), Arc::new(provider), lease,
                ).await?;
                session.request_stop();
                drop(session);
                Ok(())
            }.await;
            let outcome = if output.is_ok() { TaskOutcome::Success } else { TaskOutcome::Failed("TLS observation failed".into()) };
            TaskCompletion { output, outcome, completed_at: TimestampNs(29_000_000_000) }
        }).await?;
        result.receipt?;
        result.output?;
        println!("tls13_handshake=completed observed_pin=matched signature=verified http_requests=0 credentials=unused");
        Ok::<(), Box<dyn Error>>(())
    })
}
