#![forbid(unsafe_code)]
//! Bounded diagnostic for an independently routed UniFi camera media push.
//!
//! This does not change the camera, authenticate a peer, retain source bytes,
//! or provide a recorder. The operator must authorize and arrange the route.

use std::{
    error::Error,
    io::{self, Write},
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

use asupersync::{runtime::RuntimeBuilder, time::timeout};
use fss_container::{
    demux::{AvcMp4, DemuxLimits},
    flv_avc::SourceKey,
};
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_packet::extended_flv::{
    Limits as FlvLimits,
    stream::{Framer, SearchMode},
};
use fss_reference::unifi_direct::{listener, metered::MeteredClock, pipeline, recording};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};

const MAX_INPUT: u64 = 16 * 1024 * 1024;
const MAX_DERIVATIVE: usize = 32 * 1024 * 1024;

struct Admission {
    bind: SocketAddrV4,
    peer: Ipv4Addr,
}
impl listener::Admission for Admission {
    fn listener(&self, requested: SocketAddrV4, bound: Option<SocketAddrV4>) -> bool {
        requested == self.bind
            && bound.is_none_or(|value| {
                value.ip() == self.bind.ip()
                    && value.port() != 0
                    && (self.bind.port() == 0 || value.port() == self.bind.port())
            })
    }
    fn peer(&self, bound: SocketAddrV4, source: SocketAddrV4) -> bool {
        bound.ip() == self.bind.ip() && *source.ip() == self.peer
    }
}

fn local(ip: Ipv4Addr) -> bool {
    (ip.is_private() || ip.is_loopback() || ip.is_link_local())
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_broadcast()
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 3 || args[2] != "--owner-authorized" {
        return Err("usage: live_media_probe BIND_IPV4:PORT PEER_IPV4 --owner-authorized".into());
    }
    let bind: SocketAddrV4 = args[0].parse()?;
    let peer: Ipv4Addr = args[1].parse()?;
    if !local(*bind.ip()) || !local(peer) {
        return Err("listener and peer must be local unicast addresses".into());
    }
    let mut budget = BudgetVector::ZERO;
    budget.bytes = 64 * 1024 * 1024;
    budget.network_bytes = 64 * 1024 * 1024;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:unifi-live-push-probe".into(),
            operation_id: OperationId::parse("operation:unifi-live-push-probe")?,
            principal: "principal:owner".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::ReadMedia.as_str().into(),
            ],
            deadline: Some(TimestampNs(120_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:local".into(),
            retention_scope: "retention:omitted".into(),
            anchor_universe: ContentDigest::sha256(b"unifi live push diagnostic")
                .with_laboratory(true),
            generation: 1,
        },
        RegionId::new("region:unifi-live-push-probe")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("runtime context unavailable")?;
        let result = run_owned_async(&mut authority, &mut tree, TaskSpec {
            task_id: TaskId::new("task:unifi-live-push-probe")?, started_at: TimestampNs(2),
        }, &cx, async |task, cx| {
            let output: Result<(u32, u32, usize), Box<dyn Error>> = async {
                let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                let admission = Admission { bind, peer };
                let listener = listener::Listener::bind(task, cx, clock, &admission, bind,
                    "camera:owner-unifi-push-probe", Duration::from_secs(30)).await?;
                println!("push_probe_ready port={}", listener.local_addr().port());
                io::stdout().flush()?;
                let limits = FlvLimits::default();
                let framer = Framer::with_mode(limits, limits.complete_candidate_buffer()?, SearchMode::ZeroStreamId)?;
                let recorder = recording::Recorder::new_inband(SourceKey { connection: 1, generation: 1 }, recording::Limits::default())?;
                let mut pipeline = listener.accept(framer, recorder, 32 * 1024, MAX_INPUT, Duration::from_secs(30)).await?;
                let result = timeout(cx.now(), Duration::from_secs(60), async {
                    for _ in 0..65_536 {
                        match pipeline.step(task, cx, clock.now()?).await? {
                            pipeline::Step::Recording(recording::Push::Source { .. })
                            | pipeline::Step::Recording(recording::Push::Buffered)
                            | pipeline::Step::Progress { .. } => (),
                            pipeline::Step::Recording(recording::Push::Segment(segment)) => {
                                let init = pipeline.initialization().ok_or("video initialization missing")?.bytes();
                                let fragment = segment.fragment().bytes();
                                let size = init.len().checked_add(fragment.len()).ok_or("derivative size overflow")?;
                                if size > MAX_DERIVATIVE { return Err("derivative bound exceeded".into()); }
                                let mut bytes = Vec::new();
                                bytes.try_reserve_exact(size)?;
                                bytes.extend_from_slice(init); bytes.extend_from_slice(fragment);
                                let movie = AvcMp4::parse_inband(&bytes, None, DemuxLimits::default())?;
                                let annex = movie.annex_b(0, 1)?;
                                let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                                let mut pictures = decoder.decode_annex_b(annex.bytes())?;
                                pictures.extend(decoder.finish()?);
                                let picture = pictures.first().ok_or("first video picture missing")?;
                                return Ok((picture.width(), picture.height(), segment.fragment().samples().len()));
                            }
                            pipeline::Step::Eof => return Err("stream ended before a complete segment".into()),
                            pipeline::Step::LimitReached => return Err("stream input bound reached".into()),
                        }
                    }
                    Err("stream step bound reached".into())
                }).await;
                let _retired = pipeline.retire();
                result.map_err(|_| "media deadline elapsed")?
            }.await;
            let outcome = if output.is_ok() { TaskOutcome::Success } else { TaskOutcome::Failed("bounded media probe failed".into()) };
            TaskCompletion { output, outcome, completed_at: TimestampNs(119_000_000_000) }
        }).await?;
        result.receipt?;
        let (width, height, samples) = result.output?;
        println!("push_probe_decoded width={width} height={height} segment_samples={samples} source_retained=no peer_identity=unverified");
        Ok(())
    })
}

fn main() {
    if let Err(error) = run() {
        eprintln!("push_probe_failed: {error}");
        std::process::exit(1);
    }
}
