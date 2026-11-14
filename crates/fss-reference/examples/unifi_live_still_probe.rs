#![forbid(unsafe_code)]
//! Bounded owner-requested JPEG diagnostic for a routed UniFi media push.
//!
//! This does not change the camera, authenticate a peer, retain source bytes,
//! or provide a recorder. The operator must authorize and arrange the route.
//! The optional output is a private, create-only lossy derivative; it is not
//! a source-custody record or a camera timestamp. Parent-component checks do
//! not defend against a hostile concurrent namespace replacement.

use std::{
    error::Error,
    fs::{File, OpenOptions},
    io::{self, Write},
    net::{Ipv4Addr, SocketAddrV4},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    time::Duration,
};

use asupersync::{runtime::RuntimeBuilder, time::timeout};
use fss_container::{
    demux::{AvcMp4, DemuxLimits},
    flv_avc::SourceKey,
};
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, Sha256Hasher, TaskId, TaskOutcome, TimestampNs,
};
use fss_packet::extended_flv::{
    Limits as FlvLimits,
    stream::{Framer, SearchMode},
};
use fss_reference::unifi_direct::{
    listener, metered::MeteredClock, pipeline, recording, video_still,
};
use fss_runtime::{
    authority::AuthorityCx,
    drained_blocking::{self, WorkOutcome},
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};

const MAX_INPUT: u64 = 16 * 1024 * 1024;
const MAX_DERIVATIVE: usize = 32 * 1024 * 1024;

fn private_parent(path: &Path) -> io::Result<()> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let mut current = PathBuf::new();
    for component in parent.components() {
        match component {
            Component::RootDir | Component::Normal(_) => current.push(component.as_os_str()),
            _ => return Err(io::ErrorKind::InvalidInput.into()),
        }
        let metadata = std::fs::symlink_metadata(&current)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    if std::fs::metadata(parent)?.mode() & 0o077 != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

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
    if !(args.len() == 4 || args.len() == 6) || args[3] != "--owner-authorized" {
        return Err("usage: unifi_live_still_probe BIND_IPV4:PORT PEER_IPV4 ABSOLUTE_NEW_JPEG --owner-authorized [--expect-dimensions WIDTHxHEIGHT]".into());
    }
    let expected_dimensions = if args.len() == 6 {
        if args[4] != "--expect-dimensions" {
            return Err("unknown diagnostic option".into());
        }
        let (width, height) = args[5]
            .split_once('x')
            .ok_or("invalid expected dimensions")?;
        let width: u32 = width.parse().map_err(|_| "invalid expected dimensions")?;
        let height: u32 = height.parse().map_err(|_| "invalid expected dimensions")?;
        if width == 0 || height == 0 {
            return Err("invalid expected dimensions".into());
        }
        Some((width, height))
    } else {
        None
    };
    let bind: SocketAddrV4 = args[0].parse()?;
    let peer: Ipv4Addr = args[1].parse()?;
    let destination = PathBuf::from(&args[2]);
    if !destination.is_absolute() || destination.to_str().is_none() {
        return Err("output must be an absolute UTF-8 path".into());
    }
    if !local(*bind.ip()) || !local(peer) {
        return Err("listener and peer must be local unicast addresses".into());
    }
    let mut budget = BudgetVector::ZERO;
    budget.bytes = 64 * 1024 * 1024;
    budget.network_bytes = 64 * 1024 * 1024;
    budget.storage_operations = 4;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:unifi-live-push-probe".into(),
            operation_id: OperationId::parse("operation:unifi-live-push-probe")?,
            principal: "principal:owner".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::ReadMedia.as_str().into(),
                RuntimeGrant::MediaDecode.as_str().into(),
                RuntimeGrant::ObjectStage.as_str().into(),
                RuntimeGrant::ObjectPublish.as_str().into(),
            ],
            deadline: Some(TimestampNs(300_000_000_000)),
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
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("runtime context unavailable")?;
        let result = run_owned_async(&mut authority, &mut tree, TaskSpec {
            task_id: TaskId::new("task:unifi-live-push-probe")?, started_at: TimestampNs(2),
        }, &cx, async |task, cx| {
            let output: Result<(u32, u32, usize, usize), Box<dyn Error>> = async {
                let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                let admission = Admission { bind, peer };
                let listener = listener::Listener::bind(task, cx, clock, &admission, bind,
                    "camera:owner-unifi-push-probe", Duration::from_secs(30)).await?;
                println!("push_probe_ready port={}", listener.local_addr().port());
                io::stdout().flush()?;
                let limits = FlvLimits::default();
                let framer = Framer::with_mode(limits, limits.complete_candidate_buffer()?, SearchMode::ZeroStreamId)?;
                let mut recorder = recording::Recorder::new_inband(SourceKey { connection: 1, generation: 1 }, recording::Limits::default())?;
                if let Some((width, height)) = expected_dimensions {
                    recorder.require_dimensions([width, height])?;
                }
                let mut pipeline = listener.accept(framer, recorder, 32 * 1024, MAX_INPUT, Duration::from_secs(30)).await?;
                let result: Result<Result<(fss_codec_h264::Picture, usize), Box<dyn Error>>, _> = timeout(cx.now(), Duration::from_secs(60), async {
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
                                let picture = pictures.into_iter().next().ok_or("first video picture missing")?;
                                return Ok((picture, segment.fragment().samples().len()));
                            }
                            pipeline::Step::Eof => return Err("stream ended before a complete segment".into()),
                            pipeline::Step::LimitReached => return Err("stream input bound reached".into()),
                        }
                    }
                    Err("stream step bound reached".into())
                }).await;
                let _retired = pipeline.retire();
                let (picture, samples) = result.map_err(|_| "media deadline elapsed")??;
                let dimensions = (picture.width(), picture.height());
                if expected_dimensions.is_some_and(|expected| expected != dimensions) {
                    return Err("decoded dimensions differ from requested dimensions".into());
                }
                let resource = "camera:owner-unifi-push-probe";
                let target = destination.to_str().ok_or("output path unavailable")?;
                let now = clock.now()?;
                task.checkpoint_for(RuntimeGrant::ReadMedia, resource, now, &BudgetVector::ZERO)?;
                task.checkpoint_for(RuntimeGrant::MediaDecode, resource, now, &BudgetVector::ZERO)?;
                let mut export_cost = BudgetVector::ZERO;
                export_cost.bytes = 16 * 1024 * 1024;
                export_cost.storage_operations = 2;
                task.checkpoint_for(RuntimeGrant::ObjectStage, target, now, &export_cost)?;
                task.checkpoint_for(RuntimeGrant::ObjectPublish, target, now, &BudgetVector::ZERO)?;
                let output_path = destination.clone();
                let work = move |child: asupersync::Cx| -> Result<usize, &'static str> {
                    let cancelled = || child.is_cancel_requested();
                    let mut source = Sha256Hasher::new();
                    for plane in [picture.luma(), picture.cb(), picture.cr()] {
                        for chunk in plane.chunks(16 * 1024) {
                            if cancelled() { return Err("cancelled before encoding"); }
                            source.update(chunk);
                        }
                    }
                    let digest = source.finalize().map_err(|_| "source digest failed")?;
                    let limits = fss_codec_jpeg_encode::EncodeLimits::default();
                    let still = video_still::from_picture_with_probe(&picture, digest,
                        video_still::Color::Bt601Full, 90, &limits, limits.maximum_pixels as u64,
                        limits.work_bound(fss_codec_jpeg_encode::PixelFormat::Rgb), &cancelled)
                        .map_err(|_| "JPEG encoding refused")?;
                    let jpeg = still.jpeg();
                    let decode_limits = fss_codec_mjpeg::DecodeLimits::default();
                    let mut decode_budget = fss_codec_mjpeg::DecodeBudget::with_cancellation_probe(decode_limits.luma_work_bound(), &cancelled);
                    let check = fss_codec_mjpeg::decode_luma(jpeg.bytes(), jpeg.receipt().encoded_sha256,
                        fss_codec_mjpeg::ComponentInterpretation::YCbCr, decode_limits, &mut decode_budget)
                        .map_err(|_| "JPEG readback decode refused")?;
                    if check.dimensions() != [dimensions.0, dimensions.1] || cancelled() {
                        return Err("JPEG dimensions or cancellation refused");
                    }
                    private_parent(&output_path).map_err(|_| "output parent refused")?;
                    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
                        .open(&output_path).map_err(|_| "output creation refused")?;
                    for chunk in jpeg.bytes().chunks(64 * 1024) {
                        if cancelled() { return Err("output incomplete; inspect destination"); }
                        file.write_all(chunk).map_err(|_| "output incomplete; inspect destination")?;
                    }
                    file.sync_all().map_err(|_| "output sync unverified")?;
                    File::open(output_path.parent().ok_or("output parent missing")?)
                        .and_then(|parent| parent.sync_all()).map_err(|_| "output directory sync unverified")?;
                    Ok(jpeg.bytes().len())
                };
                let mut worker = drained_blocking::start(cx, work).map_err(|_| "blocking worker refused")?;
                let receipt = worker.join().await.ok_or("worker completion missing")?;
                receipt.runtime.map_err(|_| "worker runtime refused")?;
                let size = match receipt.work {
                    WorkOutcome::Finished(Ok(size)) => size,
                    WorkOutcome::Finished(Err(error)) => return Err(error.into()),
                    _ => return Err("still worker did not complete".into()),
                };
                let now = clock.now()?;
                task.checkpoint_for(RuntimeGrant::ReadMedia, resource, now, &BudgetVector::ZERO)?;
                task.checkpoint_for(RuntimeGrant::ObjectPublish, target, now, &BudgetVector::ZERO)?;
                Ok((dimensions.0, dimensions.1, samples, size))
            }.await;
            let outcome = if output.is_ok() { TaskOutcome::Success } else { TaskOutcome::Failed("bounded media probe failed".into()) };
            TaskCompletion { output, outcome, completed_at: TimestampNs(299_000_000_000) }
        }).await?;
        result.receipt?;
        let (width, height, samples, jpeg_bytes) = result.output?;
        println!("push_probe_decoded width={width} height={height} segment_samples={samples} jpeg_bytes={jpeg_bytes} jpeg_color=bt601-full source_retained=no peer_identity=unverified");
        Ok(())
    })
}

fn main() {
    if let Err(error) = run() {
        eprintln!("push_probe_failed: {error}");
        std::process::exit(1);
    }
}
