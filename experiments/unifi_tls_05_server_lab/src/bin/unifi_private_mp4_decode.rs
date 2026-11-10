#![forbid(unsafe_code)]
//! Bounded, read-only laboratory decode of a private MP4 supplied on stdin.
//!
//! This exercises FSS demux and AVC decoding, not camera identity, capture
//! time, direct camera control, recording durability, or continuous coverage.

use std::{error::Error, io::Read};

use asupersync::runtime::RuntimeBuilder;
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};

const MAX_INPUT: u64 = 16 * 1024 * 1024;
const MAX_SAMPLES: usize = 300;

fn run() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let emit_hashes =
        match args.as_slice() {
            [authorized] if authorized == "--owner-authorized" => false,
            [authorized, hashes]
                if authorized == "--owner-authorized" && hashes == "--frame-hashes" =>
            {
                true
            }
            _ => return Err(
                "usage: unifi_private_mp4_decode --owner-authorized [--frame-hashes] < PRIVATE_MP4"
                    .into(),
            ),
        };
    let mut budget = BudgetVector::ZERO;
    // Reserve the sentinel byte too, before reading from stdin.
    budget.bytes = MAX_INPUT + 1;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:unifi-private-mp4-decode".into(),
            operation_id: OperationId::parse("operation:unifi-private-mp4-decode")?,
            principal: "principal:owner".into(),
            capabilities: vec![
                RuntimeGrant::ReadMedia.as_str().into(),
                RuntimeGrant::MediaDecode.as_str().into(),
            ],
            deadline: Some(TimestampNs(120_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:owner".into(),
            retention_scope: "retention:in-memory".into(),
            anchor_universe: ContentDigest::sha256(b"owner-authorized private mp4 diagnostic")
                .with_laboratory(true),
            generation: 1,
        },
        RegionId::new("region:unifi-private-mp4-decode")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("runtime unavailable")?;
        let result = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec { task_id: TaskId::new("task:unifi-private-mp4-decode")?, started_at: TimestampNs(2) },
            &cx,
            async |task, cx| {
                let output: Result<(usize, usize, u32, u32, usize, Vec<[u8; 32]>), Box<dyn Error>> = (|| {
                    let clock = fss_reference::unifi_direct::metered::MeteredClock::new(task, cx, TimestampNs(3))?;
                    let resource = "camera:owner-private-mp4";
                    let mut cost = BudgetVector::ZERO;
                    cost.bytes = MAX_INPUT + 1;
                    task.checkpoint_for(RuntimeGrant::ReadMedia, resource, clock.now()?, &cost)?;
                    let mut bytes = Vec::new();
                    std::io::stdin().lock().take(MAX_INPUT + 1).read_to_end(&mut bytes)?;
                    if bytes.is_empty() || bytes.len() as u64 > MAX_INPUT {
                        return Err("private input exceeds its bound or is empty".into());
                    }
                    let movie = fss_container::demux::AvcMp4::parse(&bytes, None, fss_container::demux::DemuxLimits::default())?;
                    let samples = movie.samples().len();
                    if samples == 0 || samples > MAX_SAMPLES { return Err("sample count outside diagnostic bound".into()); }
                    task.checkpoint_for(RuntimeGrant::MediaDecode, resource, clock.now()?, &BudgetVector::ZERO)?;
                    let annex = movie.annex_b(0, samples)?;
                    let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                    let mut dimensions = None;
                    let mut frame_count = 0usize;
                    let mut hashes = Vec::new();
                    let mut observe = |picture: fss_codec_h264::Picture| -> Result<(), Box<dyn Error>> {
                        let size = (picture.width(), picture.height());
                        if dimensions.is_some_and(|expected| expected != size) {
                            return Err("decoded dimensions changed".into());
                        }
                        dimensions = Some(size);
                        frame_count = frame_count.checked_add(1).ok_or("frame count overflow")?;
                        if emit_hashes { hashes.push(picture.i420_sha256()); }
                        Ok(())
                    };
                    for nal in fss_codec_h264::annex_b_nal_units(annex.bytes()) {
                        task.checkpoint_for(RuntimeGrant::MediaDecode, resource, clock.now()?, &BudgetVector::ZERO)?;
                        if let Some(picture) = decoder.decode_nal(nal)? { observe(picture)?; }
                        while let Some(picture) = decoder.next_output() { observe(picture)?; }
                    }
                    for picture in decoder.finish()? { observe(picture)?; }
                    let (width, height) = dimensions.ok_or("no decoded video frame")?;
                    task.checkpoint_for(RuntimeGrant::MediaDecode, resource, clock.now()?, &BudgetVector::ZERO)?;
                    Ok((bytes.len(), samples, width, height, frame_count, hashes))
                })();
                let outcome = if output.is_ok() { TaskOutcome::Success } else { TaskOutcome::Failed("private mp4 decode failed".into()) };
                TaskCompletion { output, outcome, completed_at: TimestampNs(119_000_000_000) }
            },
        ).await?;
        result.receipt?;
        let (bytes, samples, width, height, frames, hashes) = result.output?;
        for hash in hashes {
            let hex: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
            println!("frame_sha256={hex}");
        }
        println!("private_mp4_decode=ok bytes={bytes} samples={samples} width={width} height={height} frames={frames} camera_identity=unverified capture_bounds=unknown");
        Ok::<(), Box<dyn Error>>(())
    })?;
    if !authority.finalize_report(&tree)?.is_empty() {
        return Err("task obligations remain".into());
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("private_mp4_decode=failed reason={error}");
        std::process::exit(1);
    }
}
