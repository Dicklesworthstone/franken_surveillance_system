#![forbid(unsafe_code)]
//! Current-clock source verification and explicit root-last recipe publication; no recording writes.
use super::input::Options;
use super::*;
use fss_publication::{LocalRootPublisher, PublishOutcome};
use fss_reference::rtsp::datagram_archive::prefix::DatagramPrefix;
use fss_reference::rtsp::datagram_reconstruction::hevc::recording::{
    HevcRecordingReplayStep, HevcReplayBoundary,
};
use fss_reference::rtsp::datagram_reconstruction::hevc::{HevcReplayRetirement, HevcReplayStep};
use fss_reference::rtsp::hevc_recording_capture::HevcCapturePoll;
use fss_reference::rtsp::recording_recipe::hevc::RecordingRecipeLimits;
use fss_reference::rtsp::recording_recipe::hevc::authoring::{
    AuthoringStep, RecordingRecipeAuthor,
};
use fss_reference::rtsp::recording_recipe::hevc::storage::{
    PreparedRecordingRecipe, RecipeStorageLimits,
};
use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};

fn existing(path: &Path) -> Result<PathBuf> {
    let directory = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir());
    let file = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_file());
    if !directory(path) {
        return Err(runtime("expected an existing non-symlink source store"));
    }
    let root = std::fs::canonicalize(path).map_err(|_| runtime("store path resolution failed"))?;
    for name in [
        "roots",
        "tombstones",
        "spool",
        "spool/objects",
        "spool/staging",
        "spool/verified",
    ] {
        if !directory(&root.join(name)) {
            return Err(runtime("existing source store layout required"));
        }
    }
    for name in ["LOCK", "spool/LOCK"] {
        if !file(&root.join(name)) {
            return Err(runtime("existing source lock layout required"));
        }
    }
    Ok(root)
}
// Explicit Linux backend: refuse symbolic links and special files without blocking on FIFO races.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn open_draft(path: &Path, maximum: usize) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    #[cfg(target_arch = "x86_64")]
    const NOFOLLOW: i32 = 0o400_000;
    #[cfg(target_arch = "aarch64")]
    const NOFOLLOW: i32 = 0o100_000;
    const NONBLOCK: i32 = 0o4_000;
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| runtime("draft metadata unavailable"))?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err(runtime("draft must be a bounded regular non-symlink file"));
    }
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW | NONBLOCK)
        .open(path)
        .map_err(|_| runtime("draft open refused"))
}
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn open_draft(_: &Path, _: usize) -> Result<std::fs::File> {
    Err(runtime(
        "bounded draft file backend unavailable on this target",
    ))
}

fn read_draft(o: &Options, clock: &Clock, work: &mut WorkBudget<'_>) -> Result<Vec<u8>> {
    clock.check()?;
    work.charge(o.draft_bytes as u64 * 4 + 4096)
        .map_err(|_| runtime("draft work bound exhausted"))?;
    let mut file = open_draft(&o.draft, o.draft_bytes)?;
    let metadata = file
        .metadata()
        .map_err(|_| runtime("opened draft metadata unavailable"))?;
    if !metadata.is_file() || metadata.len() > o.draft_bytes as u64 {
        return Err(runtime("opened draft is not a bounded regular file"));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(o.draft_bytes + 1)
        .map_err(|_| runtime("draft allocation refused"))?;
    let mut buffer = [0_u8; 16384];
    let mut interrupted = 0;
    let mut ended = false;
    for _ in 0..o.draft_bytes + 16 {
        clock.check()?;
        let capacity = buffer.len().min(o.draft_bytes + 1 - bytes.len());
        match file.read(&mut buffer[..capacity]) {
            Ok(0) => {
                ended = true;
                break;
            }
            Ok(n) => {
                bytes.extend_from_slice(&buffer[..n]);
                interrupted = 0;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted && interrupted < 7 => {
                interrupted += 1;
            }
            Err(_) => return Err(runtime("bounded draft read refused")),
        }
        if bytes.len() > o.draft_bytes {
            return Err(runtime("draft grew beyond its bound"));
        }
    }
    if !ended {
        return Err(runtime("draft read work exhausted"));
    }
    clock.check()?;
    if ContentDigest::try_sha256(&bytes).map_err(|_| runtime("draft digest failed"))? != o.draft_id
    {
        return Err(runtime("draft differs from the explicitly selected digest"));
    }
    Ok(bytes)
}

#[derive(Default)]
struct Summary {
    windows: usize,
    pictures: usize,
    bytes: u64,
    queued_packets: usize,
    fragment_bytes: usize,
}
impl Summary {
    fn receiver(&mut self, r: &fss_packet::H265ReceiveCancellation) -> Result<()> {
        self.queued_packets = self
            .queued_packets
            .checked_add(r.queue.packets)
            .ok_or_else(|| runtime("receiver accounting overflow"))?;
        self.fragment_bytes = self
            .fragment_bytes
            .checked_add(r.fragment.as_ref().map_or(0, |f| f.byte_len))
            .ok_or_else(|| runtime("fragment accounting overflow"))?;
        Ok(())
    }
    fn source(&mut self, r: &HevcReplayStep) -> Result<()> {
        // Normal prefix exhaustion already transfers the receiver here, not in final retirement.
        if let HevcReplayStep::PrefixExhausted { retired, .. } = r {
            self.receiver(retired)?;
        }
        Ok(())
    }
    fn replay_retirement(&mut self, r: &HevcReplayRetirement) -> Result<()> {
        if let Some(receiver) = &r.receiver {
            self.receiver(receiver)?;
        }
        Ok(())
    }
}
pub(super) fn execute(o: Options) -> Result<String> {
    let clock = Clock {
        start: Instant::now(),
        timeout: o.timeout,
    };
    let mut work = WorkBudget::new(o.work);
    let raw = read_draft(&o, &clock, &mut work)?;
    let draft = input::draft(&raw, &o)?;
    drop(raw);
    clock.check()?;
    let root = existing(&o.root)?;
    clock.check()?;
    let mut p = LocalRootPublisher::open(root, o.storage)
        .map_err(|_| runtime("source store open or exclusive ownership refused"))?;
    clock.check()?;
    let prefix = DatagramPrefix::recover(&p, draft.scope, o.source, draft.pin, &clock, &mut work)
        .map_err(|_| runtime("selected source prefix or full current chain refused"))?;
    let limits = RecordingRecipeLimits {
        max_timings: o.timings,
        ..RecordingRecipeLimits::default()
    };
    let mut author = RecordingRecipeAuthor::new(
        prefix.archive(),
        draft.hevc,
        draft.recording,
        draft.inputs,
        limits,
        o.bounds(&clock)?,
        clock.now()?,
    )
    .map_err(|_| malformed("timing schedule or native authoring configuration refused"))?;
    let mut summary = Summary::default();
    let mut finished = None;
    // An outer finite operation cap bounds even zero-work native outputs. No replenishment.
    for _ in 0..o.steps {
        match author
            .step(&p, clock.now()?, &clock, &mut work)
            .map_err(|_| runtime("native authoring refused; no recipe was published"))?
        {
            AuthoringStep::Replay(HevcRecordingReplayStep::Source(source)) => {
                summary.source(&source)?
            }
            AuthoringStep::Replay(HevcRecordingReplayStep::Capture(event)) => {
                if let HevcCapturePoll::Window(window) = *event {
                    let next = summary
                        .bytes
                        .checked_add(window.byte_len() as u64)
                        .ok_or_else(|| runtime("preview output accounting overflow"))?;
                    if summary.windows >= o.windows || next > o.output_bytes {
                        return Err(runtime(
                            "preview output bound exhausted; no recipe was published",
                        ));
                    }
                    summary.windows += 1;
                    summary.pictures = summary
                        .pictures
                        .checked_add(window.samples().len())
                        .ok_or_else(|| runtime("preview picture accounting overflow"))?;
                    summary.bytes = next;
                    // Disposable preview derivative only. Its originals remain in the pinned
                    // source store; this command never publishes preview windows or calls them durable.
                }
            }
            AuthoringStep::Finished { recipe, retained } => {
                finished = Some((recipe, retained));
                break;
            }
            AuthoringStep::Ended => return Err(runtime("native author ended without a recipe")),
            _ => {}
        }
    }
    let (recipe, retained) =
        finished.ok_or_else(|| runtime("authoring step allowance exhausted"))?;
    if retained.observations_read > recipe.source().datagrams || retained.boundary.is_none() {
        return Err(runtime("inconsistent terminal source accounting"));
    }
    if let Some(replay) = &retained.replay {
        summary.replay_retirement(replay)?;
    }
    if let Some(source) = &retained.held_source {
        summary.source(source)?;
    }
    let unsealed = retained
        .capture
        .as_ref()
        .map_or(0, |c| c.collection.sources.len());
    let queued_nals = retained.queued_nals.len();
    let incomplete_picture = retained.assembly.as_ref().is_some_and(|a| a.nals != 0);
    let eob = retained.boundary == Some(HevcReplayBoundary::EndOfBitstream);
    clock.check()?;
    // Revalidate the full observed chain, not just the older selected recipe prefix.
    prefix
        .revalidate(&p, &clock, &mut work)
        .map_err(|_| runtime("source changed during authoring"))?;
    if o.approval.is_some_and(|id| id != recipe.identity()) {
        return Err(runtime(
            "authored recipe differs from explicit preview approval",
        ));
    }
    let plan = PreparedRecordingRecipe::prepare(
        &recipe,
        prefix.archive(),
        &p,
        RecipeStorageLimits {
            max_source_roots: fss_object::MAX_MANIFEST_CHILDREN - 1,
            max_spool_object_bytes: o.source.max_spool_object_bytes,
        },
        &clock,
        &mut work,
    )
    .map_err(|_| runtime("source-closed recipe preparation refused"))?;
    // Reserve and format all identity/remainder fields BEFORE possibly committing publication.
    let mut report = String::new();
    report
        .try_reserve_exact(8192)
        .map_err(|_| runtime("report allocation refused"))?;
    let source = recipe.source();
    let observed = prefix.observed_head();
    write!(&mut report,
        "{{\"schema\":\"fss.hevc_recipe_authoring.v1\",\"command\":\"author-hevc-recipe\",\"codec\":\"hevc\",\"draft\":\"{}\",\"recipe\":\"{}\",\"recipe_root\":\"{}\",\"recipe_slot\":\"{}\",\"interpretation\":\"{}\",\"source_scope\":\"{}\",\"source_head\":\"{}\",\"source_datagrams\":{},\"source_bytes\":{},\"observed_source_head_at_load\":\"{}\",\"observed_source_datagrams_at_load\":{},\"timings_applied\":{},\"preview_windows\":{},\"preview_pictures\":{},\"preview_output_bytes\":{},\"observations_read\":{},\"remaining_datagrams\":{},\"queued_packets\":{},\"fragment_bytes\":{},\"queued_nals\":{},\"unsealed_packets\":{},\"incomplete_picture\":{},\"end_of_bitstream\":{},\"capture_complete\":false,\"recording_published\":false,\"source_bytes_emitted\":false,\"authoring_complete\":true,",
        o.draft_id.to_text(), recipe.identity().to_text(), plan.pin().root.to_text(), plan.pin().slot,
        recipe.interpretation().to_text(), source.scope.to_text(), source.head.to_text(), source.datagrams,
        source.payload_bytes, observed.head.to_text(), observed.datagrams, recipe.timings().len(),
        summary.windows, summary.pictures, summary.bytes, retained.observations_read,
        source.datagrams - retained.observations_read, summary.queued_packets, summary.fragment_bytes,
        queued_nals, unsealed, incomplete_picture, eob).map_err(|_| runtime("report formatting refused"))?;
    if report.len() > 7000 {
        return Err(runtime("report capacity exceeded"));
    }
    let status = if o.approval.is_some() {
        prefix
            .revalidate(&p, &clock, &mut work)
            .map_err(|_| runtime("source changed before publication"))?;
        clock.check()?;
        let receipt = plan.publish(&mut p, &clock, &mut work).map_err(|_| {
            runtime("recipe publication failed or is uncertain; reconcile the approved identity")
        })?;
        match receipt.local.outcome {
            PublishOutcome::Published => "published",
            PublishOutcome::AlreadyPublished => "already_durable",
        }
    } else {
        clock.check()?;
        "not_requested"
    };
    // After commit, deliver its actual outcome. A later cancellation cannot erase the receipt.
    writeln!(&mut report, "\"publication_requested\":{},\"recipe_status\":\"{}\",\"work_used\":{},\"work_remaining\":{}}}",
        o.approval.is_some(), status, work.used(), work.remaining())
        .map_err(|_| runtime("report formatting refused"))?;
    Ok(report)
}
