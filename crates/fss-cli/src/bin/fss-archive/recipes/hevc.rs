#![forbid(unsafe_code)]
//! Explicit HEVC dispatch with the same operator parser, current clock and storage owner.
use super::*;
use fss_reference::rtsp::datagram_reconstruction::hevc::HevcReplayBounds;
use fss_reference::rtsp::recording_recipe::hevc::{self as recipe, storage};
use storage::operation as op;

struct HevcClock<'a>(&'a Clock);
impl op::ReconstructionClock for HevcClock<'_> {
    fn now_ns(&self) -> Option<u64> {
        ReconstructionClock::now_ns(self.0)
    }
}
pub(super) fn run(options: Options) -> Result<String> {
    let clock = Clock {
        start: Instant::now(),
        deadline: u64::try_from(options.timeout.as_nanos())
            .map_err(|_| runtime("operation deadline overflow"))?,
    };
    let root = existing(&options.root)?;
    if clock.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
        return Err(runtime("operation deadline expired"));
    }
    let mut p = LocalRootPublisher::open(root, options.storage)
        .map_err(|_| runtime("archive open or exclusive ownership refused"))?;
    let mut work = WorkBudget::new(options.work);
    // Only the explicit command option chooses this native family. All metadata and original
    // source still pass through its codec-pinned graph and recording verifiers.
    let limits = op::RecipeLoadLimits {
        source: options.load.source,
        recipe: recipe::RecordingRecipeLimits {
            max_bytes: options.load.recipe.max_bytes,
            max_timings: options.load.recipe.max_timings,
            ..recipe::RecordingRecipeLimits::default()
        },
        storage: storage::RecipeStorageLimits {
            max_source_roots: options.load.storage.max_source_roots,
            max_spool_object_bytes: options.load.storage.max_spool_object_bytes,
        },
    };
    let selected = op::RecipeSelection {
        recipe: options.selected.recipe,
        root: options.selected.root,
        scope: options.selected.scope,
    };
    let loaded = op::LoadedRecordingRecipe::load(&p, selected, limits, &clock, &mut work)
        .map_err(|_| runtime("selected HEVC recipe or original source verification failed"))?;
    let bounds = HevcReplayBounds {
        max_source_bytes: limits.source.max_payload_bytes,
        max_steps: options.steps,
        deadline_ns: clock.deadline,
    };
    let plan = op::PreparedReconstruction::prepare(
        &loaded,
        &p,
        bounds,
        op::ReconstructionLimits {
            max_windows: options.output.max_windows,
            max_output_bytes: options.output.max_output_bytes,
            max_scan_roots: options.output.max_scan_roots,
        },
        &HevcClock(&clock),
        &clock,
        &mut work,
    )
    .map_err(|_| {
        runtime("complete native HEVC reconstruction refused; preparation published no output")
    })?;
    let mut report = String::new();
    report
        .try_reserve_exact(8192)
        .map_err(|_| runtime("report capacity exhausted"))?;
    let (status, published, reused) = if options.publish {
        let outcome = plan.publish(&mut p, clock.deadline, &HevcClock(&clock), &clock, &mut work)
            .map_err(|_| runtime("publication stopped; exact windows or completion root may already have committed"))?;
        let new = outcome
            .windows
            .iter()
            .filter(|r| r.outcome == PublishOutcome::Published)
            .count();
        (
            if outcome.completion.outcome == PublishOutcome::AlreadyPublished {
                "already_durable"
            } else {
                "published"
            },
            new,
            outcome.windows.len() - new,
        )
    } else {
        ("not_requested", 0, 0)
    };
    let s = plan.summary();
    let source = loaded.pin().source;
    let observed = loaded.observed_source_head();
    writeln!(&mut report,
        "{{\"schema\":\"fss.local_reconstruction_operator.v1\",\"codec\":\"hevc\",\"command\":\"{}\",\"recipe\":\"{}\",\"recipe_root\":\"{}\",\"source_scope\":\"{}\",\"source_head\":\"{}\",\"source_datagrams\":{},\"source_bytes\":{},\"observed_source_head_at_load\":\"{}\",\"observed_source_datagrams_at_load\":{},\"interpretation\":\"{}\",\"result_slot\":\"{}\",\"result_root\":\"{}\",\"result_status\":\"{}\",\"publication_requested\":{},\"windows\":{},\"output_bytes\":{},\"new_windows\":{},\"reused_windows\":{},\"rtp_observations\":{},\"rtcp_observations\":{},\"invalid_rtcp\":{},\"timings_applied\":{},\"unselected_pictures\":{},\"released_packets\":{},\"unsealed_packets\":{},\"queued_packets\":{},\"fragment_bytes\":{},\"queued_nals\":{},\"incomplete_picture\":{},\"observations_read\":{},\"remaining_datagrams\":{},\"end_of_bitstream\":{},\"capture_complete\":false,\"archive_index_published\":false,\"source_bytes_emitted\":false,\"operation_complete\":true}}",
        if options.publish { "reconstruct-recipe" } else { "check-recipe" }, loaded.pin().recipe,
        loaded.pin().root, source.scope, source.head, source.datagrams, source.payload_bytes,
        observed.head, observed.datagrams, loaded.recipe().interpretation(), plan.pin().slot,
        plan.pin().root, status, options.publish, s.windows, s.output_bytes, published, reused,
        s.rtp_observations, s.rtcp_observations, s.invalid_rtcp, s.timings_applied,
        s.unselected_pictures, s.released_packets, s.unsealed_packets, s.queued_packets,
        s.fragment_bytes, s.queued_nals, s.incomplete_picture, s.observations_read,
        s.remaining_datagrams, s.end_of_bitstream,
    ).map_err(|_| runtime("report formatting failed"))?;
    if report.len() > 8192 {
        return Err(runtime("report bound exceeded"));
    }
    Ok(report)
}
