#![forbid(unsafe_code)]
//! Real native AVC reconstruction under portable, exactly matched timing decisions.
mod datagram_reconstruction_support;
use datagram_reconstruction_support::*;
use fss_core::{ContentDigest, SensorId, StreamId};
use fss_publication::{LocalRootPublisher, NeverCancel, PublishCancellation, PublishCutPoint};
use fss_reference::rtsp::datagram_archive::DatagramArchive;
use fss_reference::rtsp::datagram_reconstruction::recording::{
    DatagramRecordingReplay, RecordingReplaySpec, RecordingReplayStep,
};
use fss_reference::rtsp::recording::{PreparedRecording, RecordingScope};
use fss_reference::rtsp::recording_capture::CapturePoll;
use fss_reference::rtsp::recording_collector::{CollectorLimits, RecordingTiming};
use fss_reference::rtsp::recording_recipe::*;

fn recording() -> Test<RecordingReplaySpec> {
    Ok(RecordingReplaySpec {
        scope: RecordingScope {
            sensor: SensorId::parse("recipe-sensor")?,
            stream: StreamId::parse("recipe-video")?,
            generation: source::KEY.generation,
            anchor: ContentDigest::sha256(b"recipe history anchor"),
            receive_clock: scope()?.receive_clock,
        },
        time_scale: 90_000,
        limits: CollectorLimits::default(),
        timing_evidence: ContentDigest::sha256(b"independently accepted explicit recipe timing"),
    })
}
fn recipe_limits() -> RecordingRecipeLimits {
    RecordingRecipeLimits::default()
}
fn record_decisions(
    p: &LocalRootPublisher,
    a: &DatagramArchive,
) -> Test<(RecordingRecipe, Vec<PreparedRecording>)> {
    let mut replay = DatagramRecordingReplay::new(a, spec()?, recording()?, bounds(), 1000)?;
    let mut timings = Vec::new();
    let mut windows = Vec::new();
    for _ in 0..512 {
        match replay.step(p, 1000, &NeverCancel, &mut work())? {
            RecordingReplayStep::Capture(event) => match *event {
                CapturePoll::TimingRequired(picture) => {
                    let timing = RecordingTiming {
                        decode_time: 700 + timings.len() as u64 * 3600,
                        duration: 3600,
                        composition_offset: -25,
                    };
                    timings.push(RecordingTimingDecision {
                        observations_read: replay.observations_read(),
                        picture,
                        timing,
                    });
                    let _ = replay.supply_timing(timing, 1000, &NeverCancel, &mut work())?;
                }
                CapturePoll::Window(window) => windows.push(window),
                CapturePoll::Receiver(_) => {}
                other => {
                    return Err(format!(
                        "unexpected reference result: {:?}",
                        RecordingReplayStep::Capture(Box::new(other))
                    )
                    .into());
                }
            },
            RecordingReplayStep::PrefixReady { .. } => {
                replay.finish_prefix(1000, &NeverCancel, &mut work())?
            }
            RecordingReplayStep::FinishedPrefix { .. } => {
                return Ok((
                    RecordingRecipe::new(a, spec()?, recording()?, timings, recipe_limits())?,
                    windows,
                ));
            }
            RecordingReplayStep::Source(_) | RecordingReplayStep::MediaQueued => {}
            other => return Err(format!("unexpected reference result: {other:?}").into()),
        }
    }
    Err("reference reconstruction bound".into())
}
fn fixture(
    name: &str,
) -> Test<(
    LocalRootPublisher,
    DatagramArchive,
    RecordingRecipe,
    Vec<PreparedRecording>,
)> {
    let path = fresh(name)?;
    let pin = save(&path, &observations(true)?)?;
    let (p, a) = reopen(&path, pin)?;
    let (recipe, expected) = record_decisions(&p, &a)?;
    Ok((p, a, recipe, expected))
}
fn run(
    recipe: &RecordingRecipe,
    a: &DatagramArchive,
    p: &LocalRootPublisher,
    now: u64,
) -> Test<Vec<PreparedRecording>> {
    let mut replay = PlannedRecordingReplay::new(recipe, a, recipe_limits(), bounds(), now)?;
    let mut windows = Vec::new();
    for _ in 0..512 {
        match replay.step(p, now, &NeverCancel, &mut work())? {
            RecipeReplayStep::Replay(RecordingReplayStep::Capture(event))
                if matches!(*event, CapturePoll::Window(_)) =>
            {
                let CapturePoll::Window(window) = *event else {
                    return Err("prepared window lost".into());
                };
                windows.push(window);
            }
            RecipeReplayStep::Replay(RecordingReplayStep::FinishedPrefix { retained }) => {
                assert_eq!(replay.timings_applied(), recipe.timings().len());
                assert!(retained.prefix.is_some());
                assert!(matches!(
                    replay.step(p, now, &NeverCancel, &mut work())?,
                    RecipeReplayStep::Ended
                ));
                return Ok(windows);
            }
            RecipeReplayStep::Replay(RecordingReplayStep::Stopped { .. }) => {
                return Err("native interpretation stopped".into());
            }
            RecipeReplayStep::Ended => return Err("missing terminal ownership".into()),
            _ => {}
        }
    }
    Err("planned reconstruction bound".into())
}

#[test]
fn portable_recipe_replays_byte_identical_source_media_index_and_signed_timing() -> Test {
    let (p, a, recipe, expected) = fixture("recipe_roundtrip")?;
    let bytes = recipe.canonical_bytes().to_vec();
    let identity = recipe.identity();
    drop(recipe);
    let decoded = RecordingRecipe::from_canonical_bytes(&bytes, &a, recipe_limits())?;
    assert_eq!(decoded.identity(), identity);
    assert_eq!(decoded.canonical_bytes(), bytes);
    assert_eq!(decoded.timings()[0].timing.composition_offset, -25);
    for now in [1000, 9_000_000_000_000] {
        let result = run(&decoded, &a, &p, now)?;
        assert_eq!(result.len(), expected.len());
        for (actual, expected) in result.iter().zip(&expected) {
            assert_eq!(actual.manifest(), expected.manifest());
            assert_eq!(actual.objects().source, expected.objects().source);
            assert_eq!(actual.objects().media, expected.objects().media);
            assert_eq!(actual.objects().index, expected.objects().index);
        }
    }
    Ok(())
}
#[test]
fn every_truncated_encoding_and_trailing_or_unknown_policy_is_refused() -> Test {
    let (_, a, recipe, _) = fixture("recipe_encoding")?;
    let bytes = recipe.canonical_bytes();
    for cut in 0..bytes.len() {
        assert!(RecordingRecipe::from_canonical_bytes(&bytes[..cut], &a, recipe_limits()).is_err());
    }
    let mut extra = bytes.to_vec();
    extra.push(0);
    assert!(RecordingRecipe::from_canonical_bytes(&extra, &a, recipe_limits()).is_err());
    let mut changed = bytes.to_vec();
    changed[8] ^= 1;
    assert!(RecordingRecipe::from_canonical_bytes(&changed, &a, recipe_limits()).is_err());
    Ok(())
}
#[test]
fn source_prefix_and_parameter_generation_cannot_be_rebound() -> Test {
    let (_, a, recipe, _) = fixture("recipe_scope")?;
    let empty = DatagramArchive::new(scope()?, limits())?;
    assert!(
        RecordingRecipe::from_canonical_bytes(recipe.canonical_bytes(), &empty, recipe_limits())
            .is_err()
    );
    let mut changed = recording()?;
    changed.scope.generation += 1;
    assert!(
        RecordingRecipe::new(
            &a,
            spec()?,
            changed,
            recipe.timings().to_vec(),
            recipe_limits()
        )
        .is_err()
    );
    let mut changed = spec()?;
    changed.pps = changed.sps;
    assert!(
        RecordingRecipe::new(
            &a,
            changed,
            recording()?,
            recipe.timings().to_vec(),
            recipe_limits()
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn external_byte_timing_receiver_and_collector_ceilings_do_not_rewrite_stored_limits() -> Test {
    let (_, a, recipe, _) = fixture("recipe_limits")?;
    let mut receiver = recipe_limits();
    receiver.receiver.reorder.max_bytes -= 1;
    let mut collector = recipe_limits();
    collector.collector.max_samples -= 1;
    for bound in [
        RecordingRecipeLimits {
            max_bytes: recipe.canonical_bytes().len() - 1,
            ..recipe_limits()
        },
        RecordingRecipeLimits {
            max_timings: 0,
            ..recipe_limits()
        },
        receiver,
        collector,
    ] {
        assert!(matches!(
            RecordingRecipe::from_canonical_bytes(recipe.canonical_bytes(), &a, bound),
            Err(RecordingRecipeError::Limit)
        ));
    }
    Ok(())
}
#[test]
fn malformed_overflowing_or_wrong_epoch_timing_is_refused_before_replay() -> Test {
    let (_, a, recipe, _) = fixture("recipe_bad_timing")?;
    for mutation in 0..6 {
        let mut decisions = recipe.timings().to_vec();
        match mutation {
            0 => decisions[0].timing.duration = 0,
            1 => decisions[0].timing.decode_time = u64::MAX,
            2 => decisions[0].timing.composition_offset = i32::MIN,
            3 => decisions[0].observations_read = 0,
            4 => decisions[0].picture.key.generation += 1,
            _ => decisions[0].observations_read = a.pin().datagrams + 1,
        }
        assert!(matches!(
            RecordingRecipe::new(&a, spec()?, recording()?, decisions, recipe_limits()),
            Err(RecordingRecipeError::Timing)
        ));
    }
    Ok(())
}
#[test]
fn changed_request_is_rejected_with_the_exact_untimed_picture_retained() -> Test {
    let (p, a, recipe, _) = fixture("recipe_mismatch")?;
    let mut decisions = recipe.timings().to_vec();
    decisions[0].picture.rtp_timestamp += 1;
    let wrong = RecordingRecipe::new(&a, spec()?, recording()?, decisions, recipe_limits())?;
    let mut replay = PlannedRecordingReplay::new(&wrong, &a, recipe_limits(), bounds(), 1000)?;
    for _ in 0..128 {
        if let Err(failure) = replay.step(&p, 1000, &NeverCancel, &mut work()) {
            assert!(matches!(failure.reason, RecordingRecipeError::Mismatch));
            let retired = failure.retirement.ok_or("lost recipe retirement")?;
            assert!(
                retired
                    .recording
                    .as_ref()
                    .and_then(|r| r.capture.as_ref())
                    .and_then(|c| c.picture.as_ref())
                    .is_some()
            );
            assert!(matches!(retired.withheld.as_deref(),
                Some(RecordingReplayStep::Capture(event)) if matches!(**event, CapturePoll::TimingRequired(_))));
            assert_eq!(replay.timings_applied(), 0);
            assert!(matches!(
                replay.step(&p, 1000, &NeverCancel, &mut work())?,
                RecipeReplayStep::Ended
            ));
            return Ok(());
        }
    }
    Err("wrong picture was not refused".into())
}
#[test]
fn missing_and_unused_decisions_are_not_defaulted_or_ignored() -> Test {
    let (p, a, recipe, _) = fixture("recipe_missing_unused")?;
    for unused in [false, true] {
        let mut decisions = Vec::new();
        if unused {
            decisions.extend_from_slice(recipe.timings());
            let mut extra = decisions[0];
            extra.timing.decode_time += 3600;
            decisions.push(extra);
        }
        let changed = RecordingRecipe::new(&a, spec()?, recording()?, decisions, recipe_limits())?;
        let mut replay =
            PlannedRecordingReplay::new(&changed, &a, recipe_limits(), bounds(), 1000)?;
        let mut refused = false;
        for _ in 0..128 {
            match replay.step(&p, 1000, &NeverCancel, &mut work()) {
                Err(failure) => {
                    assert!(matches!(
                        (&failure.reason, unused),
                        (RecordingRecipeError::MissingTiming, false)
                            | (RecordingRecipeError::UnusedTiming, true)
                    ));
                    assert!(failure.retirement.is_some());
                    refused = true;
                    break;
                }
                Ok(RecipeReplayStep::Replay(RecordingReplayStep::Capture(event)))
                    if matches!(*event, CapturePoll::Window(_)) =>
                {
                    return Err("mismatched plan emitted a terminal window".into());
                }
                _ => {}
            }
        }
        assert!(refused);
    }
    Ok(())
}
#[test]
fn matched_timing_waits_one_step_without_read_ahead_and_clock_refusal_is_retryable() -> Test {
    let (p, a, recipe, _) = fixture("recipe_clock")?;
    let mut replay = PlannedRecordingReplay::new(&recipe, &a, recipe_limits(), bounds(), 1000)?;
    for _ in 0..128 {
        if let RecipeReplayStep::Replay(RecordingReplayStep::Capture(event)) =
            replay.step(&p, 1000, &NeverCancel, &mut work())?
            && matches!(*event, CapturePoll::TimingRequired(_))
        {
            let observed = replay.observations_read();
            let failure = replay
                .step(&p, 999, &NeverCancel, &mut work())
                .err()
                .ok_or("accepted reverse clock")?;
            assert!(failure.retirement.is_none());
            assert_eq!(replay.timings_applied(), 0);
            assert!(matches!(
                replay.step(&p, 1000, &NeverCancel, &mut work())?,
                RecipeReplayStep::TimingApplied { index: 0, .. }
            ));
            assert_eq!(replay.observations_read(), observed);
            return Ok(());
        }
    }
    Err("timing request missing".into())
}
#[test]
fn incomplete_fragment_prefix_is_not_flushed_into_a_picture_or_recording() -> Test {
    let path = fresh("recipe_fragment")?;
    let mut input = observations(true)?;
    let _ = input.pop();
    let pin = save(&path, &input)?;
    let (p, a) = reopen(&path, pin)?;
    let recipe = RecordingRecipe::new(&a, spec()?, recording()?, vec![], recipe_limits())?;
    assert!(run(&recipe, &a, &p, 1000)?.is_empty());
    Ok(())
}
#[test]
fn source_backpressure_does_not_authorize_an_unrecorded_manual_seal() -> Test {
    let (p, a, recipe, _) = fixture("recipe_pressure")?;
    let mut low = recording()?;
    low.limits.max_source_bytes = 12;
    let limited =
        RecordingRecipe::new(&a, spec()?, low, recipe.timings().to_vec(), recipe_limits())?;
    let mut replay = PlannedRecordingReplay::new(&limited, &a, recipe_limits(), bounds(), 1000)?;
    for _ in 0..128 {
        if let Err(failure) = replay.step(&p, 1000, &NeverCancel, &mut work()) {
            assert!(matches!(
                failure.reason,
                RecordingRecipeError::CollectionPressure
            ));
            assert!(failure.retirement.is_some());
            return Ok(());
        }
    }
    Err("collection pressure was not refused".into())
}
#[test]
fn explicit_cancellation_transfers_a_pending_picture_once() -> Test {
    let (p, a, recipe, _) = fixture("recipe_cancel")?;
    let mut replay = PlannedRecordingReplay::new(&recipe, &a, recipe_limits(), bounds(), 1000)?;
    for _ in 0..128 {
        if let RecipeReplayStep::Replay(RecordingReplayStep::Capture(event)) =
            replay.step(&p, 1000, &NeverCancel, &mut work())?
            && matches!(*event, CapturePoll::TimingRequired(_))
        {
            let retired = replay.cancel().ok_or("retirement missing")?;
            assert!(
                retired
                    .recording
                    .as_ref()
                    .and_then(|r| r.capture.as_ref())
                    .and_then(|c| c.picture.as_ref())
                    .is_some()
            );
            assert!(replay.cancel().is_none());
            return Ok(());
        }
    }
    Err("timing request missing".into())
}
struct Stop;
impl PublishCancellation for Stop {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        true
    }
}
#[test]
fn current_cancellation_and_work_exhaustion_fence_instead_of_skipping_a_decision() -> Test {
    let (p, a, recipe, _) = fixture("recipe_admission")?;
    for cancelled in [true, false] {
        let mut replay = PlannedRecordingReplay::new(&recipe, &a, recipe_limits(), bounds(), 1000)?;
        let result = if cancelled {
            replay.step(&p, 1000, &Stop, &mut work())
        } else {
            replay.step(
                &p,
                1000,
                &NeverCancel,
                &mut fss_geometry::WorkBudget::new(0),
            )
        };
        assert!(
            result
                .err()
                .ok_or("refused work succeeded")?
                .retirement
                .is_some()
        );
        assert_eq!(replay.timings_applied(), 0);
        assert!(matches!(
            replay.step(&p, 1000, &NeverCancel, &mut work())?,
            RecipeReplayStep::Ended
        ));
    }
    Ok(())
}

#[path = "recording_recipe/storage.rs"]
mod storage_contracts;
