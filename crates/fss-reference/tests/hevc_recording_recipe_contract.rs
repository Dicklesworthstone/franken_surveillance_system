#![forbid(unsafe_code)]
//! Portable HEVC timing programs, actual source custody and native recording equivalence.
mod hevc_datagram_support;
use fss_core::ContentDigest;
use fss_packet::hevc::{HevcAssemblyLimits, HevcBoundary};
use fss_publication::{
    LocalRootPublisher, NeverCancel, PublishCancellation, PublishCutPoint, PublishOutcome,
};
use fss_reference::rtsp::datagram_archive::DatagramArchive;
use fss_reference::rtsp::datagram_reconstruction::hevc::recording::*;
use fss_reference::rtsp::hevc_recording_capture::HevcCapturePoll;
use fss_reference::rtsp::recording::hevc::{HevcRecordingTiming, PreparedHevcRecording};
use fss_reference::rtsp::recording_collector::CollectorLimits;
use fss_reference::rtsp::recording_recipe::hevc::storage::*;
use fss_reference::rtsp::recording_recipe::hevc::*;
use hevc_datagram_support::*;

fn recording() -> Test<HevcRecordingReplaySpec> {
    Ok(HevcRecordingReplaySpec {
        scope: media::scope()?,
        configuration: media::configuration()?,
        time_scale: 90_000,
        limits: CollectorLimits::default(),
        assembly: HevcAssemblyLimits::default(),
        timing_evidence: ContentDigest::sha256(b"original explicit timing evidence"),
    })
}
fn input(fragmented: bool) -> Test<Vec<Observation>> {
    let mut input = observations(fragmented)?;
    let n = media::nals()?;
    let idr = n
        .iter()
        .find(|n| matches!((n[0] >> 1) & 63, 19 | 20))
        .ok_or("IDR")?;
    let seq = input.len() as u64 + 1;
    input.push((0, 10 + seq - 1, raw(seq, 27_000, true, idr)));
    Ok(input)
}
fn record_choices(
    p: &LocalRootPublisher,
    a: &DatagramArchive,
) -> Test<(Vec<RecordingTimingDecision>, Vec<PreparedHevcRecording>)> {
    let mut native = DatagramHevcRecordingReplay::new(a, spec(), recording()?, bounds(), 0)?;
    let mut decisions = Vec::new();
    let mut windows = Vec::new();
    let mut budget = work();
    for _ in 0..1024 {
        match native.step(p, 0, &NeverCancel, &mut budget)? {
            HevcRecordingReplayStep::Capture(e) => match *e {
                HevcCapturePoll::TimingRequired(picture) => {
                    let timing = HevcRecordingTiming {
                        decode_time: decisions.len() as u64 * 18_000,
                        duration: 18_000,
                        composition_offset: 0,
                    };
                    decisions.push(RecordingTimingDecision {
                        observations_read: native.observations_read(),
                        picture,
                        timing,
                    });
                    let _ = native.supply_timing(timing, 0, &NeverCancel, &mut budget)?;
                }
                HevcCapturePoll::Window(w) => windows.push(*w),
                _ => {}
            },
            HevcRecordingReplayStep::PrefixReady { .. } => {
                let _ = native.finish_prefix(0, &NeverCancel, &mut budget)?;
            }
            HevcRecordingReplayStep::FinishedPrefix { .. } => return Ok((decisions, windows)),
            HevcRecordingReplayStep::Stopped { .. } | HevcRecordingReplayStep::Ended => {
                return Err("unexpected native stop".into());
            }
            _ => {}
        }
    }
    Err("native work bound".into())
}
fn drive(
    p: &LocalRootPublisher,
    a: &DatagramArchive,
    recipe: &RecordingRecipe,
) -> Test<(Vec<PreparedHevcRecording>, HevcRecordingReplayRetirement)> {
    let mut r =
        PlannedRecordingReplay::new(recipe, a, RecordingRecipeLimits::default(), bounds(), 100)?;
    let mut windows = Vec::new();
    let mut timings = 0;
    let mut seals = 0;
    let mut budget = work();
    for _ in 0..1024 {
        match r.step(p, 100, &NeverCancel, &mut budget)? {
            RecipeReplayStep::TimingApplied {
                index, decision, ..
            } => {
                assert_eq!(index, timings);
                assert_eq!(decision, recipe.timings()[index]);
                timings += 1;
            }
            RecipeReplayStep::PrefixFinalizing { seal } => {
                assert_eq!(seal.window_ready, !recipe.timings().is_empty());
                seals += 1;
            }
            RecipeReplayStep::Replay(HevcRecordingReplayStep::Capture(e)) => {
                if let HevcCapturePoll::Window(w) = *e {
                    windows.push(*w);
                }
            }
            RecipeReplayStep::Replay(HevcRecordingReplayStep::FinishedPrefix { retained }) => {
                assert_eq!(timings, recipe.timings().len());
                assert_eq!(seals, 1);
                assert!(r.cancel().is_none());
                assert!(matches!(
                    r.step(p, 100, &NeverCancel, &mut budget)?,
                    RecipeReplayStep::Ended
                ));
                return Ok((windows, *retained));
            }
            RecipeReplayStep::Replay(HevcRecordingReplayStep::Stopped { .. })
            | RecipeReplayStep::Ended => return Err("unexpected recipe stop".into()),
            _ => {}
        }
    }
    Err("recipe work bound".into())
}
fn fixture(
    name: &str,
    fragmented: bool,
) -> Test<(
    LocalRootPublisher,
    DatagramArchive,
    Vec<RecordingTimingDecision>,
    Vec<PreparedHevcRecording>,
)> {
    let path = fresh(name)?;
    let pin = save(&path, &input(fragmented)?)?;
    let (p, a) = reopen(&path, pin)?;
    let (d, w) = record_choices(&p, &a)?;
    Ok((p, a, d, w))
}
fn execution_failure(
    p: &LocalRootPublisher,
    a: &DatagramArchive,
    recipe: &RecordingRecipe,
) -> Test<RecipeReplayFailure> {
    let mut r =
        PlannedRecordingReplay::new(recipe, a, RecordingRecipeLimits::default(), bounds(), 0)?;
    let mut budget = work();
    for _ in 0..1024 {
        match r.step(p, 0, &NeverCancel, &mut budget) {
            Err(e) => {
                assert!(r.cancel().is_none());
                assert!(matches!(
                    r.step(p, 0, &NeverCancel, &mut budget)?,
                    RecipeReplayStep::Ended
                ));
                return Ok(e);
            }
            Ok(RecipeReplayStep::Ended) => return Err("bad recipe accepted".into()),
            _ => {}
        }
    }
    Err("failure bound".into())
}
#[test]
fn canonical_cold_recipe_reproduces_native_single_and_fragmented_recordings() -> Test {
    for fragmented in [false, true] {
        let (p, a, d, expected) = fixture(
            if fragmented {
                "recipe-roundtrip-fu"
            } else {
                "recipe-roundtrip-single"
            },
            fragmented,
        )?;
        let recipe = RecordingRecipe::new(
            &a,
            spec(),
            recording()?,
            d,
            RecordingRecipeLimits::default(),
        )?;
        let bytes = recipe.canonical_bytes().to_vec();
        let identity = recipe.identity();
        drop(recipe);
        let recipe =
            RecordingRecipe::from_canonical_bytes(&bytes, &a, RecordingRecipeLimits::default())?;
        assert_eq!(recipe.identity(), identity);
        assert_eq!(recipe.canonical_bytes(), bytes);
        let (windows, tail) = drive(&p, &a, &recipe)?;
        assert_eq!(windows.len(), expected.len());
        for (w, e) in windows.iter().zip(expected.iter()) {
            assert_eq!(w.manifest(), e.manifest());
            assert_eq!(w.objects().source, e.objects().source);
            assert_eq!(w.objects().media, e.objects().media);
            assert_eq!(w.objects().index, e.objects().index);
            assert_eq!(w.source_only_nals(), 1);
        }
        assert!(tail.assembly.is_some());
        assert_eq!(tail.boundary, Some(HevcReplayBoundary::RetainedPrefix));
    }
    Ok(())
}
#[test]
fn portable_encoding_refuses_truncation_trailing_bytes_wrong_domains_and_digests() -> Test {
    let (_, a, d, _) = fixture("recipe-encoding", false)?;
    let recipe = RecordingRecipe::new(
        &a,
        spec(),
        recording()?,
        d,
        RecordingRecipeLimits::default(),
    )?;
    let bytes = recipe.canonical_bytes();
    for end in 0..bytes.len() {
        assert!(
            RecordingRecipe::from_canonical_bytes(
                &bytes[..end],
                &a,
                RecordingRecipeLimits::default()
            )
            .is_err()
        );
    }
    let mut extra = bytes.to_vec();
    extra.push(0);
    assert!(
        RecordingRecipe::from_canonical_bytes(&extra, &a, RecordingRecipeLimits::default())
            .is_err()
    );
    // Header source/interpretation changes cannot select a different observed prefix.
    for needle in [
        b"fss.datagram_hevc_recording_recipe.v1".as_slice(),
        recipe.source().head.bytes().as_slice(),
        recipe.interpretation().bytes().as_slice(),
    ] {
        let mut changed = bytes.to_vec();
        let at = changed
            .windows(needle.len())
            .position(|s| s == needle)
            .ok_or("needle")?;
        changed[at] ^= 1;
        assert!(
            RecordingRecipe::from_canonical_bytes(&changed, &a, RecordingRecipeLimits::default())
                .is_err()
        );
    }
    Ok(())
}
#[test]
fn caller_ceilings_cannot_be_widened_by_stored_native_configuration() -> Test {
    let (_, a, d, _) = fixture("recipe-limits", false)?;
    let recipe = RecordingRecipe::new(
        &a,
        spec(),
        recording()?,
        d,
        RecordingRecipeLimits::default(),
    )?;
    let mut policies = Vec::new();
    let base = RecordingRecipeLimits::default();
    let mut l = base;
    l.max_bytes = recipe.canonical_bytes().len() - 1;
    policies.push(l);
    let mut l = base;
    l.max_timings = 0;
    policies.push(l);
    let mut l = base;
    l.reorder.max_packets -= 1;
    policies.push(l);
    let mut l = base;
    l.reconstruction.max_fragment_packets -= 1;
    policies.push(l);
    let mut l = base;
    l.assembly.max_source_spans -= 1;
    policies.push(l);
    let mut l = base;
    l.collector.max_samples -= 1;
    policies.push(l);
    let mut l = base;
    l.configuration.max_width = 1;
    policies.push(l);
    for l in policies {
        assert!(RecordingRecipe::from_canonical_bytes(recipe.canonical_bytes(), &a, l).is_err());
        assert!(PlannedRecordingReplay::new(&recipe, &a, l, bounds(), 0).is_err());
    }
    Ok(())
}
#[test]
fn missing_or_mismatched_decision_returns_the_held_picture_and_exact_request() -> Test {
    let (p, a, d, _) = fixture("recipe-request-match", false)?;
    for variant in 0..4 {
        let mut choices = d.clone();
        match variant {
            0 => choices.clear(),
            1 => choices[0].picture.rtp_timestamp += 1,
            2 => choices[0].observations_read -= 1,
            _ => choices[0].picture.idr = false,
        }
        let recipe = RecordingRecipe::new(
            &a,
            spec(),
            recording()?,
            choices,
            RecordingRecipeLimits::default(),
        )?;
        let failure = execution_failure(&p, &a, &recipe)?;
        assert!(matches!(
            failure.reason,
            RecordingRecipeError::Mismatch | RecordingRecipeError::MissingTiming
        ));
        let retired = failure.retirement.ok_or("retirement")?;
        assert_eq!(retired.timings_applied, 0);
        assert!(
            matches!(retired.withheld.as_deref(),Some(HevcRecordingReplayStep::Capture(e)) if matches!(**e,HevcCapturePoll::TimingRequired(_)))
        );
        assert!(
            retired
                .recording
                .ok_or("native")?
                .capture
                .ok_or("capture")?
                .event
                .is_some()
        );
    }
    Ok(())
}
#[test]
fn unused_timing_is_not_silently_ignored_at_the_retained_prefix_boundary() -> Test {
    let (p, a, mut d, _) = fixture("recipe-unused", false)?;
    let mut extra = d[0];
    extra.timing.decode_time += 18_000;
    d.push(extra);
    let recipe = RecordingRecipe::new(
        &a,
        spec(),
        recording()?,
        d,
        RecordingRecipeLimits::default(),
    )?;
    let failure = execution_failure(&p, &a, &recipe)?;
    assert!(matches!(failure.reason, RecordingRecipeError::UnusedTiming));
    assert!(matches!(
        failure.retirement.ok_or("retired")?.withheld.as_deref(),
        Some(HevcRecordingReplayStep::PrefixReady { .. })
    ));
    Ok(())
}
#[test]
fn invalid_timing_boundary_and_no_don_contracts_refuse_before_io() -> Test {
    let (_, a, d, _) = fixture("recipe-invalid-timing", false)?;
    for i in 0..6 {
        let mut bad = d.clone();
        match i {
            0 => bad[0].timing.duration = 0,
            1 => bad[0].timing.decode_time = u64::MAX,
            2 => bad[0].timing.composition_offset = -1,
            3 => bad[0].picture.boundary = HevcBoundary::EndOfInputUnverified,
            4 => bad[0].picture.key.generation += 1,
            _ => bad[0].observations_read = 0,
        }
        assert!(
            RecordingRecipe::new(
                &a,
                spec(),
                recording()?,
                bad,
                RecordingRecipeLimits::default()
            )
            .is_err()
        );
    }
    let mut s = spec();
    s.sprop_max_don_diff = 1;
    assert!(
        RecordingRecipe::new(&a, s, recording()?, d, RecordingRecipeLimits::default()).is_err()
    );
    Ok(())
}
#[test]
fn changed_source_prefix_refuses_without_reusing_the_older_program() -> Test {
    let (mut p, mut a, d, _) = fixture("recipe-source-pin", false)?;
    let recipe = RecordingRecipe::new(
        &a,
        spec(),
        recording()?,
        d,
        RecordingRecipeLimits::default(),
    )?;
    append(
        &mut p,
        &mut a,
        &[(1, 100, vec![0x80, 201, 0, 1, 0, 0, 0, 1])],
    )?;
    assert!(
        RecordingRecipe::from_canonical_bytes(
            recipe.canonical_bytes(),
            &a,
            RecordingRecipeLimits::default()
        )
        .is_err()
    );
    assert!(
        PlannedRecordingReplay::new(&recipe, &a, RecordingRecipeLimits::default(), bounds(), 0)
            .is_err()
    );
    Ok(())
}
struct Cancel;
impl PublishCancellation for Cancel {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        true
    }
}
#[test]
fn cancellation_and_current_work_bounds_stop_once_without_publishing() -> Test {
    let (p, a, d, _) = fixture("recipe-cancel", false)?;
    let recipe = RecordingRecipe::new(
        &a,
        spec(),
        recording()?,
        d,
        RecordingRecipeLimits::default(),
    )?;
    let before = p.visible_roots().count();
    for cancellation in [false, true] {
        let mut r = PlannedRecordingReplay::new(
            &recipe,
            &a,
            RecordingRecipeLimits::default(),
            bounds(),
            100,
        )?;
        assert!(
            r.step(&p, 99, &NeverCancel, &mut work())
                .err()
                .ok_or("clock")?
                .retirement
                .is_none()
        );
        let mut budget = if cancellation {
            work()
        } else {
            fss_geometry::WorkBudget::new(0)
        };
        let cancel: &dyn PublishCancellation = if cancellation { &Cancel } else { &NeverCancel };
        let error = r
            .step(&p, 100, cancel, &mut budget)
            .err()
            .ok_or("expected refusal")?;
        assert!(error.retirement.is_some());
        assert!(r.cancel().is_none());
    }
    assert_eq!(before, p.visible_roots().count());
    Ok(())
}
#[test]
fn published_recipe_reopens_and_retries_exactly_without_claiming_recordings() -> Test {
    let path = fresh("recipe-stored")?;
    let pin = save(&path, &input(true)?)?;
    let stored = {
        let (mut p, a) = reopen(&path, pin)?;
        let (d, _) = record_choices(&p, &a)?;
        let recipe = RecordingRecipe::new(
            &a,
            spec(),
            recording()?,
            d,
            RecordingRecipeLimits::default(),
        )?;
        let plan = PreparedRecordingRecipe::prepare(
            &recipe,
            &a,
            &p,
            RecipeStorageLimits::default(),
            &NeverCancel,
            &mut work(),
        )?;
        let first = plan.publish(&mut p, &NeverCancel, &mut work())?;
        assert_eq!(first.local.outcome, PublishOutcome::Published);
        let again = plan.publish(&mut p, &NeverCancel, &mut work())?;
        assert_eq!(again.local.outcome, PublishOutcome::AlreadyPublished);
        assert_eq!(first.pin, again.pin);
        first.pin
    };
    let (p, a) = reopen(&path, pin)?;
    let loaded = load_recording_recipe(
        &p,
        &stored,
        &a,
        RecordingRecipeLimits::default(),
        RecipeStorageLimits::default(),
        &NeverCancel,
        &mut work(),
    )?;
    let (windows, _) = drive(&p, &a, &loaded)?;
    assert_eq!(windows.len(), 1);
    assert!(
        p.visible_roots()
            .all(|r| r.root != windows[0].manifest().root())
    );
    Ok(())
}
#[test]
fn incomplete_and_empty_source_recipes_do_not_invent_final_pictures() -> Test {
    for empty in [false, true] {
        let path = fresh(if empty {
            "recipe-empty"
        } else {
            "recipe-incomplete"
        })?;
        let data = if empty {
            Vec::new()
        } else {
            observations(true)?
        };
        let pin = save(&path, &data)?;
        let (p, a) = reopen(&path, pin)?;
        let (d, w) = record_choices(&p, &a)?;
        assert!(d.is_empty());
        assert!(w.is_empty());
        let recipe = RecordingRecipe::new(
            &a,
            spec(),
            recording()?,
            d,
            RecordingRecipeLimits::default(),
        )?;
        let (w, tail) = drive(&p, &a, &recipe)?;
        assert!(w.is_empty());
        assert_eq!(tail.boundary, Some(HevcReplayBoundary::RetainedPrefix));
        if !empty {
            assert!(tail.assembly.is_some());
        }
    }
    Ok(())
}
