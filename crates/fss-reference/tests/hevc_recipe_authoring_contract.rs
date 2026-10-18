#![forbid(unsafe_code)]
//! Real cold original-source fixtures; authoring never owns publication or a camera.
mod hevc_datagram_support;
use fss_core::ContentDigest;
use fss_packet::hevc::HevcAssemblyLimits;
use fss_publication::{LocalRootPublisher, NeverCancel, PublishCancellation, PublishCutPoint};
use fss_reference::rtsp::datagram_archive::DatagramArchive;
use fss_reference::rtsp::datagram_reconstruction::hevc::recording::*;
use fss_reference::rtsp::hevc_recording_capture::HevcCapturePoll;
use fss_reference::rtsp::recording::hevc::{HevcRecordingTiming, PreparedHevcRecording};
use fss_reference::rtsp::recording_collector::CollectorLimits;
use fss_reference::rtsp::recording_recipe::hevc::authoring::*;
use fss_reference::rtsp::recording_recipe::hevc::storage::*;
use fss_reference::rtsp::recording_recipe::hevc::*;
use hevc_datagram_support::*;
use std::cell::Cell;

fn recording() -> Test<HevcRecordingReplaySpec> {
    Ok(HevcRecordingReplaySpec {
        scope: media::scope()?,
        configuration: media::configuration()?,
        time_scale: 90_000,
        limits: CollectorLimits::default(),
        assembly: HevcAssemblyLimits::default(),
        timing_evidence: ContentDigest::sha256(b"independent original fixture timing"),
    })
}
fn row(index: u64) -> TimingInput {
    TimingInput {
        rtp_timestamp: 9000 + index as u32 * 18000,
        timing: HevcRecordingTiming {
            decode_time: index * 18000,
            duration: 18000,
            composition_offset: 0,
        },
    }
}
fn input(fragmented: bool, eob: bool) -> Test<Vec<Observation>> {
    let mut data = observations(fragmented)?;
    let nals = media::nals()?;
    let idr = nals
        .iter()
        .find(|n| matches!((n[0] >> 1) & 63, 19 | 20))
        .ok_or("IDR")?;
    let seq = data.len() as u64 + 1;
    data.push((0, 9 + seq, raw(seq, 27000, true, idr)));
    if eob {
        data.push((0, 10 + seq, raw(seq + 1, 27000, false, &[37 << 1, 1, 0x80])));
        data.push((1, 11 + seq, vec![0, 0, 0])); // unread after EOB, not silently interpreted
    }
    Ok(data)
}
fn author<'a>(
    archive: &'a DatagramArchive,
    rows: Vec<TimingInput>,
) -> Test<RecordingRecipeAuthor<'a>> {
    Ok(RecordingRecipeAuthor::new(
        archive,
        spec(),
        recording()?,
        rows,
        RecordingRecipeLimits::default(),
        bounds(),
        0,
    )?)
}
fn finish(
    p: &LocalRootPublisher,
    a: &mut RecordingRecipeAuthor<'_>,
) -> Test<(
    Box<RecordingRecipe>,
    Vec<PreparedHevcRecording>,
    Box<HevcRecordingReplayRetirement>,
)> {
    let mut windows = Vec::new();
    let mut budget = work();
    for _ in 0..2048 {
        match a.step(p, 0, &NeverCancel, &mut budget)? {
            AuthoringStep::Replay(HevcRecordingReplayStep::Capture(event)) => {
                if let HevcCapturePoll::Window(w) = *event {
                    windows.push(*w);
                }
            }
            AuthoringStep::Finished { recipe, retained } => return Ok((recipe, windows, retained)),
            AuthoringStep::Ended => return Err("author ended without recipe".into()),
            _ => {}
        }
    }
    Err("author bound".into())
}
fn failure(p: &LocalRootPublisher, a: &mut RecordingRecipeAuthor<'_>) -> Test<AuthoringFailure> {
    let mut budget = work();
    for _ in 0..2048 {
        match a.step(p, 0, &NeverCancel, &mut budget) {
            Err(e) => {
                assert!(a.cancel().is_none());
                return Ok(e);
            }
            Ok(AuthoringStep::Finished { .. } | AuthoringStep::Ended) => {
                return Err("bad draft succeeded".into());
            }
            _ => {}
        }
    }
    Err("failure bound".into())
}
fn replay(
    p: &LocalRootPublisher,
    a: &DatagramArchive,
    recipe: &RecordingRecipe,
) -> Test<Vec<PreparedHevcRecording>> {
    let mut r =
        PlannedRecordingReplay::new(recipe, a, RecordingRecipeLimits::default(), bounds(), 0)?;
    let mut windows = Vec::new();
    let mut budget = work();
    for _ in 0..2048 {
        match r.step(p, 0, &NeverCancel, &mut budget)? {
            RecipeReplayStep::Replay(HevcRecordingReplayStep::Capture(event)) => {
                if let HevcCapturePoll::Window(w) = *event {
                    windows.push(*w);
                }
            }
            RecipeReplayStep::Replay(HevcRecordingReplayStep::FinishedPrefix { .. }) => {
                return Ok(windows);
            }
            RecipeReplayStep::Replay(HevcRecordingReplayStep::Stopped { .. })
            | RecipeReplayStep::Ended => return Err("authored recipe stopped".into()),
            _ => {}
        }
    }
    Err("replay bound".into())
}
#[test]
fn explicit_rows_author_existing_canonical_recipe_and_cold_source_closed_replay() -> Test {
    for fragmented in [false, true] {
        let path = fresh(&format!("author_cold_{fragmented}"))?;
        let pin = save(&path, &input(fragmented, false)?)?;
        let (mut p, archive) = reopen(&path, pin)?;
        let roots = p.visible_roots().count();
        let mut a = author(&archive, vec![row(0)])?;
        let (recipe, preview, retained) = finish(&p, &mut a)?;
        assert_eq!(retained.boundary, Some(HevcReplayBoundary::RetainedPrefix));
        assert_eq!(recipe.timings().len(), 1);
        assert_eq!(a.timings_applied(), 1);
        assert!(a.cancel().is_none());
        assert!(matches!(
            a.step(&p, 0, &NeverCancel, &mut work())?,
            AuthoringStep::Ended
        ));
        assert_eq!(p.visible_roots().count(), roots); // authoring never publishes
        let expected = RecordingRecipe::new(
            &archive,
            spec(),
            recording()?,
            recipe.timings().to_vec(),
            RecordingRecipeLimits::default(),
        )?;
        assert_eq!(recipe.canonical_bytes(), expected.canonical_bytes());
        assert_eq!(preview.len(), 1);
        let result = PreparedRecordingRecipe::prepare(
            &recipe,
            &archive,
            &p,
            RecipeStorageLimits::default(),
            &NeverCancel,
            &mut work(),
        )?;
        let receipt = result.publish(&mut p, &NeverCancel, &mut work())?;
        drop(result);
        drop(recipe);
        drop(p);
        let (p, archive) = reopen(&path, pin)?;
        let loaded = load_recording_recipe(
            &p,
            &receipt.pin,
            &archive,
            RecordingRecipeLimits::default(),
            RecipeStorageLimits::default(),
            &NeverCancel,
            &mut work(),
        )?;
        let replayed = replay(&p, &archive, &loaded)?;
        assert_eq!(preview.len(), replayed.len());
        for (a, b) in preview.iter().zip(replayed) {
            assert_eq!(a.manifest().root(), b.manifest().root());
            assert_eq!(a.objects().source, b.objects().source);
            assert_eq!(a.objects().media, b.objects().media);
            assert_eq!(a.objects().index, b.objects().index);
        }
    }
    Ok(())
}
#[test]
fn eob_requires_exact_schedule_and_preserves_unread_source() -> Test {
    let path = fresh("author_eob")?;
    let pin = save(&path, &input(false, true)?)?;
    let (p, archive) = reopen(&path, pin)?;
    let (recipe, windows, retained) = finish(&p, &mut author(&archive, vec![row(0), row(1)])?)?;
    assert_eq!(retained.boundary, Some(HevcReplayBoundary::EndOfBitstream));
    assert_eq!(retained.observations_read, pin.datagrams - 1);
    assert_eq!(recipe.timings().len(), 2);
    assert_eq!(windows.iter().map(|w| w.samples().len()).sum::<usize>(), 2);
    let error = failure(&p, &mut author(&archive, vec![row(0), row(1), row(2)])?)?;
    assert!(matches!(
        error.reason,
        AuthoringError::Recipe(RecordingRecipeError::UnusedTiming)
    ));
    Ok(())
}
#[test]
fn incomplete_and_empty_sources_never_invent_picture_or_timing() -> Test {
    for data in [vec![], observations(true)?.into_iter().take(2).collect()] {
        let path = fresh(&format!("author_incomplete_{}", data.len()))?;
        let pin = save(&path, &data)?;
        let (p, archive) = reopen(&path, pin)?;
        let (recipe, windows, retained) = finish(&p, &mut author(&archive, vec![])?)?;
        assert_eq!(recipe.timings().len(), 0);
        assert!(windows.is_empty());
        assert_eq!(retained.boundary, Some(HevcReplayBoundary::RetainedPrefix));
        assert_eq!(retained.observations_read, pin.datagrams);
        if !data.is_empty() {
            assert!(format!("{retained:?}").contains("fragment"));
        }
    }
    Ok(())
}
#[test]
fn missing_extra_and_wrong_timestamp_rows_return_native_request_without_recipe() -> Test {
    let path = fresh("author_bad_rows")?;
    let pin = save(&path, &input(false, false)?)?;
    let (p, archive) = reopen(&path, pin)?;
    for (rows, expected) in [
        (vec![], "missing"),
        (vec![row(0), row(1)], "extra"),
        (vec![row(1)], "mismatch"),
    ] {
        let error = failure(&p, &mut author(&archive, rows)?)?;
        assert!(match (&error.reason, expected) {
            (AuthoringError::Recipe(RecordingRecipeError::MissingTiming), "missing")
            | (AuthoringError::Recipe(RecordingRecipeError::UnusedTiming), "extra")
            | (AuthoringError::Recipe(RecordingRecipeError::Mismatch), "mismatch") => true,
            _ => false,
        });
        let retired = error.retirement.ok_or("retirement")?;
        assert!(retired.candidate.is_none());
        assert!(retired.withheld.is_some());
        assert_eq!(retired.source, pin);
    }
    Ok(())
}
#[test]
fn bad_timelines_and_limits_refuse_before_source_reads() -> Test {
    let path = fresh("author_bounds")?;
    let pin = save(&path, &input(false, false)?)?;
    let (_, archive) = reopen(&path, pin)?;
    let mut zero = row(0);
    zero.timing.duration = 0;
    let mut overflow = row(0);
    overflow.timing.decode_time = u64::MAX;
    let mut underflow = row(0);
    underflow.timing.composition_offset = -1;
    for rows in [
        vec![zero],
        vec![overflow],
        vec![underflow],
        vec![row(0), row(0)],
    ] {
        assert!(matches!(
            RecordingRecipeAuthor::new(
                &archive,
                spec(),
                recording()?,
                rows,
                RecordingRecipeLimits::default(),
                bounds(),
                0
            ),
            Err(RecordingRecipeError::Timing)
        ));
    }
    assert!(matches!(
        RecordingRecipeAuthor::new(
            &archive,
            spec(),
            recording()?,
            vec![row(0)],
            RecordingRecipeLimits {
                max_timings: 0,
                ..RecordingRecipeLimits::default()
            },
            bounds(),
            0
        ),
        Err(RecordingRecipeError::Limit)
    ));
    Ok(())
}
#[test]
fn pending_timing_survives_clock_refusal_and_cancel_transfers_once() -> Test {
    let path = fresh("author_clock")?;
    let pin = save(&path, &input(false, false)?)?;
    let (p, archive) = reopen(&path, pin)?;
    let mut a = author(&archive, vec![row(0)])?;
    let mut budget = work();
    let mut held = false;
    for _ in 0..1024 {
        if let AuthoringStep::Replay(HevcRecordingReplayStep::Capture(e)) =
            a.step(&p, 10, &NeverCancel, &mut budget)?
            && matches!(*e, HevcCapturePoll::TimingRequired(_))
        {
            held = true;
            break;
        }
    }
    assert!(held);
    let before = a.observations_read();
    let error = a
        .step(&p, 9, &NeverCancel, &mut budget)
        .err()
        .ok_or("clock refused")?;
    assert!(error.retirement.is_none());
    assert_eq!(a.timings_applied(), 0);
    assert_eq!(a.observations_read(), before);
    assert!(matches!(
        a.step(&p, 10, &NeverCancel, &mut budget)?,
        AuthoringStep::TimingApplied { index: 0, .. }
    ));
    assert_eq!(a.timings_applied(), 1);
    let retained = a.cancel().ok_or("cancel")?;
    assert_eq!(retained.timings_applied, 1);
    assert!(retained.recording.is_some());
    assert!(a.cancel().is_none());
    Ok(())
}
#[test]
fn source_loss_is_not_a_successful_recipe() -> Test {
    let mut data = input(false, false)?;
    let nals = media::nals()?;
    // A receiver restart/malformed source cannot be replaced with guessed missing pictures.
    data.push((0, 50, vec![0]));
    let path = fresh("author_loss")?;
    let pin = save(&path, &data)?;
    let (p, archive) = reopen(&path, pin)?;
    let e = failure(&p, &mut author(&archive, vec![row(0)])?)?;
    assert!(matches!(
        e.reason,
        AuthoringError::Stopped | AuthoringError::Recipe(_)
    ));
    assert!(e.retirement.ok_or("retirement")?.candidate.is_none());
    assert!(!nals.is_empty());
    Ok(())
}
#[test]
fn budget_and_deadline_refuse_without_recipe_or_publication() -> Test {
    let path = fresh("author_deadline")?;
    let pin = save(&path, &input(false, false)?)?;
    let (p, archive) = reopen(&path, pin)?;
    let roots = p.visible_roots().count();
    let mut a = author(&archive, vec![row(0)])?;
    let mut zero = fss_geometry::WorkBudget::new(0);
    assert!(a.step(&p, 0, &NeverCancel, &mut zero).is_err());
    assert!(a.cancel().is_none());
    let mut b = RecordingRecipeAuthor::new(
        &archive,
        spec(),
        recording()?,
        vec![row(0)],
        RecordingRecipeLimits::default(),
        fss_reference::rtsp::datagram_reconstruction::hevc::HevcReplayBounds {
            deadline_ns: 1,
            ..bounds()
        },
        0,
    )?;
    assert!(b.step(&p, 1, &NeverCancel, &mut work()).is_err());
    assert_eq!(p.visible_roots().count(), roots);
    Ok(())
}
struct Cut {
    calls: Cell<usize>,
    at: usize,
}
impl PublishCancellation for Cut {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        let n = self.calls.get() + 1;
        self.calls.set(n);
        n >= self.at
    }
}
#[test]
fn post_encoding_revocation_returns_withheld_recipe_and_terminal_originals() -> Test {
    let path = fresh("author_post_cancel")?;
    let pin = save(&path, &input(false, false)?)?;
    let (p, archive) = reopen(&path, pin)?;
    let count = Cut {
        calls: Cell::new(0),
        at: usize::MAX,
    };
    let mut a = author(&archive, vec![row(0)])?;
    let mut budget = work();
    let mut done = false;
    for _ in 0..2048 {
        if matches!(
            a.step(&p, 0, &count, &mut budget)?,
            AuthoringStep::Finished { .. }
        ) {
            done = true;
            break;
        }
    }
    assert!(done);
    let cut = Cut {
        calls: Cell::new(0),
        at: count.calls.get(),
    };
    let mut a = author(&archive, vec![row(0)])?;
    let mut budget = work();
    let mut failed = false;
    for _ in 0..2048 {
        match a.step(&p, 0, &cut, &mut budget) {
            Err(e) => {
                let r = e.retirement.ok_or("retirement")?;
                assert!(r.candidate.is_some());
                assert!(matches!(
                    r.withheld.as_deref(),
                    Some(HevcRecordingReplayStep::FinishedPrefix { .. })
                ));
                assert_eq!(r.timings_applied, 1);
                assert!(a.cancel().is_none());
                failed = true;
                break;
            }
            Ok(AuthoringStep::Finished { .. }) => return Err("revoked recipe escaped".into()),
            _ => {}
        }
    }
    assert!(failed);
    Ok(())
}

#[path = "hevc_recipe_authoring_contract/additional.rs"]
mod additional;
