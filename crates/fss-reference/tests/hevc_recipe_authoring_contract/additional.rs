#![forbid(unsafe_code)]
//! Cold replay and independent work cancellation across the authoring completion boundary.
use super::*;

#[test]
fn independent_work_revocation_after_encoding_withholds_the_recipe() -> Test {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct WorkCut<'a> {
        calls: Cell<usize>,
        at: usize,
        cancelled: &'a AtomicBool,
    }
    impl PublishCancellation for WorkCut<'_> {
        fn cancel_requested(&self, _: PublishCutPoint) -> bool {
            let n = self.calls.get() + 1;
            self.calls.set(n);
            if n >= self.at {
                self.cancelled.store(true, Ordering::SeqCst);
            }
            false // The independent work owner, not this read authority, was revoked.
        }
    }
    let path = fresh("author_work_post_cancel")?;
    let pin = save(&path, &input(false, false)?)?;
    let (p, archive) = reopen(&path, pin)?;
    let count = Cut {
        calls: Cell::new(0),
        at: usize::MAX,
    };
    let mut a = author(&archive, vec![row(0)])?;
    let mut done = false;
    let mut budget = work();
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
    let cancelled = AtomicBool::new(false);
    let cut = WorkCut {
        calls: Cell::new(0),
        at: count.calls.get(),
        cancelled: &cancelled,
    };
    let mut a = author(&archive, vec![row(0)])?;
    let mut budget = fss_geometry::WorkBudget::cancellable(1_000_000_000_000, &cancelled);
    for _ in 0..2048 {
        match a.step(&p, 0, &cut, &mut budget) {
            Err(error) => {
                let r = error.retirement.ok_or("retirement")?;
                assert!(r.candidate.is_some());
                assert!(matches!(
                    r.withheld.as_deref(),
                    Some(HevcRecordingReplayStep::FinishedPrefix { .. })
                ));
                assert!(a.cancel().is_none());
                return Ok(());
            }
            Ok(AuthoringStep::Finished { .. }) => return Err("work-revoked recipe escaped".into()),
            _ => {}
        }
    }
    Err("work-cut bound".into())
}

#[test]
fn authored_cold_recipe_produces_independently_published_pixel_decodable_recording() -> Test {
    use fss_codec_h265::{Decoder, DecoderLimits};
    use fss_container::demux::{AvcMp4, DemuxLimits, VideoCodec};
    use fss_publication::SlotName;
    use fss_reference::rtsp::recording::hevc::local::load_hevc_recording;
    use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
    fn pixels(window: &PreparedHevcRecording) -> Test<Vec<ContentDigest>> {
        let mut bytes = window.objects().initialization.to_vec();
        bytes.extend_from_slice(window.objects().media);
        let parsed = AvcMp4::parse(&bytes, None, DemuxLimits::default())?;
        assert_eq!(parsed.codec(), VideoCodec::Hevc);
        let annex = parsed.annex_b(0, parsed.samples().len())?;
        let mut decoder = Decoder::new(DecoderLimits::default())?;
        let mut pictures = decoder.decode_annex_b(annex.bytes())?;
        pictures.extend(decoder.finish()?);
        assert_eq!(pictures.len(), window.samples().len());
        Ok(pictures
            .iter()
            .map(|p| ContentDigest::sha256(p.luma()))
            .collect())
    }
    let path = fresh("author_independent_source")?;
    let output = fresh("author_independent_output")?;
    let offline = fresh("author_independent_offline")?;
    let pin = save(&path, &input(true, false)?)?;
    let recipe_pin = {
        let (mut p, archive) = reopen(&path, pin)?;
        let (recipe, _, _) = finish(&p, &mut author(&archive, vec![row(0)])?)?;
        let plan = PreparedRecordingRecipe::prepare(
            &recipe,
            &archive,
            &p,
            RecipeStorageLimits::default(),
            &NeverCancel,
            &mut work(),
        )?;
        plan.publish(&mut p, &NeverCancel, &mut work())?.pin
    };
    let (root, expected_pixels) = {
        let (p, archive) = reopen(&path, pin)?;
        let recipe = load_recording_recipe(
            &p,
            &recipe_pin,
            &archive,
            RecordingRecipeLimits::default(),
            RecipeStorageLimits::default(),
            &NeverCancel,
            &mut work(),
        )?;
        let mut windows = replay(&p, &archive, &recipe)?;
        let window = windows.pop().ok_or("cold window")?;
        assert!(windows.is_empty());
        let expected = pixels(&window)?;
        assert!(!expected.is_empty());
        let mut destination = LocalRootPublisher::open(&output, storage())?;
        let mut job = RecordingPublication::new(
            window.publication_plan(),
            &mut destination,
            SlotName::parse("authored-independent-hevc")?,
            window.byte_len(),
            u64::MAX,
        )?;
        let mut published = false;
        for _ in 0..8 {
            if matches!(job.step(0, &NeverCancel)?, RecordingProgress::Published(_)) {
                published = true;
                break;
            }
        }
        assert!(published);
        (window.manifest().root(), expected)
    };
    std::fs::rename(&path, &offline)?;
    let destination = LocalRootPublisher::open(&output, storage())?;
    let window = load_hevc_recording(
        &destination,
        &SlotName::parse("authored-independent-hevc")?,
        root,
        &media::scope()?,
        &NeverCancel,
    )?;
    assert_eq!(pixels(&window)?, expected_pixels);
    Ok(())
}
