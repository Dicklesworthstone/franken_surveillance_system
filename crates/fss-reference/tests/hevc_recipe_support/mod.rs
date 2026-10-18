#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Shared native source/recipe fixture for library and independent CLI process tests.
#[path = "../hevc_datagram_support/mod.rs"]
pub mod source;
use fss_core::ContentDigest;
use fss_packet::hevc::HevcAssemblyLimits;
use fss_publication::{LocalRootPublisher, NeverCancel};
use fss_reference::rtsp::datagram_archive::DatagramScope;
use fss_reference::rtsp::datagram_reconstruction::hevc::recording::*;
use fss_reference::rtsp::hevc_recording_capture::HevcCapturePoll;
use fss_reference::rtsp::recording::hevc::{HevcRecordingTiming, PreparedHevcRecording};
use fss_reference::rtsp::recording_collector::CollectorLimits;
use fss_reference::rtsp::recording_recipe::hevc::storage::operation::*;
use fss_reference::rtsp::recording_recipe::hevc::storage::*;
use fss_reference::rtsp::recording_recipe::hevc::*;
pub use source::{Test, bounds, work};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
pub struct Fixture {
    pub path: PathBuf,
    pub pin: RecordingRecipePin,
    pub expected: Vec<ContentDigest>,
    pub payload: ContentDigest,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
pub struct Clock(pub u64);
impl ReconstructionClock for Clock {
    fn now_ns(&self) -> Option<u64> {
        Some(self.0)
    }
}
pub fn source_scope() -> Test<DatagramScope> {
    source::scope()
}
pub fn open(path: &Path) -> Test<LocalRootPublisher> {
    Ok(LocalRootPublisher::open(path, source::storage())?)
}
pub fn limits() -> RecipeLoadLimits {
    RecipeLoadLimits {
        source: source::limits(),
        recipe: RecordingRecipeLimits::default(),
        storage: RecipeStorageLimits::default(),
    }
}
pub fn select(f: &Fixture) -> Test<RecipeSelection> {
    Ok(RecipeSelection {
        recipe: f.pin.recipe,
        root: f.pin.root,
        scope: source_scope()?,
    })
}
pub fn load(f: &Fixture, p: &LocalRootPublisher) -> Test<LoadedRecordingRecipe> {
    Ok(LoadedRecordingRecipe::load(
        p,
        select(f)?,
        limits(),
        &NeverCancel,
        &mut work(),
    )?)
}
fn spec() -> Test<HevcRecordingReplaySpec> {
    Ok(HevcRecordingReplaySpec {
        scope: source::media::scope()?,
        configuration: source::media::configuration()?,
        time_scale: 90_000,
        limits: CollectorLimits::default(),
        assembly: HevcAssemblyLimits::default(),
        timing_evidence: ContentDigest::sha256(b"original explicit recipe clock evidence"),
    })
}
pub fn seed(name: &str, pictures: usize, bad_last: bool, fragment_only: bool) -> Test<Fixture> {
    let mut input = source::observations(true)?;
    if fragment_only {
        input.pop();
    } else {
        let n = source::media::nals()?;
        let idr = n
            .iter()
            .find(|n| matches!((n[0] >> 1) & 63, 19 | 20))
            .ok_or("IDR")?;
        for i in 0..pictures {
            let seq = input.len() as u64 + 1;
            input.push((
                0,
                seq + 9,
                source::raw(seq, 27_000 + 18_000 * i as u32, true, idr),
            ));
        }
    }
    seed_input(name, &input, bad_last)
}
pub fn seed_eob(name: &str) -> Test<Fixture> {
    let mut input = source::observations(false)?;
    // Real EOB closes this IDR. A later original RTCP observation is deliberately not consumed.
    input.push((0, 12, source::raw(3, 9000, true, &[0x4a, 1, 0x80])));
    input.push((1, 13, vec![0, 0, 0]));
    seed_input(name, &input, false)
}
pub fn seed_input(name: &str, input: &[source::Observation], bad_last: bool) -> Test<Fixture> {
    let path = std::env::temp_dir().join(format!(
        "fss-hevc-recipe-{name}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let pin = source::save(&path, input)?;
    let (mut p, a) = source::reopen(&path, pin)?;
    let payload = a
        .records()
        .first()
        .map_or(ContentDigest::sha256(b"empty"), |r| r.payload_digest);
    let mut native = DatagramHevcRecordingReplay::new(&a, source::spec(), spec()?, bounds(), 0)?;
    let mut choices = Vec::new();
    let mut expected = Vec::new();
    let mut budget = work();
    let mut done = false;
    for _ in 0..4096 {
        match native.step(&p, 0, &NeverCancel, &mut budget)? {
            HevcRecordingReplayStep::Capture(e) => match *e {
                HevcCapturePoll::TimingRequired(picture) => {
                    let timing = HevcRecordingTiming {
                        decode_time: choices.len() as u64 * 18_000,
                        duration: 18_000,
                        composition_offset: 0,
                    };
                    choices.push(RecordingTimingDecision {
                        observations_read: native.observations_read(),
                        picture,
                        timing,
                    });
                    let _ = native.supply_timing(timing, 0, &NeverCancel, &mut budget)?;
                }
                HevcCapturePoll::Window(w) => expected.push(w.manifest().root()),
                HevcCapturePoll::Receiver(_) => {}
                other => return Err(format!("fixture capture refused {other:?}").into()),
            },
            HevcRecordingReplayStep::PrefixReady { .. } => {
                let _ = native.finish_prefix(0, &NeverCancel, &mut budget)?;
            }
            HevcRecordingReplayStep::FinishedPrefix { .. } => {
                done = true;
                break;
            }
            HevcRecordingReplayStep::Source(_) | HevcRecordingReplayStep::MediaQueued => {}
            other => return Err(format!("fixture native replay refused {other:?}").into()),
        }
    }
    assert!(done);
    if bad_last {
        choices
            .last_mut()
            .ok_or("no decision")?
            .picture
            .rtp_timestamp += 1;
    }
    let recipe = RecordingRecipe::new(
        &a,
        source::spec(),
        spec()?,
        choices,
        RecordingRecipeLimits::default(),
    )?;
    let prepared = PreparedRecordingRecipe::prepare(
        &recipe,
        &a,
        &p,
        RecipeStorageLimits::default(),
        &NeverCancel,
        &mut budget,
    )?;
    let stored = prepared.publish(&mut p, &NeverCancel, &mut budget)?.pin;
    Ok(Fixture {
        path,
        pin: stored,
        expected,
        payload,
    })
}

pub fn decode_pixels(window: &PreparedHevcRecording) -> Test<Vec<ContentDigest>> {
    use fss_codec_h265::{Decoder, DecoderLimits};
    use fss_container::demux::{AvcMp4, DemuxLimits, VideoCodec};
    let mut bytes = window.objects().initialization.to_vec();
    bytes.extend_from_slice(window.objects().media);
    let parsed = AvcMp4::parse(&bytes, None, DemuxLimits::default())?;
    assert_eq!(parsed.codec(), VideoCodec::Hevc);
    let elementary = parsed.annex_b(0, parsed.samples().len())?;
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let mut pictures = decoder.decode_annex_b(elementary.bytes())?;
    pictures.extend(decoder.finish()?);
    assert_eq!(pictures.len(), window.samples().len());
    let mut digests = Vec::new();
    for picture in pictures {
        assert!(picture.width() > 0 && picture.height() > 0);
        assert_eq!(
            picture.luma().len(),
            picture.width() as usize * picture.height() as usize
        );
        // Main8 fixture samples are native u8 surfaces; no derived preview is used.
        digests.push(ContentDigest::sha256(picture.luma()));
    }
    Ok(digests)
}
