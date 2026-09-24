#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Shared real parser/custody/native-replay fixture, also usable across an executable boundary.
#[path = "../digest_media_support/mod.rs"]
pub mod source;
use fss_core::{ContentDigest, SensorId, StreamId};
use fss_object::SpoolLimits;
use fss_packet::H264Mode;
use fss_packet::avc::AvcReceiveLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel};
use fss_reference::rtsp::avc_client::{AvcClientPoll, authenticated::DigestAvcPoll};
use fss_reference::rtsp::datagram_archive::{
    DatagramArchive, DatagramArchiveLimits, DatagramScope,
};
use fss_reference::rtsp::datagram_reconstruction::recording::{
    DatagramRecordingReplay, RecordingReplaySpec, RecordingReplayStep,
};
use fss_reference::rtsp::datagram_reconstruction::{AvcReplayBounds, AvcReplaySpec};
use fss_reference::rtsp::recording::RecordingScope;
use fss_reference::rtsp::recording_capture::CapturePoll;
use fss_reference::rtsp::recording_collector::{CollectorLimits, RecordingTiming};
use fss_reference::rtsp::recording_recipe::storage::operation::*;
use fss_reference::rtsp::recording_recipe::storage::{
    PreparedRecordingRecipe, RecipeStorageLimits, RecordingRecipePin,
};
use fss_reference::rtsp::recording_recipe::{
    RecordingRecipe, RecordingRecipeLimits, RecordingTimingDecision,
};
use fss_reference::rtsp::tcp::{TcpBinding, TcpSecurityPolicy};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
pub struct Fixture {
    pub path: PathBuf,
    pub pin: RecordingRecipePin,
    pub expected: Vec<ContentDigest>,
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
pub fn work() -> WorkBudget<'static> {
    WorkBudget::new(1_000_000_000_000)
}
pub fn bounds() -> AvcReplayBounds {
    AvcReplayBounds {
        max_source_bytes: 1_048_576,
        max_steps: 4096,
        deadline_ns: u64::MAX,
    }
}
pub fn storage() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        256,
        1024,
        256,
        1024,
        SpoolLimits::new(2048, 32 * 1024 * 1024, 1_048_576, 2048),
    )
}
pub fn source_scope() -> Test<DatagramScope> {
    Ok(DatagramScope {
        binding: TcpBinding::new(
            source::KEY,
            "127.0.0.1:554".parse()?,
            "camera.local",
            TcpSecurityPolicy::OwnerApprovedPlaintext,
        )?,
        channels: (0, 1),
        receive_clock: ContentDigest::sha256(b"reconstruction operation receive clock"),
        retention_evidence: ContentDigest::sha256(b"operator accepted original retention"),
    })
}
pub fn limits() -> RecipeLoadLimits {
    RecipeLoadLimits {
        source: DatagramArchiveLimits {
            max_datagrams: 128,
            max_payload_bytes: 1_048_576,
            max_scan_roots: 1024,
            max_spool_object_bytes: 1_048_576,
        },
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
pub fn open(path: &Path) -> Test<LocalRootPublisher> {
    Ok(LocalRootPublisher::open(path, storage())?)
}
pub fn seed(name: &str, pictures: usize, bad_last: bool, fragment_only: bool) -> Test<Fixture> {
    let path = std::env::temp_dir().join(format!(
        "fss-reconstruction-{name}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut p = open(&path)?;
    let scope = source_scope()?;
    let mut archive = DatagramArchive::new(scope.clone(), limits().source)?;
    let nals = source::nals();
    let sps = *nals.iter().find(|n| n[0] & 31 == 7).ok_or("missing SPS")?;
    let pps = *nals.iter().find(|n| n[0] & 31 == 8).ok_or("missing PPS")?;
    let idr = *nals.iter().find(|n| n[0] & 31 == 5).ok_or("missing IDR")?;
    let mut observations = vec![(10, source::packet(1, 9000, sps))];
    if fragment_only {
        let mut payload = vec![(idr[0] & 0x60) | 28, (idr[0] & 31) | 128];
        payload.extend_from_slice(&idr[1..1 + (idr.len() - 1) / 2]);
        observations.push((11, source::packet(2, 9000, &payload)));
    } else {
        for i in 0..pictures {
            let mut packet = source::packet(2 + i as u16, 9000 + i as u32 * 3600, idr);
            packet[1] |= 128;
            observations.push((11 + i as u64, packet));
        }
    }
    let mut parser = source::playing()?;
    for (now, packet) in &observations {
        let mut events = Vec::new();
        source::send(
            &mut parser,
            &source::interleaved(0, packet),
            4096,
            *now,
            &mut events,
        )?;
        let mut seen = 0;
        for event in events {
            if let DigestAvcPoll::Client { event, .. } = event
                && let AvcClientPoll::Rtp { source, .. } = *event
            {
                let plan = archive.prepare(&source, &mut work())?;
                let _ = archive.publish(&plan, &mut p, &NeverCancel, &mut work())?;
                seen += 1;
            }
        }
        assert_eq!(seen, 1);
    }
    let avc = AvcReplaySpec {
        payload_type: 96,
        mode: H264Mode::NonInterleaved,
        sps,
        pps,
        limits: AvcReceiveLimits::default(),
        reduced_rtcp: false,
        configuration_evidence: ContentDigest::sha256(
            b"operator accepted native fixture parameters",
        ),
    };
    let recording = RecordingReplaySpec {
        scope: RecordingScope {
            sensor: SensorId::parse("reconstruction-sensor")?,
            stream: StreamId::parse("reconstruction-video")?,
            generation: source::KEY.generation,
            anchor: ContentDigest::sha256(b"operation history anchor"),
            receive_clock: scope.receive_clock,
        },
        time_scale: 90_000,
        limits: CollectorLimits::default(),
        timing_evidence: ContentDigest::sha256(b"operator independent media timing"),
    };
    let mut replay =
        DatagramRecordingReplay::new(&archive, avc, recording.clone(), bounds(), 1000)?;
    let mut decisions = Vec::new();
    let mut expected = Vec::new();
    let mut finished = false;
    for _ in 0..1024 {
        match replay.step(&p, 1000, &NeverCancel, &mut work())? {
            RecordingReplayStep::Capture(event) => match *event {
                CapturePoll::TimingRequired(picture) => {
                    let timing = RecordingTiming {
                        decode_time: 700 + decisions.len() as u64 * 3600,
                        duration: 3600,
                        composition_offset: -25,
                    };
                    decisions.push(RecordingTimingDecision {
                        observations_read: replay.observations_read(),
                        picture,
                        timing,
                    });
                    let _ = replay.supply_timing(timing, 1000, &NeverCancel, &mut work())?;
                }
                CapturePoll::Window(w) => expected.push(w.manifest().root()),
                CapturePoll::Receiver(_) => {}
                other => {
                    return Err(format!(
                        "unexpected fixture output: {:?}",
                        RecordingReplayStep::Capture(Box::new(other))
                    )
                    .into());
                }
            },
            RecordingReplayStep::PrefixReady { .. } => {
                replay.finish_prefix(1000, &NeverCancel, &mut work())?
            }
            RecordingReplayStep::FinishedPrefix { .. } => {
                finished = true;
                break;
            }
            RecordingReplayStep::Source(_) | RecordingReplayStep::MediaQueued => {}
            other => return Err(format!("unexpected fixture output: {other:?}").into()),
        }
    }
    assert!(finished);
    if bad_last {
        decisions
            .last_mut()
            .ok_or("no timing to mutate")?
            .picture
            .rtp_timestamp += 1;
    }
    let recipe = RecordingRecipe::new(&archive, avc, recording, decisions, limits().recipe)?;
    let prepared = PreparedRecordingRecipe::prepare(
        &recipe,
        &archive,
        &p,
        limits().storage,
        &NeverCancel,
        &mut work(),
    )?;
    let pin = prepared.publish(&mut p, &NeverCancel, &mut work())?.pin;
    // Every old source/configuration/recipe object dies here. Only exact pins and disk survive.
    Ok(Fixture {
        path,
        pin,
        expected,
    })
}
