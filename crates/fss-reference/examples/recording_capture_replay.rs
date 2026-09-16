#![forbid(unsafe_code)]
//! Bounded real-bitstream capture -> window archive -> immutable catalog -> verified range.
//! Run: cargo run --locked -p fss-reference --example recording_capture_replay -- NEW_DIRECTORY
//! Laboratory timing comes from the retained four-frame, 25 fps Baseline fixture, not RTP inference.

#[path = "../tests/collector_support/mod.rs"]
mod fixture;

use fss_core::ContentDigest;
use fss_object::SpoolLimits;
use fss_packet::avc::{AvcReceivePoll, AvcReceiver};
use fss_publication::{LocalPublicationLimits, LocalPublicationState, LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication, load_recording};
use fss_reference::rtsp::recording_capture::{CapturePoll, RecordingCapture, TimedCapture};
use fss_reference::rtsp::recording_collector::CollectorLimits;
use fss_reference::rtsp::recording_catalog::{CatalogBuilder, CatalogScope, CatalogQueryLimits};
use fss_reference::rtsp::recording_catalog::local::{CatalogPublication, CatalogProgress,
    RecordingRangeRead, RangeProgress, load_catalog};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_WINDOWS: usize = 8;

struct ExpectedWindow {
    slot: SlotName,
    root: ContentDigest,
    source: ContentDigest,
    media: ContentDigest,
    samples: usize,
}
struct Archive {
    publisher: LocalRootPublisher,
    expected: Vec<ExpectedWindow>,
    catalog: CatalogBuilder,
    samples: u64,
    packets: usize,
}
impl Archive {
    fn publish(&mut self, window: PreparedRecording, now: u64) -> Result<()> {
        if self.expected.len() == MAX_WINDOWS { return Err("fixture window bound".into()); }
        self.expected.try_reserve(1)?;
        let slot = SlotName::parse(&format!("capture-window-{:04}", self.expected.len() + 1))?;
        let expected = ExpectedWindow { slot: slot.clone(), root: window.manifest().root(),
            source: ContentDigest::try_sha256(window.objects().source)?,
            media: ContentDigest::try_sha256(window.objects().media)?, samples: window.summary().samples };
        let mut publication = RecordingPublication::new(&window, &mut self.publisher,
            slot, window.byte_len(), now.checked_add(100).ok_or("fixture deadline overflow")?)?;
        for step in 0..5 {
            match publication.step(now + step, &NeverCancel)? {
                RecordingProgress::ChildStaged { role, digest, bytes, .. } if step < 4 => println!(
                    "{{\"kind\":\"child_staged\",\"role\":\"{role:?}\",\"digest\":\"{}\",\"bytes\":{bytes}}}", digest.to_text()),
                RecordingProgress::Published(receipt) if step == 4 && receipt.claims.local == LocalPublicationState::Durable => println!(
                    "{{\"kind\":\"window_published\",\"root\":\"{}\",\"samples\":{},\"local\":\"Durable\"}}",
                    receipt.root.to_text(), expected.samples),
                other => return Err(format!("unexpected publication step: {other:?}").into()),
            }
        }
        self.catalog.push(&expected.slot, &window)?;
        self.expected.push(expected);
        Ok(())
    }
    fn capture_step(&mut self, capture: &mut RecordingCapture, now: u64) -> Result<bool> {
        for _ in 0..64 {
            match capture.poll(now)? {
                CapturePoll::Receiver(AvcReceivePoll::Source { source, .. }) => {
                    self.packets += 1;
                    println!("{{\"kind\":\"source\",\"sequence\":{},\"digest\":\"{}\"}}",
                        source.sequence(), ContentDigest::try_sha256(source.bytes())?.to_text());
                    return Ok(false);
                }
                CapturePoll::Receiver(_) | CapturePoll::Pending { .. } => return Ok(false),
                CapturePoll::TimingRequired(request) => {
                    if self.samples >= 4 { return Err("unexpected extra fixture picture".into()); }
                    match capture.supply_timing(fixture::timing(self.samples * 3600), now)? {
                        TimedCapture::Collected { unselected, .. } if unselected.is_empty() => {}
                        other => return Err(format!("unexpected fixture selection: {other:?}").into()),
                    }
                    self.samples += 1;
                    println!("{{\"kind\":\"picture_timed\",\"basis\":\"synthetic_fixture_25fps\",\"frame_num\":{},\"boundary\":\"{:?}\",\"complete_picture_certified\":false}}",
                        request.frame_num, request.boundary);
                }
                CapturePoll::Window(window) => self.publish(window, now)?,
                CapturePoll::InputEnded => {}
                CapturePoll::Tail(out) if out.picture.is_none() && out.retired.is_none() => {}
                CapturePoll::Ended { trailing } => {
                    if trailing.is_some_and(|t| !t.sources.is_empty() || !t.pictures.is_empty()) {
                        return Err("clean fixture left unselected originals".into());
                    }
                    return Ok(true);
                }
                // This laboratory rehearsal stops on non-clean input rather than declaring
                // a clean archive. A real owner must retain/receipt returned media before stopping.
                other => return Err(format!("fixture stopped instead of claiming clean capture: {other:?}").into()),
            }
        }
        Err("fixture capture-step bound".into())
    }
    fn drain(&mut self, receiver: &mut AvcReceiver, capture: &mut RecordingCapture, now: u64) -> Result<bool> {
        for _ in 0..1024 {
            let event = receiver.poll(now)?;
            let pending = matches!(&event, AvcReceivePoll::Pending { .. });
            capture.offer(event, now)?;
            if self.capture_step(capture, now)? { return Ok(true); }
            if pending { return Ok(false); }
        }
        Err("fixture receiver-step bound".into())
    }
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let root = std::path::PathBuf::from(args.next().ok_or("supply an explicit new laboratory archive directory")?);
    if args.next().is_some() || root.exists() { return Err("exactly one new directory is required; existing data is never replaced".into()); }
    let limits = LocalPublicationLimits::new(8, 16, 8, 64,
        SpoolLimits::new(64, 4 * 1024 * 1024, 1024 * 1024, 64));
    let catalog_scope = CatalogScope { recording: fixture::scope()?,
        decode_clock: ContentDigest::try_sha256(b"fixture-dts-epoch")?, time_scale: 90_000 };
    let mut archive = Archive { publisher: LocalRootPublisher::open(&root, limits)?,
        expected: Vec::new(), catalog: CatalogBuilder::new(catalog_scope.clone())?, samples: 0, packets: 0 };
    let mut receiver = fixture::receiver()?;
    let mut capture = RecordingCapture::new(fixture::collector(CollectorLimits::default())?);
    let nals = fixture::nals();
    receiver.ingest(fixture::key(), &fixture::packet(0, 90_000, false, nals[0]), 0)?;
    let mut frame = 0;
    for (index, nal) in nals.iter().enumerate() {
        let sequence = index as u64 + 1;
        let vcl = matches!(nal[0] & 31, 1 | 5);
        let wire = fixture::packet(sequence, 90_000 + frame * 3600, vcl, nal);
        receiver.ingest(fixture::key(), &wire, sequence)?;
        if archive.drain(&mut receiver, &mut capture, sequence)? { return Err("premature fixture EOF".into()); }
        if vcl { frame += 1; }
    }
    receiver.finish();
    if !archive.drain(&mut receiver, &mut capture, 1000)? || archive.samples != 4
        || archive.expected.len() != 2 || archive.packets != nals.len()
    { return Err("capture did not produce two complete fixture windows and quiescence".into()); }
    let Archive { mut publisher, expected, catalog, .. } = archive;
    let catalog = catalog.prepare()?;
    let catalog_slot = SlotName::parse("catalog-page-1")?;
    {
        let mut job = CatalogPublication::new(&catalog, &mut publisher, catalog_slot.clone(), catalog.byte_len(), 2000)?;
        for i in 0..catalog.entries().len() {
            if !matches!(job.step(1000 + i as u64, &NeverCancel)?, CatalogProgress::WindowVerified { .. }) {
                return Err("catalog child verification did not complete".into());
            }
        }
        if !matches!(job.step(1100, &NeverCancel)?, CatalogProgress::IndexStaged { .. }) {
            return Err("catalog index staging did not complete".into());
        }
        if !matches!(job.step(1101, &NeverCancel)?, CatalogProgress::Published(_)) {
            return Err("catalog root publication did not complete".into());
        }
    }
    drop(publisher);
    let reopened = LocalRootPublisher::open(&root, limits)?;
    for expected in expected {
        let loaded = load_recording(&reopened, &expected.slot, expected.root, &fixture::scope()?, &NeverCancel)?;
        if ContentDigest::try_sha256(loaded.objects().source)? != expected.source
            || ContentDigest::try_sha256(loaded.objects().media)? != expected.media
            || loaded.summary().samples != expected.samples
        { return Err("archive reopen differs from captured source/media".into()); }
        println!("{{\"kind\":\"verified_readback\",\"root\":\"{}\",\"samples\":{},\"packets\":{}}}",
            expected.root.to_text(), loaded.summary().samples, loaded.summary().packets);
    }
    let catalog = load_catalog(&reopened, &catalog_slot, catalog.manifest().root(), &catalog_scope, &NeverCancel)?;
    let mut read = RecordingRangeRead::new(&reopened, &catalog, &catalog_slot, 0..14400, CatalogQueryLimits::default(), 2000)?;
    for i in 0..2 {
        if !matches!(read.step(1200 + i, &NeverCancel)?, RangeProgress::Window { .. }) {
            return Err("catalog did not retrieve both complete windows".into());
        }
    }
    match read.step(1202, &NeverCancel)? {
        RangeProgress::Complete(receipt) if receipt.windows == 2 && receipt.unindexed.is_empty() => println!(
            "{{\"kind\":\"catalog_range_verified\",\"root\":\"{}\",\"windows\":2,\"unindexed_intervals\":0,\"camera_coverage_certified\":false}}", receipt.catalog_root),
        other => return Err(format!("unexpected range result: {other:?}").into()),
    }
    println!("{{\"kind\":\"terminal\",\"windows\":2,\"samples\":4,\"pending_bytes\":0,\"live_camera\":false,\"qualification\":\"reference_rehearsal_only\"}}");
    Ok(())
}
