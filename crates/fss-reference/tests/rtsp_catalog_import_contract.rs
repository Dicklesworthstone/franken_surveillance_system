#![forbid(unsafe_code)]
//! Complete native catalogs through retained custody, cold replay, long analysis and fault retry.
//! These synthetic packets qualify source closure and continuity, not camera or detector accuracy.

mod recording_support;
mod hevc_recording_support;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, CanonicalEncode, ContentDigest, OperationId, TimestampNs};
use fss_geometry::WorkBudget;
use fss_object::{ObjectManifest, SpoolLimits};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::ingest::long_watch::{LongWatchLimits, LongWatchReport};
use fss_reference::ingest::privacy_mask::{MASK_FILL_LUMA, PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_decode::h264::{DecoderLimits as AvcLimits, RecordedH264Range, RecordedH264Request};
use fss_reference::ingest::recorded_decode::h265::{DecoderLimits as HevcLimits, RecordedH265Range, RecordedH265Request};
use fss_reference::ingest::recorded_watch::{WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone};
use fss_reference::ingest::rtsp_import::{RtspCaptureOrigin, RtspImportCodec, RtspImportError};
use fss_reference::ingest::rtsp_import::catalog::{
    ADAPTER, MAX_FRAMES, MAX_MEDIA_BYTES, MAX_ORIGINAL_BYTES, MAX_WINDOWS,
    RtspCatalogImportAuthority, RtspCatalogImportReceipt, RtspCatalogImportRequest, import_rtsp_catalog,
};
use fss_reference::ingest::{FileIngestAdapter, RetainedFileImport, RetainedReadLimits, VerifiedChunkCache};
use fss_reference::rtsp::recording::{PreparedRecording, RecordingSummary};
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording_catalog::{CatalogScope, CatalogWindow, RecordingCatalog, prepare_catalog};
use fss_reference::rtsp::recording_catalog::local::{CatalogProgress, CatalogPublication};
use fss_reference::rtsp::recording_catalog::hevc::{HevcCatalogWindow, HevcRecordingCatalog, prepare_hevc_catalog};
use fss_reference::rtsp::recording_catalog::hevc::local::HevcCatalogPublication;
use fss_reference::{ReferenceDeployment, ReplayCx};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:rtsp-catalog-import";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let p = std::env::temp_dir().join(format!("fss-rtsp-catalog-{label}-{}-{attempt}", std::process::id()));
            match fs::create_dir(&p) {
                Ok(()) => return Ok(Self(p)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("temporary directory bound".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:rtsp-catalog-import".into(), operation_id: OperationId::parse("operation:rtsp-catalog-import")?,
        principal: "principal:rtsp-catalog-import".into(),
        capabilities: vec!["ADP-REPLAY-001".into(), "CAP-READ-MEDIA-001".into(), "CAP-OBJECT-STAGE-001".into(),
            "CAP-OBJECT-PUBLISH-001".into(), "CAP-RETENTION-COMMIT-001".into(), "CAP-DELETE-PREPARE-001".into()],
        deadline: None, priority: 10, budgets: BudgetVector::builder().bytes(1024 * 1024 * 1024).build()?,
        privacy_scope: "privacy:fixture".into(), retention_scope: "retention:fixture".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()), generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(&authority, root.to_path_buf())?)
}
fn archive_limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(16, 512, 16, 256, SpoolLimits::new(256, 128 * 1024 * 1024, 32 * 1024 * 1024, 256))
}
fn work() -> WorkBudget<'static> { WorkBudget::new(1024 * 1024 * 1024) }
struct Owner(Cell<bool>);
impl RtspCatalogImportAuthority for Owner {
    fn permit(&self, _: &RtspCatalogImportRequest, destination: &ReferenceDeployment) -> bool {
        self.0.get() && destination.site_lineage() == SITE
    }
}
fn slot(index: usize) -> Test<SlotName> { Ok(SlotName::parse(&format!("window-{index:06}"))?) }
fn scope(summary: &RecordingSummary) -> CatalogScope {
    CatalogScope { recording: summary.scope.clone(), decode_clock: ContentDigest::sha256(b"explicit-decode-epoch"), time_scale: 90_000 }
}
enum Page { Avc(RecordingCatalog), Hevc(HevcRecordingCatalog) }
impl Page {
    fn manifest(&self) -> &ObjectManifest { match self { Self::Avc(p) => p.manifest(), Self::Hevc(p) => p.manifest() } }
    fn index(&self) -> &[u8] { match self { Self::Avc(p) => p.index_bytes(), Self::Hevc(p) => p.index_bytes() } }
    fn scope(&self) -> &CatalogScope { match self { Self::Avc(p) => p.scope(), Self::Hevc(p) => p.scope() } }
    fn publish(&self, source: &mut LocalRootPublisher, slot: SlotName) -> Test {
        match self {
            Self::Avc(c) => {
                let mut p = CatalogPublication::new(c, source, slot, c.byte_len(), 100)?;
                for at in 0..c.entries().len() as u64 + 2 {
                    if matches!(p.step(at, &NeverCancel)?, CatalogProgress::Published(_)) { return Ok(()); }
                }
            }
            Self::Hevc(c) => {
                let mut p = HevcCatalogPublication::new(c, source, slot, c.byte_len(), 100)?;
                for at in 0..c.entries().len() as u64 + 2 {
                    if matches!(p.step(at, &NeverCancel)?, CatalogProgress::Published(_)) { return Ok(()); }
                }
            }
        }
        Err("catalog publication incomplete".into())
    }
}
struct Fixture {
    directory: Directory,
    source: Option<LocalRootPublisher>,
    target: Option<ReferenceDeployment>,
    cx: ReplayCx,
    request: RtspCatalogImportRequest,
    originals: BTreeMap<ContentDigest, Vec<u8>>,
    original_packs: Vec<ContentDigest>,
    original_bytes: u64,
    mp4: Vec<u8>,
}
impl Fixture {
    fn avc(label: &str, per_window: usize, gap: u64, different_config: bool) -> Test<Self> {
        let first = recording_support::repeated(301, per_window, 1, 0)?.prepare_at(0)?;
        let start = per_window as u64 * 3600 + gap;
        let second = if different_config {
            recording_support::repeated_from(302, per_window, 2000, start as u32, include_bytes!(
                "../../fss-packet/tests/fixtures/avc/high_cropped.264"
            ))?.prepare_at(start)?
        } else {
            recording_support::repeated(302, per_window, 2000, start as u32)?.prepare_at(start)?
        };
        let a = slot(0)?; let b = slot(1)?;
        let page = prepare_catalog(scope(first.summary()), &[
            CatalogWindow { slot: &a, recording: &first }, CatalogWindow { slot: &b, recording: &second },
        ])?;
        Self::from_plans(label, RtspImportCodec::Avc, &[&first, &second], Page::Avc(page))
    }
    fn hevc(label: &str) -> Test<Self> {
        let first = hevc_recording_support::fixture()?;
        let mut packets = hevc_recording_support::packets()?;
        for p in &mut packets {
            p.sequence += 32; p.received_ns += 32;
            p.bytes[2..4].copy_from_slice(&(p.sequence as u16).to_be_bytes());
            let timestamp = u32::from_be_bytes(p.bytes[4..8].try_into()?);
            p.bytes[4..8].copy_from_slice(&(timestamp + 72_000).to_be_bytes());
        }
        let mut timings = hevc_recording_support::timings(4);
        for t in &mut timings { t.decode_time += 72_000; }
        // B-frame-style presentation reordering stays native across the page boundary.
        timings[1].composition_offset = 18_000;
        timings[2].composition_offset = -18_000;
        let second = hevc_recording_support::prepare(&packets, &timings)?;
        let a = slot(0)?; let b = slot(1)?;
        let page = prepare_hevc_catalog(scope(first.summary()), &[
            HevcCatalogWindow { slot: &a, recording: &first }, HevcCatalogWindow { slot: &b, recording: &second },
        ])?;
        Self::from_plans(label, RtspImportCodec::Hevc, &[first.publication_plan(), second.publication_plan()], Page::Hevc(page))
    }
    fn from_plans(label: &str, codec: RtspImportCodec, plans: &[&PreparedRecording], page: Page) -> Test<Self> {
        let directory = Directory::new(label)?;
        let mut source = LocalRootPublisher::open(directory.0.join("archive"), archive_limits())?;
        let mut originals = BTreeMap::new();
        let mut original_packs = Vec::new();
        let mut original_bytes = (page.manifest().canonical_bytes().len() + page.index().len()) as u64;
        let mut mp4 = Vec::new();
        for (index, plan) in plans.iter().enumerate() {
            let mut job = RecordingPublication::new(plan, &mut source, slot(index)?, plan.byte_len(), 100)?;
            for at in 0..4 { assert!(matches!(job.step(at, &NeverCancel)?, RecordingProgress::ChildStaged { .. })); }
            assert!(matches!(job.step(4, &NeverCancel)?, RecordingProgress::Published(_)));
            drop(job);
            originals.insert(plan.manifest().root(), plan.manifest().canonical_bytes());
            originals.extend(plan.children().into_iter().map(|(_, d, b)| (d, b.to_vec())));
            original_packs.push(ContentDigest::sha256(plan.objects().source));
            original_bytes += plan.byte_len() as u64;
            if index == 0 { mp4.extend_from_slice(plan.objects().initialization); }
            mp4.extend_from_slice(plan.objects().media);
        }
        let catalog_slot = SlotName::parse("whole-catalog")?;
        page.publish(&mut source, catalog_slot.clone())?;
        originals.insert(page.manifest().root(), page.manifest().canonical_bytes());
        originals.insert(ContentDigest::sha256(page.index()), page.index().to_vec());
        let root = directory.0.join("destination");
        let cx = context(&root)?;
        let target = ReferenceDeployment::open(&root, SITE, &cx)?;
        let request = RtspCatalogImportRequest {
            codec, slot: catalog_slot, root: page.manifest().root(), scope: page.scope().clone(),
            receive_time: TimestampNs(1_000_000_000_000),
            capture_origin: Some(RtspCaptureOrigin { start_ns: TimestampNs(1_000_000_000), uncertainty_ns: 10 }),
            max_windows: MAX_WINDOWS, max_frames: MAX_FRAMES,
            max_original_bytes: MAX_ORIGINAL_BYTES, max_media_bytes: MAX_MEDIA_BYTES,
        };
        Ok(Self { directory, source: Some(source), target: Some(target), cx, request, originals, original_packs, original_bytes, mp4 })
    }
    fn target(&self) -> Test<&ReferenceDeployment> { self.target.as_ref().ok_or_else(|| "target closed".into()) }
    fn run(&mut self) -> Test<RtspCatalogImportReceipt> {
        Ok(import_rtsp_catalog(self.source.as_ref().ok_or("source")?, self.target.as_mut().ok_or("target")?,
            &self.request, &Owner(Cell::new(true)), &self.cx, &mut work())?)
    }
    fn retained(&self, receipt: &RtspCatalogImportReceipt) -> Test<RetainedFileImport> {
        Ok(RetainedFileImport::open(self.target()?, receipt.import.import_identity, RetainedReadLimits::default(), &self.cx)?)
    }
    fn snapshot(&self) -> Test<(usize, usize, usize)> {
        let d = self.target()?;
        Ok((d.ledger().batches().len(), d.publisher().visible_roots().count(), d.publisher().spool().digests().count()))
    }
}

#[test]
fn three_hundred_twenty_native_frames_remain_one_cold_decodable_watch_range() -> Test {
    let mut f = Fixture::avc("long", 160, 0, false)?;
    let result = f.run()?;
    assert_eq!(result.windows, 2);
    assert_eq!(result.import.frames, 320);
    assert_eq!(result.decode_interval, 0..320 * 3600);
    let retained = f.retained(&result)?;
    assert_eq!(retained.manifest().adapter_id, ADAPTER);
    assert_eq!(retained.manifest().input_sha256, ContentDigest::sha256(&f.mp4));
    assert!(retained.manifest().validate_retained(RetainedReadLimits::default()).is_err());
    assert!(FileIngestAdapter::fetch_segment_bytes(retained.manifest(), f.target()?, 0).is_err());
    for (d, b) in &f.originals { assert_eq!(f.target()?.publisher().spool().read(*d)?, *b); }
    let mut cache = VerifiedChunkCache::default();
    for index in [0, 159, 160, 255, 256, 319] {
        let span = &retained.manifest().segment_spans[index];
        let bytes = retained.read_segment_cached(f.target()?, index, RetainedReadLimits::default(), &f.cx, &mut cache)?;
        assert_eq!(bytes, f.mp4[span.offset as usize..(span.offset + span.len) as usize]);
    }
    drop(f.source.take());
    fs::rename(f.directory.0.join("archive"), f.directory.0.join("offline-archive"))?;
    drop(f.target.take());
    f.cx = context(&f.directory.0.join("destination"))?;
    f.target = Some(ReferenceDeployment::open(&f.directory.0.join("destination"), SITE, &f.cx)?);
    let mut decoder = RecordedH264Range::open_stream(f.target()?, RecordedH264Request {
        import_identity: result.import.import_identity, first_segment: 0, segment_count: 320,
        interpretation: ComponentInterpretation::YCbCr, read_limits: RetainedReadLimits::default(),
        decoder_limits: AvcLimits::default(),
    }, &f.cx)?;
    let mut decoded = 0;
    while let Some(frame) = decoder.next_frame(f.target()?, &f.cx)? {
        assert_eq!(frame.segment_index(), decoded);
        assert!(!frame.pixels().is_empty());
        assert_eq!(frame.capsule().capture.earliest.0, 1_000_000_000 + i128::from(decoded) * 40_000_000 - 10);
        decoded += 1;
    }
    assert_eq!(decoded, 320);
    let plan = WatchPlan {
        import_identity: result.import.import_identity, interpretation: ComponentInterpretation::YCbCr,
        first_segment: 0, segment_count: 320,
        zones: vec![WatchZone { zone_id: "scene".into(), x: 0, y: 0, width: 16, height: 16 }],
        detector: WatchDetectorConfig::default(), tracker: WatchTrackerConfig::default(),
    };
    let before = f.snapshot()?;
    let report = LongWatchReport::analyze(f.target()?, &plan, WatchOptions::default(), &LongWatchLimits::default(), &f.cx)?;
    assert_eq!(report.frames_decoded(), 320);
    assert!(report.to_json(0, None)?.contains("\"tracking_restarts\":0"));
    assert!(report.source_chunk_bytes_read() < 64 * 1024 * 1024, "native closure was repeatedly reread per sample");
    let limited = LongWatchLimits { maximum_source_chunk_bytes: report.source_chunk_bytes_read() - 1, ..LongWatchLimits::default() };
    assert!(LongWatchReport::analyze(f.target()?, &plan, WatchOptions::default(), &limited, &f.cx).is_err());
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn hevc_whole_catalog_preserves_presentation_order_privacy_and_original_deletion_closure() -> Test {
    let mut f = Fixture::hevc("hevc")?;
    let result = f.run()?;
    assert_eq!(result.import.frames, 8);
    assert_eq!(result.decode_interval, 0..144_000);
    let retained = f.retained(&result)?;
    let mut check = || Ok(());
    let mp4 = fss_container::demux::AvcMp4::parse_recovering_tail(&f.mp4, None, fss_container::demux::DemuxLimits::default(), &mut check)?;
    let times: Vec<_> = mp4.samples().iter().map(|s| s.presentation_time()).collect();
    assert!(times.windows(2).any(|w| w[1] < w[0]));
    let earliest = *times.iter().min().ok_or("presentation sample")?;
    for (index, time) in times.iter().enumerate() {
        let capsule = fss_reference::ingest::recorded_decode::retained_source_capsule(f.target()?, &retained, index)?;
        let offset = ((*time - earliest) * 1_000_000_000 + 45_000) / 90_000;
        assert_eq!(capsule.capture.earliest.0, 1_000_000_000 + offset - 10);
        assert_eq!(capsule.capture.latest.0, 1_000_000_000 + offset + 10);
    }
    let request = RecordedH265Request {
        import_identity: result.import.import_identity, first_segment: 0, segment_count: 8,
        interpretation: ComponentInterpretation::YCbCr, read_limits: RetainedReadLimits::default(), decoder_limits: HevcLimits::default(),
    };
    let mut decoder = RecordedH265Range::open(f.target()?, request.clone(), &f.cx)?;
    let dimensions = decoder.next_frame(f.target()?, &f.cx)?.ok_or("HEVC frame")?.dimensions();
    drop(decoder);
    let policy = PrivacyMaskPolicy::new(f.request.scope.recording.sensor.clone(), dimensions, &[[0, 0, dimensions[0], dimensions[1]]])?;
    let approval = preview_mask(f.target()?, &policy)?.approval;
    declare_mask(f.target.as_mut().ok_or("target")?, &policy, approval, &f.cx)?;
    let mut masked = RecordedH265Range::open(f.target()?, request, &f.cx)?;
    let mut count = 0;
    while let Some(frame) = masked.next_frame(f.target()?, &f.cx)? {
        assert!(frame.pixels().iter().all(|p| *p == MASK_FILL_LUMA));
        assert_eq!(frame.receipt().mask_policy(), Some(policy.digest()));
        count += 1;
    }
    assert_eq!(count, 8);
    let deletion = fss_reference::deletion::plan_deletion(f.target()?, result.import.import_identity, &f.cx)?;
    for d in f.originals.keys().copied().chain(std::iter::once(result.import.proof)) {
        assert!(deletion.deletable.iter().any(|entry| entry.digest == d));
    }
    assert!(f.run()?.import.reused);
    Ok(())
}

#[test]
fn exact_scope_and_all_cumulative_bounds_refuse_before_destination_mutation() -> Test {
    let mut f = Fixture::hevc("bounds")?;
    let original = f.request.clone();
    let before = f.snapshot()?;
    for case in 0..9 {
        f.request = original.clone();
        match case {
            0 => f.request.scope.decode_clock = ContentDigest::sha256(b"other clock"),
            1 => f.request.scope.time_scale += 1,
            2 => f.request.scope.recording.generation += 1,
            3 => f.request.max_windows = 1,
            4 => f.request.max_frames = 7,
            5 => f.request.max_original_bytes = f.original_bytes - 1,
            6 => f.request.max_media_bytes = f.mp4.len() as u64 - 1,
            7 => f.request.codec = RtspImportCodec::Avc,
            _ => f.request.root = ContentDigest::sha256(b"other catalog"),
        }
        assert!(f.run().is_err(), "case {case}");
        assert_eq!(f.snapshot()?, before, "case {case}");
    }
    f.request = original;
    let limited = import_rtsp_catalog(f.source.as_ref().ok_or("source")?, f.target.as_mut().ok_or("target")?,
        &f.request, &Owner(Cell::new(true)), &f.cx, &mut WorkBudget::new(2 * 32 * 1024 * 1024));
    assert!(limited.is_err(), "window reservations renewed the work budget");
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn valid_native_catalogs_with_a_gap_or_changed_initialization_do_not_fabricate_continuity() -> Test {
    for (label, gap, reconfigured) in [("gap", 3600, false), ("reconfigured", 0, true)] {
        let mut f = Fixture::avc(label, 1, gap, reconfigured)?;
        let before = f.snapshot()?;
        assert!(f.run().is_err());
        assert_eq!(f.snapshot()?, before);
    }
    Ok(())
}

#[test]
fn interrupted_publication_resumes_exactly_and_cold_retry_does_not_append_authority() -> Test {
    let mut f = Fixture::hevc("retry")?;
    let before = f.snapshot()?;
    let denied = import_rtsp_catalog(f.source.as_ref().ok_or("source")?, f.target.as_mut().ok_or("target")?,
        &f.request, &Owner(Cell::new(false)), &f.cx, &mut work());
    assert!(matches!(denied, Err(RtspImportError::Denied)));
    assert_eq!(f.snapshot()?, before);
    f.cx.set_cancel_at_checkpoint("file_parts:root");
    assert!(f.run().is_err());
    assert!(f.snapshot()?.0 > before.0);
    f.cx = context(&f.directory.0.join("destination"))?;
    let completed = f.run()?;
    let anchor = f.target()?.current_anchor().clone();
    let snapshot = f.snapshot()?;
    drop(f.target.take());
    drop(f.source.take());
    f.cx = context(&f.directory.0.join("destination"))?;
    f.target = Some(ReferenceDeployment::open(&f.directory.0.join("destination"), SITE, &f.cx)?);
    f.source = Some(LocalRootPublisher::open(f.directory.0.join("archive"), archive_limits())?);
    let retried = f.run()?;
    assert!(retried.import.reused);
    assert_eq!(retried.import.import_root, completed.import.import_root);
    assert_eq!(retried.import.proof, completed.import.proof);
    assert_eq!(f.target()?.current_anchor(), &anchor);
    assert_eq!(f.snapshot()?, snapshot);
    Ok(())
}

#[test]
fn retained_original_damage_never_repairs_from_the_still_available_archive() -> Test {
    let mut f = Fixture::hevc("tamper")?;
    let result = f.run()?;
    let retained = f.retained(&result)?;
    // Damage only the second original packet pack; reconstructed MP4 chunks remain intact.
    let original = f.original_packs[1];
    let path = f.target()?.publisher().spool().object_path(original);
    fs::write(&path, b"corrupt second original packet pack")?;
    let before = f.snapshot()?;
    assert!(retained.read_segment(f.target()?, 0, RetainedReadLimits::default(), &f.cx).is_err());
    assert!(retained.verify_source(f.target()?, RetainedReadLimits::default(), &f.cx).is_err());
    assert!(f.run().is_err());
    assert_eq!(f.snapshot()?, before);
    assert_eq!(fs::read(path)?, b"corrupt second original packet pack");
    Ok(())
}
