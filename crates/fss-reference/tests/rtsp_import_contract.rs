#![forbid(unsafe_code)]
//! Actual source-closed AVC/HEVC recording import, native decode, privacy and restart contracts.

mod recording_support;
mod hevc_recording_support;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, CanonicalEncode, CaptureInterval, ContentDigest, OperationId, TimestampNs,
};
use fss_geometry::WorkBudget;
use fss_object::SpoolLimits;
use fss_publication::{
    LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName,
};
use fss_reference::ingest::privacy_mask::{
    MASK_FILL_LUMA, PrivacyMaskPolicy, declare_mask, preview_mask,
};
use fss_reference::ingest::recorded_decode::h264::{
    DecoderLimits as AvcLimits, RecordedH264Range, RecordedH264Request,
};
use fss_reference::ingest::recorded_decode::h265::{
    DecoderLimits as HevcLimits, RecordedH265Range, RecordedH265Request,
};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::rtsp_import::{
    ADAPTER, MAX_ORIGINAL_BYTES, RtspCaptureOrigin, RtspImportAuthority, RtspImportCodec,
    RtspImportError, RtspImportReceipt, RtspImportRequest, import_rtsp,
};
use fss_reference::ingest::{
    FileIngestAdapter, RetainedFileImport, RetainedReadLimits, VerifiedChunkCache,
};
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::{ReferenceDeployment, ReplayCx};
use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-rtsp-import-{label}-{}-{attempt}", std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("directory allocation bound".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:rtsp-import".into(),
        operation_id: OperationId::parse("operation:rtsp-import")?,
        principal: "principal:rtsp-import".into(),
        capabilities: vec![
            "ADP-REPLAY-001".into(), "CAP-READ-MEDIA-001".into(),
            "CAP-OBJECT-STAGE-001".into(), "CAP-OBJECT-PUBLISH-001".into(),
            "CAP-RETENTION-COMMIT-001".into(), "CAP-DELETE-PREPARE-001".into(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(512 * 1024 * 1024).build()?,
        privacy_scope: "privacy:fixture".into(),
        retention_scope: "retention:fixture".into(),
        anchor_universe: ContentDigest::sha256(b"site:rtsp-import"),
        generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(&authority, root.to_path_buf())?)
}
fn archive_limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(16, 64, 16, 256,
        SpoolLimits::new(256, 128 * 1024 * 1024, 32 * 1024 * 1024, 256))
}
fn work() -> WorkBudget<'static> { WorkBudget::new(512 * 1024 * 1024) }
struct Owner(Cell<bool>);
impl RtspImportAuthority for Owner {
    fn permit(&self, _: &RtspImportRequest, destination: &ReferenceDeployment) -> bool {
        self.0.get() && destination.site_lineage() == "site:rtsp-import"
    }
}
struct Fixture {
    source_dir: Directory,
    target_dir: Directory,
    source: Option<LocalRootPublisher>,
    target: Option<ReferenceDeployment>,
    cx: ReplayCx,
    request: RtspImportRequest,
    original: Vec<(ContentDigest, Vec<u8>)>,
    mp4: Vec<u8>,
}
impl Fixture {
    fn new(label: &str, codec: RtspImportCodec) -> Test<Self> {
        match codec {
            RtspImportCodec::Avc => {
                let plan = recording_support::fixture(101, true)?.prepare()?;
                Self::from_plan(label, codec, &plan)
            }
            RtspImportCodec::Hevc => {
                let plan = hevc_recording_support::fixture()?;
                Self::from_plan(label, codec, plan.publication_plan())
            }
        }
    }
    fn from_plan(label: &str, codec: RtspImportCodec, plan: &PreparedRecording) -> Test<Self> {
        let source_dir = Directory::new(&format!("{label}-source"))?;
        let target_dir = Directory::new(&format!("{label}-target"))?;
        let mut source = LocalRootPublisher::open(&source_dir.0, archive_limits())?;
        let slot = SlotName::parse("window-000001")?;
        let mut job = RecordingPublication::new(plan, &mut source, slot.clone(), plan.byte_len(), 100)?;
        let mut published = false;
        for at in 0..5 {
            if let RecordingProgress::Published(receipt) = job.step(at, &NeverCancel)? {
                assert_eq!(receipt.root, plan.manifest().root());
                published = true;
            }
        }
        assert!(published);
        drop(job);
        let objects = plan.objects();
        let mut original = vec![(plan.manifest().root(), plan.manifest().canonical_bytes())];
        original.extend(plan.children().into_iter().map(|(_, digest, bytes)| (digest, bytes.to_vec())));
        let mp4 = [objects.initialization, objects.media].concat();
        let cx = context(&target_dir.0)?;
        let target = ReferenceDeployment::open(&target_dir.0, "site:rtsp-import", &cx)?;
        let request = RtspImportRequest {
            codec, slot,
            root: plan.manifest().root(),
            source: plan.summary().scope.clone(),
            receive_time: TimestampNs(10_000_000_000),
            capture_origin: None,
            max_frames: 256,
            max_original_bytes: 32 * 1024 * 1024,
            max_media_bytes: 32 * 1024 * 1024,
        };
        Ok(Self { source_dir, target_dir, source: Some(source), target: Some(target), cx, request, original, mp4 })
    }
    fn target(&self) -> Test<&ReferenceDeployment> { self.target.as_ref().ok_or_else(|| "target closed".into()) }
    fn run(&mut self) -> Test<RtspImportReceipt> {
        Ok(import_rtsp(
            self.source.as_ref().ok_or("source closed")?,
            self.target.as_mut().ok_or("target closed")?,
            &self.request, &Owner(Cell::new(true)), &self.cx, &mut work(),
        )?)
    }
    fn retained(&self, imported: &RtspImportReceipt) -> Test<RetainedFileImport> {
        Ok(RetainedFileImport::open(
            self.target()?, imported.import_identity, RetainedReadLimits::default(), &self.cx,
        )?)
    }
}
#[derive(Debug)]
struct Decoded {
    pixels: Vec<u8>,
    dimensions: [u32; 2],
    capture: CaptureInterval,
    mask: Option<ContentDigest>,
}
fn decode(f: &Fixture, imported: &RtspImportReceipt) -> Test<Vec<Decoded>> {
    let mut frames = Vec::new();
    match imported.codec {
        RtspImportCodec::Avc => {
            let mut decoder = RecordedH264Range::open(f.target()?, RecordedH264Request {
                import_identity: imported.import_identity, first_segment: 0, segment_count: imported.frames,
                interpretation: ComponentInterpretation::YCbCr, read_limits: RetainedReadLimits::default(),
                decoder_limits: AvcLimits::default(),
            }, &f.cx)?;
            while let Some(frame) = decoder.next_frame(f.target()?, &f.cx)? {
                frames.push(Decoded {
                    pixels: frame.pixels().to_vec(), dimensions: frame.receipt().dimensions(),
                    capture: frame.receipt().capsule().capture, mask: frame.receipt().mask_policy(),
                });
            }
        }
        RtspImportCodec::Hevc => {
            let mut decoder = RecordedH265Range::open(f.target()?, RecordedH265Request {
                import_identity: imported.import_identity, first_segment: 0, segment_count: imported.frames,
                interpretation: ComponentInterpretation::YCbCr, read_limits: RetainedReadLimits::default(),
                decoder_limits: HevcLimits::default(),
            }, &f.cx)?;
            while let Some(frame) = decoder.next_frame(f.target()?, &f.cx)? {
                frames.push(Decoded {
                    pixels: frame.pixels().to_vec(), dimensions: frame.receipt().dimensions(),
                    capture: frame.receipt().capsule().capture, mask: frame.receipt().mask_policy(),
                });
            }
        }
    }
    Ok(frames)
}

#[test]
fn avc_and_hevc_import_retain_originals_and_decode_after_archive_goes_offline() -> Test {
    for codec in [RtspImportCodec::Avc, RtspImportCodec::Hevc] {
        let mut f = Fixture::new(codec.as_str(), codec)?;
        let imported = f.run()?;
        let retained = f.retained(&imported)?;
        let manifest = retained.manifest();
        assert_eq!(manifest.adapter_id, ADAPTER);
        assert_eq!(manifest.input_sha256, ContentDigest::sha256(&f.mp4));
        assert_eq!(imported.capture_time_label, "unknown");
        assert!(manifest.validate_retained(RetainedReadLimits::default()).is_err());
        assert!(FileIngestAdapter::fetch_segment_bytes(manifest, f.target()?, 0).is_err());
        for (digest, bytes) in &f.original {
            assert_eq!(f.target()?.publisher().spool().read(*digest)?, *bytes);
        }
        let mut cache = VerifiedChunkCache::default();
        for span in &manifest.segment_spans {
            let actual = retained.read_segment_cached(
                f.target()?, span.segment_index, RetainedReadLimits::default(), &f.cx, &mut cache,
            )?;
            assert_eq!(&actual, &f.mp4[span.offset as usize..(span.offset + span.len) as usize]);
        }
        f.source.take();
        fs::remove_dir_all(&f.source_dir.0)?;
        assert_eq!(retained.verify_source(f.target()?, RetainedReadLimits::default(), &f.cx)?, ContentDigest::sha256(&f.mp4));
        let decoded = decode(&f, &imported)?;
        assert_eq!(decoded.len(), imported.frames);
        let unknown = CaptureInterval::new(TimestampNs(0), f.request.receive_time)?;
        assert!(decoded.iter().all(|frame| !frame.pixels.is_empty()
            && frame.capture == unknown && frame.mask.is_none()));
    }
    Ok(())
}

#[test]
fn exact_cold_retry_reuses_native_publication_and_preserves_authority() -> Test {
    let mut f = Fixture::new("cold", RtspImportCodec::Hevc)?;
    let first = f.run()?;
    let anchor = f.target()?.current_anchor().clone();
    let batches = f.target()?.ledger().batches().len();
    drop(f.target.take());
    drop(f.source.take());
    f.cx = context(&f.target_dir.0)?;
    f.target = Some(ReferenceDeployment::open(&f.target_dir.0, "site:rtsp-import", &f.cx)?);
    f.source = Some(LocalRootPublisher::open(&f.source_dir.0, archive_limits())?);
    let retry = f.run()?;
    assert!(retry.reused);
    assert_eq!(retry.import_identity, first.import_identity);
    assert_eq!(retry.import_root, first.import_root);
    assert_eq!(retry.proof, first.proof);
    assert_eq!(f.target()?.current_anchor(), &anchor);
    assert_eq!(f.target()?.ledger().batches().len(), batches);
    Ok(())
}

#[test]
fn source_scope_root_codec_and_each_independent_bound_refuse_before_target_mutation() -> Test {
    let mut f = Fixture::new("bounds", RtspImportCodec::Hevc)?;
    let original = f.request.clone();
    let baseline = f.target()?.ledger().batches().len();
    let roots = f.target()?.publisher().visible_roots().count();
    let total = f.original.iter().map(|(_, bytes)| bytes.len() as u64).sum::<u64>();
    for case in 0..7 {
        f.request = original.clone();
        match case {
            0 => f.request.root = ContentDigest::sha256(b"wrong exact window"),
            1 => f.request.source.generation += 1,
            2 => f.request.codec = RtspImportCodec::Avc,
            3 => f.request.max_frames = 1,
            4 => f.request.max_original_bytes = total - 1,
            5 => f.request.max_media_bytes = f.mp4.len() as u64 - 1,
            _ => f.request.slot = SlotName::parse("missing-window")?,
        }
        assert!(f.run().is_err(), "case {case}");
        assert_eq!(f.target()?.ledger().batches().len(), baseline);
        assert_eq!(f.target()?.publisher().visible_roots().count(), roots);
    }
    f.request = original;
    let limited = import_rtsp(
        f.source.as_ref().ok_or("source")?, f.target.as_mut().ok_or("target")?,
        &f.request, &Owner(Cell::new(true)), &f.cx, &mut WorkBudget::new(MAX_ORIGINAL_BYTES - 1),
    );
    assert!(limited.is_err());
    assert_eq!(f.target()?.ledger().batches().len(), baseline);
    Ok(())
}

#[test]
fn missing_or_corrupt_originals_are_never_replaced_by_reconstructed_mp4() -> Test {
    for codec in [RtspImportCodec::Avc, RtspImportCodec::Hevc] {
        let mut f = Fixture::new(&format!("damage-{}", codec.as_str()), codec)?;
        let imported = f.run()?;
        let retained = f.retained(&imported)?;
        let original_source = f.original.get(1).ok_or("source")?.0;
        let path = f.target()?.publisher().spool().object_path(original_source);
        fs::write(&path, b"damaged original packet pack")?;
        let before = f.target()?.ledger().batches().len();
        assert!(retained.verify_source(f.target()?, RetainedReadLimits::default(), &f.cx).is_err());
        assert!(retained.read_segment(f.target()?, 0, RetainedReadLimits::default(), &f.cx).is_err());
        assert!(decode(&f, &imported).is_err());
        assert!(f.run().is_err());
        assert_eq!(f.target()?.ledger().batches().len(), before);
        assert_eq!(fs::read(&path)?, b"damaged original packet pack");
    }
    let mut missing = Fixture::new("missing-original", RtspImportCodec::Avc)?;
    let original_source = missing.original.get(1).ok_or("source")?.0;
    fs::remove_file(missing.source.as_ref().ok_or("source")?.spool().object_path(original_source))?;
    let before = missing.target()?.ledger().batches().len();
    assert!(missing.run().is_err());
    assert_eq!(missing.target()?.ledger().batches().len(), before);
    Ok(())
}

#[test]
fn privacy_masks_apply_to_native_decoded_pixels_without_changing_source_identity() -> Test {
    for codec in [RtspImportCodec::Avc, RtspImportCodec::Hevc] {
        let mut f = Fixture::new(&format!("mask-{}", codec.as_str()), codec)?;
        let imported = f.run()?;
        let original = decode(&f, &imported)?;
        let size = original.first().ok_or("native frame")?.dimensions;
        let policy = PrivacyMaskPolicy::new(f.request.source.sensor.clone(), size, &[[0, 0, size[0], size[1]]])?;
        let approval = preview_mask(f.target()?, &policy)?.approval;
        declare_mask(f.target.as_mut().ok_or("target")?, &policy, approval, &f.cx)?;
        let masked = decode(&f, &imported)?;
        assert_eq!(masked.len(), imported.frames);
        assert!(masked.iter().all(|frame| frame.mask == Some(policy.digest())
            && frame.pixels.iter().all(|p| *p == MASK_FILL_LUMA)));
        let retry = f.run()?;
        assert!(retry.reused);
        assert_eq!(retry.import_identity, imported.import_identity);
        assert_eq!(f.retained(&retry)?.manifest().input_sha256, ContentDigest::sha256(&f.mp4));
    }
    Ok(())
}

#[test]
fn explicit_capture_origin_preserves_native_presentation_offsets_and_changes_identity() -> Test {
    let packets = hevc_recording_support::packets()?;
    let mut timings = hevc_recording_support::timings(4);
    // Declared composition offsets reorder presentation relative to coding order. The import
    // binds these supplied timings, not an inferred camera clock or invented fixed frame rate.
    timings[1].composition_offset = 18_000;
    timings[2].composition_offset = -18_000;
    let plan = hevc_recording_support::prepare(&packets, &timings)?;
    let mut f = Fixture::from_plan("presentation", RtspImportCodec::Hevc, plan.publication_plan())?;
    let unknown = f.run()?;
    f.request.capture_origin = Some(RtspCaptureOrigin { start_ns: TimestampNs(1_000_000_000), uncertainty_ns: 123 });
    let timed = f.run()?;
    assert_ne!(timed.import_identity, unknown.import_identity);
    assert_ne!(timed.proof, unknown.proof);
    assert_eq!(timed.capture_time_label, "operator_assumption");
    let retained = f.retained(&timed)?;
    let mut check = || Ok(());
    let mp4 = fss_container::demux::AvcMp4::parse_recovering_tail(
        &f.mp4, None, fss_container::demux::DemuxLimits::default(), &mut check,
    )?;
    let times: Vec<_> = mp4.samples().iter().map(|s| s.presentation_time()).collect();
    assert!(times.windows(2).any(|p| p[1] < p[0]));
    let earliest = *times.iter().min().ok_or("sample time")?;
    let denominator = i128::from(mp4.timescale());
    for (index, time) in times.iter().enumerate() {
        let capsule = fss_reference::ingest::recorded_decode::retained_source_capsule(
            f.target()?, &retained, index,
        )?;
        let offset = ((*time - earliest) * 1_000_000_000 + denominator / 2) / denominator;
        let expected = CaptureInterval::new(
            TimestampNs(1_000_000_000 + offset - 123),
            TimestampNs(1_000_000_000 + offset + 123),
        )?;
        assert_eq!(capsule.capture, expected);
    }
    Ok(())
}

#[test]
fn owner_denial_and_cancellation_preserve_partial_custody_for_exact_resume() -> Test {
    let mut f = Fixture::new("resume", RtspImportCodec::Hevc)?;
    let before = f.target()?.ledger().batches().len();
    let denied = import_rtsp(
        f.source.as_ref().ok_or("source")?, f.target.as_mut().ok_or("target")?,
        &f.request, &Owner(Cell::new(false)), &f.cx, &mut work(),
    );
    assert!(matches!(denied, Err(RtspImportError::Denied)));
    assert_eq!(f.target()?.ledger().batches().len(), before);
    f.cx.set_cancel_at_checkpoint("file_parts:root");
    assert!(f.run().is_err());
    assert!(f.target()?.ledger().batches().len() > before);
    f.cx = context(&f.target_dir.0)?;
    let completed = f.run()?;
    let retained = f.retained(&completed)?;
    retained.verify_source(f.target()?, RetainedReadLimits::default(), &f.cx)?;
    assert!(f.run()?.reused);
    Ok(())
}

#[test]
fn deletion_closure_carries_original_packet_graph_and_origin_recipe() -> Test {
    let mut f = Fixture::new("deletion", RtspImportCodec::Hevc)?;
    let imported = f.run()?;
    let plan = fss_reference::deletion::plan_deletion(f.target()?, imported.import_identity, &f.cx)?;
    for digest in f.original.iter().map(|(d, _)| *d).chain(std::iter::once(imported.proof)) {
        assert!(plan.deletable.iter().any(|entry| entry.digest == digest));
    }
    Ok(())
}

#[test]
fn changed_origin_and_missing_proof_cannot_reuse_old_replay_settings() -> Test {
    let mut f = Fixture::new("recipe", RtspImportCodec::Avc)?;
    let first = f.run()?;
    f.request.capture_origin = Some(RtspCaptureOrigin { start_ns: TimestampNs(1000), uncertainty_ns: 100 });
    let next = f.run()?;
    assert_ne!(next.import_identity, first.import_identity);
    let path = f.target()?.publisher().spool().object_path(next.proof);
    fs::remove_file(path)?;
    let before = f.target()?.ledger().batches().len();
    assert!(f.retained(&next).is_err());
    assert!(f.run().is_err());
    assert_eq!(f.target()?.ledger().batches().len(), before);
    Ok(())
}

#[test]
fn unknown_time_and_timestamp_overflow_remain_explicit_failures_or_unknown() -> Test {
    let mut f = Fixture::new("clock", RtspImportCodec::Hevc)?;
    let imported = f.run()?;
    assert!(decode(&f, &imported)?.iter().all(|frame| frame.capture.earliest == TimestampNs(0)));
    let before = f.target()?.ledger().batches().len();
    f.request.receive_time = TimestampNs(i128::MAX);
    f.request.capture_origin = Some(RtspCaptureOrigin { start_ns: TimestampNs(i128::MAX - 100), uncertainty_ns: 0 });
    assert!(f.run().is_err());
    assert_eq!(f.target()?.ledger().batches().len(), before);
    f.request.capture_origin = Some(RtspCaptureOrigin { start_ns: TimestampNs(i128::MAX), uncertainty_ns: 1 });
    assert!(f.request.digest().is_err());
    Ok(())
}
