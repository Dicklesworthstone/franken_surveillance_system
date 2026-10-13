#![forbid(unsafe_code)]
//! Durable native video frames: actual codecs, cold reads, crash resumption and custody refusal.

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, Plane, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::recorded_decode::h264::{
    DecoderLimits as AvcLimits, RecordedH264Frame, RecordedH264Range, RecordedH264Request,
};
use fss_reference::ingest::recorded_decode::h265::{
    DecoderLimits as HevcLimits, RecordedH265Range, RecordedH265Request,
};
use fss_reference::ingest::recorded_decode::{ComponentInterpretation, RecordedDecodeError};
use fss_reference::ingest::video_publication::{
    NativeVideoFrame, PublishedVideoCodec, PublishedVideoFrame, STAGE_VIDEO_PUBLICATION_COMMIT,
    VideoPublicationLimits,
};
use fss_reference::ingest::{FileFormatHint, FileIngestAdapter, FileIngestRequest, RetainedFileImport, RetainedReadLimits};
use fss_reference::{ReferenceDeployment, ReplayCx};
use std::fs;
use std::path::{Path, PathBuf};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:video-publication";
const AVC: &[u8] = include_bytes!("../../fss-codec-h264/tests/fixtures/decode/p_qcif_ref3_p4x4.h264");
const HEVC: &[u8] = include_bytes!("../../fss-codec-h265/tests/fixtures/decode/f_qcif_default.h265");

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-video-publication-{label}-{}-{attempt}", std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:video-publication".to_owned(),
        operation_id: OperationId::parse("operation:video-publication")?,
        principal: "principal:video-publication".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).storage_operations(65_536).build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(&authority, root.to_path_buf())?)
}
struct Imported {
    _directory: Directory,
    root: PathBuf,
    cx: ReplayCx,
    deployment: ReferenceDeployment,
    identity: ContentDigest,
}
fn imported(label: &str, bytes: &[u8], format: FileFormatHint) -> Test<Imported> {
    let directory = Directory::new(label)?;
    let root = directory.0.join("deployment");
    let source = directory.0.join("input");
    fs::write(&source, bytes)?;
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let mut request = FileIngestRequest::new(
        source.clone(), SensorId::parse("sensor:video-publication")?,
        StreamId::parse("stream:video-publication")?,
    ).with_receive_time(TimestampNs(1_000_000_000));
    request.format_hint = Some(format);
    let receipt = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;
    fs::remove_file(source)?;
    Ok(Imported { _directory: directory, root, cx, deployment, identity: receipt.import_identity })
}
fn avc_frames(imported: &Imported, count: usize) -> Test<Vec<RecordedH264Frame>> {
    let mut range = RecordedH264Range::open(&imported.deployment, RecordedH264Request {
        import_identity: imported.identity, first_segment: 0, segment_count: count,
        interpretation: ComponentInterpretation::YCbCr,
        read_limits: RetainedReadLimits::default(),
        decoder_limits: AvcLimits {
            max_width: 176, max_height: 144, max_macroblocks: 99, ..AvcLimits::default()
        },
    }, &imported.cx)?;
    let mut frames = Vec::new();
    while let Some(frame) = range.next_frame(&imported.deployment, &imported.cx)? { frames.push(frame); }
    assert_eq!(frames.len(), count);
    Ok(frames)
}
fn publish(imported: &mut Imported, frame: &RecordedH264Frame) -> Test<PublishedVideoFrame> {
    Ok(PublishedVideoFrame::publish(&mut imported.deployment, NativeVideoFrame::H264(frame),
                                   VideoPublicationLimits::default(), &imported.cx)?)
}

#[test]
fn h264_pixels_and_native_receipt_survive_cold_restart_with_idempotent_authority() -> Test {
    let mut imported = imported("avc", AVC, FileFormatHint::AnnexB)?;
    let frames = avc_frames(&imported, 3)?;
    let native = &frames[1];
    let published = publish(&mut imported, native)?;
    assert_eq!(published.codec(), PublishedVideoCodec::H264);
    assert_eq!(published.codec_receipt(), native.receipt().encoded());
    assert_eq!(published.pixels(), native.pixels());
    assert_eq!(published.cb(), native.cb());
    assert_eq!(published.cr(), native.cr());
    assert_eq!(published.to_rgb()?, native.to_rgb()?);
    assert_eq!(published.range_segment_count(), 3);
    assert_eq!(published.output_index(), 1);
    let anchor = published.authority_anchor().clone();
    let batches = imported.deployment.ledger().batches().len();
    assert_eq!(publish(&mut imported, native)?.authority_anchor(), &anchor);
    assert_eq!(imported.deployment.ledger().batches().len(), batches);
    let completion = imported.deployment.ledger().batches().last().ok_or("completion")?;
    assert_eq!(completion.deltas.len(), 1);
    assert_eq!(completion.deltas[0].plane, Plane::Cognition);
    assert_eq!(completion.deltas[0].family, "decode_receipt");
    drop(imported.deployment);
    let reopened = ReferenceDeployment::open(&imported.root, SITE, &imported.cx)?;
    let cold = PublishedVideoFrame::open(&reopened, published.publication_root(),
                                         VideoPublicationLimits::default(), &imported.cx)?;
    assert_eq!(cold.i420(), published.i420());
    assert_eq!(cold.codec_receipt(), published.codec_receipt());
    assert_eq!(cold.authority_anchor(), &anchor);
    assert_eq!(cold.to_rgb()?, native.to_rgb()?);
    Ok(())
}

#[test]
fn hevc_display_order_and_chroma_survive_publication() -> Test {
    let mut imported = imported("hevc", HEVC, FileFormatHint::Hevc)?;
    let mut range = RecordedH265Range::open(&imported.deployment, RecordedH265Request {
        import_identity: imported.identity, first_segment: 0, segment_count: 8,
        interpretation: ComponentInterpretation::YCbCr,
        read_limits: RetainedReadLimits::default(),
        decoder_limits: HevcLimits {
            max_width: 176, max_height: 144, max_luma_samples: 176 * 144, ..HevcLimits::default()
        },
    }, &imported.cx)?;
    let mut segments = Vec::new();
    while let Some(frame) = range.next_frame(&imported.deployment, &imported.cx)? {
        let published = PublishedVideoFrame::publish(&mut imported.deployment,
            NativeVideoFrame::H265(&frame), VideoPublicationLimits::default(), &imported.cx)?;
        assert_eq!(published.codec(), PublishedVideoCodec::H265);
        assert_eq!(published.output_index(), segments.len() as u64);
        assert_eq!(published.segment_index(), frame.segment_index());
        assert_eq!(published.codec_receipt(), frame.receipt().encoded());
        let cold = PublishedVideoFrame::open(&imported.deployment, published.publication_root(),
                                             VideoPublicationLimits::default(), &imported.cx)?;
        assert_eq!(cold.to_rgb()?, frame.to_rgb()?);
        assert_eq!(ContentDigest::sha256(cold.i420()), frame.receipt().i420_sha256());
        segments.push(frame.segment_index());
    }
    assert_eq!(segments.len(), 8);
    assert!(segments.windows(2).any(|pair| pair[1] < pair[0]));
    Ok(())
}

#[test]
fn published_root_without_completion_is_not_a_frame_and_exact_retry_resumes() -> Test {
    let mut imported = imported("cut", AVC, FileFormatHint::AnnexB)?;
    let frames = avc_frames(&imported, 3)?;
    let retained = RetainedFileImport::open(&imported.deployment, imported.identity,
                                            RetainedReadLimits::default(), &imported.cx)?;
    let receipt = frames[1].receipt();
    let expected_root = fss_object::ObjectManifest::new("recorded-video-frame:v1:3:1",
        std::collections::BTreeSet::from([retained.import_root(), retained.manifest_digest(),
            receipt.capsule_digest(), receipt.i420_sha256()]), Some(receipt.digest()))?.root();
    let before = imported.deployment.ledger().batches().len();
    imported.cx.set_cancel_at_checkpoint_occurrence(STAGE_VIDEO_PUBLICATION_COMMIT, 1);
    assert!(matches!(PublishedVideoFrame::publish(&mut imported.deployment,
        NativeVideoFrame::H264(&frames[1]), VideoPublicationLimits::default(), &imported.cx),
        Err(RecordedDecodeError::Cancelled)));
    // Only root publication may have committed; the named frame-completion batch must not exist.
    assert!(!imported.deployment.ledger().batches()[before..].iter().any(|batch|
        batch.batch_id.as_str().starts_with("batch:recorded-video:")));
    drop(imported.deployment);
    let cx = context(&imported.root)?;
    let mut deployment = ReferenceDeployment::open(&imported.root, SITE, &cx)?;
    assert!(matches!(PublishedVideoFrame::open(&deployment, expected_root,
        VideoPublicationLimits::default(), &cx), Err(RecordedDecodeError::Unavailable)));
    let published = PublishedVideoFrame::publish(&mut deployment, NativeVideoFrame::H264(&frames[1]),
                                                 VideoPublicationLimits::default(), &cx)?;
    assert_eq!(published.pixels(), frames[1].pixels());
    let n = deployment.ledger().batches().len();
    let repeated = PublishedVideoFrame::publish(&mut deployment, NativeVideoFrame::H264(&frames[1]),
                                                VideoPublicationLimits::default(), &cx)?;
    assert_eq!(repeated.authority_anchor(), published.authority_anchor());
    assert_eq!(deployment.ledger().batches().len(), n);
    Ok(())
}

#[test]
fn completed_reuse_does_not_widen_pixel_or_source_limits() -> Test {
    let mut imported = imported("bounds", AVC, FileFormatHint::AnnexB)?;
    let frames = avc_frames(&imported, 3)?;
    let published = publish(&mut imported, &frames[0])?;
    let before = imported.deployment.ledger().batches().len();
    let narrow = VideoPublicationLimits { maximum_pixels: 1, ..VideoPublicationLimits::default() };
    assert!(matches!(PublishedVideoFrame::open(&imported.deployment, published.publication_root(),
                                              narrow, &imported.cx), Err(RecordedDecodeError::Limit)));
    assert!(matches!(PublishedVideoFrame::publish(&mut imported.deployment,
        NativeVideoFrame::H264(&frames[0]), narrow, &imported.cx), Err(RecordedDecodeError::Limit)));
    let mut narrow = VideoPublicationLimits::default();
    narrow.source.max_source_bytes = 1;
    assert!(PublishedVideoFrame::open(&imported.deployment, published.publication_root(), narrow,
                                      &imported.cx).is_err());
    assert_eq!(imported.deployment.ledger().batches().len(), before);
    Ok(())
}

// Deliberate storage fault injection without depending on the spool's private envelope layout.
fn payload_file(root: &Path, payload: &[u8]) -> Test<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() { pending.push(entry.path()); }
            else if entry.file_type()?.is_file() {
                let bytes = fs::read(entry.path())?;
                if bytes.windows(payload.len()).any(|window| window == payload) {
                    return Ok(entry.path());
                }
            }
        }
    }
    Err("retained payload missing".into())
}

#[test]
fn corrupt_completed_pixels_are_not_silently_repaired_by_republication() -> Test {
    let mut imported = imported("corrupt-pixels", AVC, FileFormatHint::AnnexB)?;
    let frames = avc_frames(&imported, 3)?;
    let published = publish(&mut imported, &frames[1])?;
    let path = payload_file(imported.deployment.publisher().spool().root(), published.i420())?;
    let mut damaged = fs::read(&path)?;
    let middle = damaged.len() / 2;
    damaged[middle] ^= 1;
    fs::write(&path, &damaged)?;
    let before = imported.deployment.ledger().batches().len();
    assert!(PublishedVideoFrame::open(&imported.deployment, published.publication_root(),
                                      VideoPublicationLimits::default(), &imported.cx).is_err());
    assert!(publish(&mut imported, &frames[1]).is_err());
    assert_eq!(fs::read(path)?, damaged);
    assert_eq!(imported.deployment.ledger().batches().len(), before);
    Ok(())
}

#[test]
fn source_damage_after_native_decode_prevents_any_frame_publication() -> Test {
    let mut imported = imported("corrupt-source", AVC, FileFormatHint::AnnexB)?;
    let frames = avc_frames(&imported, 3)?;
    let path = payload_file(imported.deployment.publisher().spool().root(), AVC)?;
    let mut damaged = fs::read(&path)?;
    let middle = damaged.len() / 2;
    damaged[middle] ^= 1;
    fs::write(path, damaged)?;
    let before = imported.deployment.ledger().batches().len();
    assert!(publish(&mut imported, &frames[1]).is_err());
    assert_eq!(imported.deployment.ledger().batches().len(), before);
    Ok(())
}
