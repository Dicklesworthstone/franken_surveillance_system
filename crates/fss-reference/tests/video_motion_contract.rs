#![forbid(unsafe_code)]
//! Receipt-backed motion order, budget and cancellation contracts over real retained video.

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::pixel_change::{
    PixelChangeConfig, PixelChangeDetector, PixelChangeError, PixelChangeReset,
};
use fss_reference::ingest::recorded_decode::h264::{
    DecoderLimits as AvcLimits, RecordedH264Range, RecordedH264Request,
};
use fss_reference::ingest::recorded_decode::h265::{
    DecoderLimits as HevcLimits, RecordedH265Range, RecordedH265Request,
};
use fss_reference::ingest::recorded_decode::video_budget::RecordedVideoDecodeBudget;
use fss_reference::ingest::recorded_decode::{ComponentInterpretation, RecordedDecodeError};
use fss_reference::ingest::{
    FileFormatHint, FileIngestAdapter, FileIngestRequest, RetainedReadLimits,
};
use fss_reference::{ReferenceDeployment, ReplayCx};
use std::fs;
use std::path::{Path, PathBuf};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const AVC: &[u8] =
    include_bytes!("../../fss-codec-h264/tests/fixtures/decode/p_qcif_ref3_p4x4.h264");
const HEVC: &[u8] =
    include_bytes!("../../fss-codec-h265/tests/fixtures/decode/f_qcif_default.h265");

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-video-motion-reference-{label}-{}-{attempt}",
                std::process::id()
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
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:video-motion".to_owned(),
        operation_id: OperationId::parse("operation:video-motion")?,
        principal: "principal:video-motion".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(4096)
            .build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(b"site:video-motion"),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

struct Imported {
    directory: Directory,
    root: PathBuf,
    cx: ReplayCx,
    deployment: ReferenceDeployment,
    identity: ContentDigest,
}

fn imported(label: &str, bytes: &[u8], format: FileFormatHint) -> Test<Imported> {
    let directory = Directory::new(label)?;
    let root = directory.0.join("deployment");
    let path = directory.0.join("source");
    fs::write(&path, bytes)?;
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, "site:video-motion", &cx)?;
    let mut request = FileIngestRequest::new(
        path.clone(),
        SensorId::parse("sensor:video-motion")?,
        StreamId::parse("stream:video-motion")?,
    )
    .with_receive_time(TimestampNs(1_000_000_000));
    request.format_hint = Some(format);
    let receipt = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;
    fs::remove_file(path)?;
    Ok(Imported {
        directory,
        root,
        cx,
        deployment,
        identity: receipt.import_identity,
    })
}

fn avc_request(identity: ContentDigest, count: usize) -> RecordedH264Request {
    RecordedH264Request {
        import_identity: identity,
        first_segment: 0,
        segment_count: count,
        interpretation: ComponentInterpretation::YCbCr,
        read_limits: RetainedReadLimits::default(),
        decoder_limits: AvcLimits {
            max_width: 176,
            max_height: 144,
            max_macroblocks: 99,
            ..AvcLimits::default()
        },
    }
}
fn hevc_request(identity: ContentDigest, count: usize) -> RecordedH265Request {
    RecordedH265Request {
        import_identity: identity,
        first_segment: 0,
        segment_count: count,
        interpretation: ComponentInterpretation::YCbCr,
        read_limits: RetainedReadLimits::default(),
        decoder_limits: HevcLimits {
            max_width: 176,
            max_height: 144,
            max_luma_samples: 176 * 144,
            ..HevcLimits::default()
        },
    }
}
fn detector() -> Test<PixelChangeDetector> {
    Ok(PixelChangeDetector::new(
        PixelChangeConfig {
            minimum_delta: 16,
            minimum_changed_pixels: 1,
            minimum_changed_fraction_ppm: 0,
        },
        1_000_000,
    )?)
}

#[test]
fn display_position_admits_b_pictures_but_rejects_reverse_delivery_and_resets_skips() -> Test {
    let imported = imported("display", HEVC, FileFormatHint::Hevc)?;
    let mut range = RecordedH265Range::open(
        &imported.deployment,
        hevc_request(imported.identity, 8),
        &imported.cx,
    )?;
    let mut frames = Vec::new();
    while let Some(frame) = range.next_frame(&imported.deployment, &imported.cx)? {
        frames.push(frame);
    }
    assert_eq!(frames.len(), 8);
    assert!(
        frames
            .windows(2)
            .any(|pair| pair[1].segment_index() < pair[0].segment_index())
    );
    let mut detector = detector()?;
    let first = detector.push_h265(&frames[0], &imported.cx)?;
    assert_eq!(first.frame_receipt_digest, frames[0].receipt().digest());
    assert_eq!(detector.push_h265(&frames[0], &imported.cx)?, first);
    assert_eq!(detector.comparisons_used(), 0);
    let second = detector.push_h265(&frames[1], &imported.cx)?;
    assert!(second.statistics.is_some());
    assert_eq!(
        detector.push_h265(&frames[0], &imported.cx),
        Err(PixelChangeError::OutOfOrder)
    );
    let third = detector.push_h265(&frames[2], &imported.cx)?;
    assert_eq!(
        third.predecessor_receipt_digest,
        Some(second.frame_receipt_digest)
    );
    assert_eq!(detector.comparisons_used(), 2 * 176 * 144);
    let skipped = detector.push_h265(&frames[4], &imported.cx)?;
    assert!(skipped.reset_reasons.contains(&PixelChangeReset::SourceGap));
    assert!(skipped.statistics.is_none());
    assert_eq!(detector.comparisons_used(), 2 * 176 * 144);
    let mut different_range = RecordedH265Range::open(
        &imported.deployment,
        hevc_request(imported.identity, 3),
        &imported.cx,
    )?;
    let first = different_range
        .next_frame(&imported.deployment, &imported.cx)?
        .ok_or("missing frame")?;
    let reset = detector.push_h265(&first, &imported.cx)?;
    assert!(reset.reset_reasons.contains(&PixelChangeReset::SourceGap));
    assert!(reset.statistics.is_none());
    Ok(())
}

#[test]
fn cancellation_during_comparison_charges_rows_without_advancing_the_baseline() -> Test {
    let imported = imported("cancel-comparison", AVC, FileFormatHint::AnnexB)?;
    let mut range = RecordedH264Range::open(
        &imported.deployment,
        avc_request(imported.identity, 3),
        &imported.cx,
    )?;
    let first = range
        .next_frame(&imported.deployment, &imported.cx)?
        .ok_or("first frame")?;
    let second = range
        .next_frame(&imported.deployment, &imported.cx)?
        .ok_or("second frame")?;
    let mut detector = detector()?;
    let baseline = detector.push_h264(&first, &imported.cx)?;
    imported
        .cx
        .set_cancel_at_checkpoint_occurrence("pixel_change:row", 3);
    assert_eq!(
        detector.push_h264(&second, &imported.cx),
        Err(PixelChangeError::Cancelled)
    );
    assert_eq!(detector.comparisons_used(), 176);
    let resumed = context(&imported.root)?;
    let observed = detector.push_h264(&second, &resumed)?;
    assert_eq!(
        observed.predecessor_receipt_digest,
        Some(baseline.frame_receipt_digest)
    );
    assert_eq!(detector.comparisons_used(), 176 + 176 * 144);
    Ok(())
}

#[test]
fn video_budget_precedes_codec_work_including_decode_ahead_and_cancelled_inputs() -> Test {
    let imported = imported("budget", AVC, FileFormatHint::AnnexB)?;
    let mut zero = RecordedVideoDecodeBudget::new(0);
    let mut range = RecordedH264Range::open_with_budget(
        &imported.deployment,
        avc_request(imported.identity, 12),
        &mut zero,
        &imported.cx,
    )?;
    assert!(matches!(
        range.next_frame_with_budget(&imported.deployment, &mut zero, &imported.cx),
        Err(RecordedDecodeError::Limit)
    ));
    assert_eq!(range.decoded(), 0);
    assert_eq!(range.next_source_segment(), 0);
    assert_eq!(zero.used(), 0);
    let mut budget = RecordedVideoDecodeBudget::new(2_000_000);
    let mut range = RecordedH264Range::open_with_budget(
        &imported.deployment,
        avc_request(imported.identity, 12),
        &mut budget,
        &imported.cx,
    )?;
    imported.cx.set_cancel_at_checkpoint("recorded_h264:nal");
    assert!(matches!(
        range.next_frame_with_budget(&imported.deployment, &mut budget, &imported.cx),
        Err(RecordedDecodeError::Cancelled)
    ));
    assert!(budget.used() >= 176 * 144);
    assert_eq!(range.decoded(), 0);
    assert_eq!(range.next_source_segment(), 0);
    // Keep the fixture directory alive through every retained read.
    assert!(imported.directory.0.exists());
    Ok(())
}

#[test]
fn a_retained_parameter_set_gap_refuses_the_whole_predictive_range_before_motion() -> Test {
    // Withholding the actual SPS/PPS creates source capsules explicitly marked undecodable;
    // no caller invents a gap flag or changes the retained manifest after publication.
    let mut bytes = Vec::new();
    for nal in fss_codec_h264::annex_b_nal_units(AVC) {
        if matches!(nal.first().map(|header| header & 31), Some(7 | 8)) {
            continue;
        }
        bytes.extend_from_slice(&[0, 0, 0, 1]);
        bytes.extend_from_slice(nal);
    }
    let imported = imported("gap", &bytes, FileFormatHint::AnnexB)?;
    let mut budget = RecordedVideoDecodeBudget::new(2_000_000);
    assert!(matches!(
        RecordedH264Range::open_with_budget(
            &imported.deployment,
            avc_request(imported.identity, 3),
            &mut budget,
            &imported.cx
        ),
        Err(RecordedDecodeError::H264SourceGap { segment: 1 })
    ));
    assert_eq!(budget.used(), 0);
    Ok(())
}
