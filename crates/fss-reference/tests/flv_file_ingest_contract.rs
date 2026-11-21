#![forbid(unsafe_code)]
//! Standard FLV originals traverse native custody, AVC decoding and detector execution.
//! The first-party remux preserves existing AVC bytes and independent frozen pixel oracles.

mod package_zone_support;
#[allow(dead_code)]
#[path = "support/import_integrity.rs"]
mod support;
#[path = "../../fss-container/tests/support/flv_fixture.rs"]
mod wire;

use std::fs;
use std::path::{Path, PathBuf};

use fss_codec_mjpeg::ComponentInterpretation;
use fss_container::demux::{AvcMp4, DemuxError, DemuxLimits, FlvVideo};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, CaptureInterval, ClockBasis, ContentDigest, OperationId, SensorId, StreamId,
    TimestampNs,
};
use fss_reference::ingest::package_detect::{
    PackageDetectLimits, PackageDetectRequest, run_package_detection,
};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::recorded_decode::h264::{
    DecoderLimits, RecordedH264Request, decode_h264_range,
};
use fss_reference::ingest::recorded_decode::{RecordedDecodeError, retained_source_capsule};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::ingest::{
    CaptureHint, FLV_PARAMETER_SET_REASON_PREFIX, FileFormatHint, FileIngestAdapter,
    FileIngestError, FileIngestReceipt, FileIngestRequest, RetainedFileImport, RetainedReadLimits,
};
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};
use support::{TestResult, directory, snapshot};

const SITE: &str = "site:flv-file-ingest";
const SENSOR: &str = "sensor:flv-file-ingest";
const RECEIVE: TimestampNs = TimestampNs(30_000_000_000);
const MP4: &[u8] = include_bytes!("../../fss-container/tests/fixtures/interleaved_av.mp4");
const ORACLE: &str = include_str!("../../fss-container/tests/fixtures/indexed_avc_i420.sha256");

fn source() -> TestResult<Vec<u8>> {
    let movie = AvcMp4::parse(MP4, None, DemuxLimits::default())?;
    let mut bytes = wire::header(true);
    wire::tag(&mut bytes, 18, 0, b"opaque source metadata");
    wire::configuration(&mut bytes, wire::avcc(MP4)?);
    for sample in movie.samples() {
        let dts = u32::try_from(sample.decode_time * 1000 / u64::from(movie.timescale()))?;
        let cts = i32::try_from(sample.composition_offset * 1000 / i64::from(movie.timescale()))?;
        wire::sample(
            &mut bytes,
            &MP4[sample.source.clone()],
            dts,
            cts,
            sample.contains_idr,
        );
        wire::tag(&mut bytes, 8, dts, &[0xaf, 1, 0, 3, 9]);
    }
    Ok(bytes)
}

fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:flv-file-ingest".into(),
        operation_id: OperationId::parse("operation:flv-file-ingest")?,
        principal: "principal:flv-file-ingest".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(512 * 1024 * 1024)
            .storage_operations(100_000)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

fn request(path: &Path) -> TestResult<FileIngestRequest> {
    let mut request = FileIngestRequest::new(
        path,
        SensorId::parse(SENSOR)?,
        StreamId::parse("stream:flv-file-ingest")?,
    )
    .with_receive_time(RECEIVE);
    request.limits.chunk_bytes = 512;
    request.limits.max_batch_deltas = 3;
    Ok(request)
}

struct Imported {
    root: PathBuf,
    deployment: ReferenceDeployment,
    cx: ReplayCx,
    receipt: FileIngestReceipt,
    source: Vec<u8>,
}

fn imported(
    label: &str,
    hint: Option<FileFormatHint>,
    timing: Option<CaptureHint>,
) -> TestResult<Imported> {
    let dir = directory(label)?;
    let input = dir.join("original.flv");
    let bytes = source()?;
    fs::write(&input, &bytes)?;
    let root = dir.join("deployment");
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let mut plan = request(&input)?;
    plan.format_hint = hint;
    plan.capture_hint = timing;
    let receipt = FileIngestAdapter::ingest(plan, &cx, &mut deployment)?;
    fs::remove_file(input)?;
    drop(deployment);
    let deployment = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    Ok(Imported {
        root,
        deployment,
        cx,
        receipt,
        source: bytes,
    })
}

fn decode_request(identity: ContentDigest, first: usize, count: usize) -> RecordedH264Request {
    RecordedH264Request {
        import_identity: identity,
        first_segment: first,
        segment_count: count,
        interpretation: ComponentInterpretation::YCbCr,
        read_limits: RetainedReadLimits::default(),
        decoder_limits: DecoderLimits::default(),
    }
}

#[test]
fn cold_auto_and_explicit_import_keep_original_flv_custody_and_frozen_avc_pixels() -> TestResult {
    for hint in [None, Some(FileFormatHint::FlvAvc)] {
        let imported = imported("flv-cold-custody", hint, None)?;
        assert_eq!(imported.receipt.manifest.format, "flvavc");
        assert_eq!(imported.receipt.manifest.capture_time_label, "unknown");
        assert!(!imported.receipt.absence_certifiable);
        let video = FlvVideo::parse(&imported.source, DemuxLimits::default())?;
        let before = snapshot(&imported.root)?;
        let retained = RetainedFileImport::open(
            &imported.deployment,
            imported.receipt.import_identity,
            RetainedReadLimits::default(),
            &imported.cx,
        )?;
        assert_eq!(
            retained.verify_source(
                &imported.deployment,
                RetainedReadLimits::default(),
                &imported.cx
            )?,
            ContentDigest::sha256(&imported.source),
        );
        assert!(retained.manifest().ordered_chunks.len() > 1);
        assert_eq!(
            retained.manifest().segment_spans.len(),
            video.samples().len()
        );
        for (span, sample) in retained
            .manifest()
            .segment_spans
            .iter()
            .zip(video.samples())
        {
            assert_eq!(span.offset, sample.source.start as u64);
            assert_eq!(span.len, sample.source.len() as u64);
            assert!(!span.gap_before);
            assert_eq!(
                retained.read_segment(
                    &imported.deployment,
                    span.segment_index,
                    RetainedReadLimits::default(),
                    &imported.cx
                )?,
                imported.source[sample.source.clone()],
            );
        }
        let parameters: Vec<_> = retained
            .manifest()
            .omission_spans
            .iter()
            .filter(|span| span.reason.starts_with(FLV_PARAMETER_SET_REASON_PREFIX))
            .collect();
        assert_eq!(parameters.len(), video.parameter_sets().len());
        for (actual, expected) in parameters.iter().zip(video.parameter_sets()) {
            assert_eq!(actual.offset, expected.start as u64);
            assert_eq!(actual.len, expected.len() as u64);
        }
        assert!(
            retained
                .manifest()
                .omission_spans
                .iter()
                .all(|span| span.is_container_structure())
        );
        let frames = decode_h264_range(
            &imported.deployment,
            decode_request(imported.receipt.import_identity, 0, video.samples().len()),
            &imported.cx,
        )?;
        let expected: Vec<_> = ORACLE
            .lines()
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| line.split_whitespace().nth(2))
            .map(|hash| format!("sha256:{hash}"))
            .collect();
        assert_eq!(frames.len(), expected.len());
        for (frame, expected) in frames.iter().zip(expected) {
            assert_eq!(frame.receipt().i420_sha256().to_text(), expected);
            assert_eq!(
                frame.capsule().capture,
                CaptureInterval::new(TimestampNs(0), RECEIVE)?
            );
            assert_eq!(frame.capsule().clock_basis, ClockBasis::Estimated);
            assert_eq!(frame.receipt().import_root(), imported.receipt.import_root);
        }
        assert_eq!(snapshot(&imported.root)?, before);
    }
    Ok(())
}

#[test]
fn explicit_capture_assumption_uses_original_pts_instead_of_assumed_frame_rate() -> TestResult {
    let hint = CaptureHint::new(TimestampNs(10_000_000_000), 3, 123.0)?;
    let imported = imported("flv-source-timing", None, Some(hint))?;
    let video = FlvVideo::parse(&imported.source, DemuxLimits::default())?;
    let earliest = video
        .samples()
        .iter()
        .map(|sample| sample.presentation_time_ms())
        .min()
        .ok_or("missing source sample")?;
    let retained = RetainedFileImport::open(
        &imported.deployment,
        imported.receipt.import_identity,
        RetainedReadLimits::default(),
        &imported.cx,
    )?;
    assert_eq!(
        retained.manifest().capture_time_label,
        "operator_assumption"
    );
    assert!(
        video
            .samples()
            .windows(2)
            .any(|pair| pair[0].presentation_time_ms() > pair[1].presentation_time_ms())
    );
    for sample in video.samples() {
        let capsule = retained_source_capsule(&imported.deployment, &retained, sample.index)?;
        let center =
            hint.start_ns.0 + i128::from(sample.presentation_time_ms() - earliest) * 1_000_000;
        assert_eq!(
            capsule.capture,
            CaptureInterval::new(TimestampNs(center - 3), TimestampNs(center + 3))?
        );
        assert_eq!(capsule.clock_basis, ClockBasis::Estimated);
    }
    assert_eq!(
        video.samples().last().and_then(|sample| sample.duration_ms),
        None
    );
    assert!(!imported.receipt.absence_certifiable);
    Ok(())
}

#[test]
fn malformed_flv_changed_configuration_and_sample_limits_publish_nothing() -> TestResult {
    let dir = directory("flv-atomic-refusal")?;
    let root = dir.join("deployment");
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let original = source()?;
    let mut malformed = original.clone();
    let video = FlvVideo::parse(&original, DemuxLimits::default())?;
    malformed[video.samples()[0].tag.end - 1] ^= 1;
    let mut changed = original.clone();
    let mut record = wire::avcc(MP4)?.to_vec();
    let last = record.len() - 1;
    record[last] ^= 1;
    wire::configuration(&mut changed, &record);
    let mut truncated = original.clone();
    truncated.pop();
    for (index, bytes) in [malformed, changed, truncated].iter().enumerate() {
        let path = dir.join(format!("refused-{index}.flv"));
        fs::write(&path, bytes)?;
        let before = snapshot(&root)?;
        assert!(matches!(
            FileIngestAdapter::ingest(request(&path)?, &cx, &mut deployment),
            Err(FileIngestError::FlvRefused { .. })
        ));
        assert_eq!(snapshot(&root)?, before);
    }
    let path = dir.join("limited.flv");
    fs::write(&path, &original)?;
    let mut plan = request(&path)?;
    plan.limits.max_segments = 9;
    let before = snapshot(&root)?;
    assert!(matches!(
        FileIngestAdapter::ingest(plan, &cx, &mut deployment),
        Err(FileIngestError::FlvRefused {
            refusal: DemuxError::Limit
        })
    ));
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

#[test]
fn cancellation_during_initial_flv_admission_precedes_any_import_publication() -> TestResult {
    let dir = directory("flv-sniff-cancel")?;
    let root = dir.join("deployment");
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let input = dir.join("source.flv");
    fs::write(&input, source()?)?;
    let before = snapshot(&root)?;
    cx.set_cancel_at_checkpoint_occurrence("file_adapter:split", 2);
    assert!(matches!(
        FileIngestAdapter::ingest(request(&input)?, &cx, &mut deployment),
        Err(FileIngestError::CancellationRequested {
            stage: "file_adapter:split"
        })
    ));
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

#[test]
fn flv_retained_ranges_keep_idr_admission_and_current_privacy_masks() -> TestResult {
    let mut imported = imported("flv-mask", None, None)?;
    assert!(matches!(
        decode_h264_range(
            &imported.deployment,
            decode_request(imported.receipt.import_identity, 1, 1),
            &imported.cx,
        ),
        Err(RecordedDecodeError::H264RangeNotIdr { segment: 1 })
    ));
    let policy = PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [64, 48], &[[0, 0, 64, 48]])?;
    let approval = preview_mask(&imported.deployment, &policy)?.approval;
    let mask =
        declare_mask(&mut imported.deployment, &policy, approval, &imported.cx)?.policy_digest;
    let before = snapshot(&imported.root)?;
    let frames = decode_h264_range(
        &imported.deployment,
        decode_request(imported.receipt.import_identity, 0, 10),
        &imported.cx,
    )?;
    assert_eq!(frames.len(), 10);
    for frame in frames {
        assert_eq!(frame.receipt().mask_policy(), Some(mask));
        assert!(frame.pixels().iter().all(|pixel| *pixel == 16));
        assert!(frame.cb().iter().all(|pixel| *pixel == 128));
        assert!(frame.cr().iter().all(|pixel| *pixel == 128));
    }
    assert_eq!(snapshot(&imported.root)?, before);
    Ok(())
}

#[test]
fn ordinary_detector_executes_from_cold_flv_custody_without_reimport_or_writes() -> TestResult {
    let imported = imported("flv-detector", None, None)?;
    let scalar = ScalarExecCx::default();
    let bytes = package_zone_support::package()?;
    let package = RgbDetectorPackage::load(
        &bytes,
        ContentDigest::sha256(&bytes),
        1 << 36,
        &imported.cx,
        &scalar,
    )?;
    let before = snapshot(&imported.root)?;
    let report = run_package_detection(
        &imported.deployment,
        &package,
        &PackageDetectRequest {
            import_identity: imported.receipt.import_identity,
            first_segment: 0,
            segment_count: 10,
            interpretation: ComponentInterpretation::YCbCr,
            minimum_score_ppm: None,
        },
        &PackageDetectLimits::default(),
        &imported.cx,
        &scalar,
    )?;
    assert_eq!(report.media_format, "flvavc");
    assert_eq!(report.import_root, imported.receipt.import_root);
    assert_eq!(report.frames.len(), 10);
    assert_eq!(report.digest, ContentDigest::sha256(report.json.as_bytes()));
    for frame in report.frames {
        assert_eq!(frame.dimensions, [64, 48]);
        assert_eq!(frame.color, "ycbcr420_bt601_limited_rgb");
        assert_eq!(frame.capsule.sensor_id.as_str(), SENSOR);
    }
    assert_eq!(snapshot(&imported.root)?, before);
    Ok(())
}
