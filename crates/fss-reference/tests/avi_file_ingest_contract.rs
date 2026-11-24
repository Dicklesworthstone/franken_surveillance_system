#![forbid(unsafe_code)]
//! AVI source custody survives restart and reaches the existing native JPEG pipeline.

#[path = "../../fss-container/tests/support/avi_fixture.rs"]
mod fixture;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits, decode_luma};
use fss_container::avi::AviMjpeg;
use fss_container::demux::DemuxLimits;
use fss_core::{
    BudgetVector, CaptureInterval, ClockBasis, ContentDigest, ContextAuthority, OperationId,
    RootAuthoritySpec, SensorId, StreamId, TimestampNs,
};
use fss_reference::ingest::recorded_decode::{
    RecordedDecodeRequest, RecordedFrame, retained_source_capsule,
};
use fss_reference::ingest::{
    CaptureHint, FileFormatHint, FileIngestAdapter, FileIngestOutcome, FileIngestRequest,
    RetainedFileImport, RetainedReadLimits,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:avi-file-ingest";
const RECEIVE: TimestampNs = TimestampNs(30_000_000_000);

fn directory(label: &str) -> Test<PathBuf> {
    for attempt in 0..128 {
        let root = std::env::temp_dir().join(format!(
            "fss-avi-{label}-{}-{attempt}", std::process::id()
        ));
        match fs::create_dir(&root) {
            Ok(()) => return Ok(root),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err("temporary directory reservation exhausted".into())
}

fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:avi-file-ingest".into(),
        operation_id: OperationId::parse("operation:avi-file-ingest")?,
        principal: "principal:avi-file-ingest".into(),
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
    Ok(ReplayCx::from_context_authority(&authority, root.to_path_buf())?)
}

fn request(path: &Path) -> Test<FileIngestRequest> {
    let mut request = FileIngestRequest::new(
        path,
        SensorId::parse("sensor:avi-file-ingest")?,
        StreamId::parse("stream:avi-file-ingest")?,
    )
    .with_receive_time(RECEIVE);
    request.limits.chunk_bytes = 512;
    request.limits.max_batch_deltas = 3;
    Ok(request)
}

fn snapshot(root: &Path) -> Test<BTreeMap<PathBuf, Vec<u8>>> {
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            files.extend(snapshot(&entry.path())?);
        } else {
            files.insert(entry.path(), fs::read(entry.path())?);
        }
    }
    Ok(files)
}

#[test]
fn auto_and_explicit_import_cold_reopen_and_decode_preserve_original_frames() -> Test {
    for hint in [None, Some(FileFormatHint::AviMjpeg)] {
        let root = directory("cold")?;
        let input = root.join("capture.avi");
        let bytes = fixture::movie(true, true);
        fs::write(&input, &bytes)?;
        let store = root.join("deployment");
        let cx = context(&store)?;
        let mut deployment = ReferenceDeployment::open(&store, SITE, &cx)?;
        let mut plan = request(&input)?;
        plan.format_hint = hint;
        let receipt = FileIngestAdapter::ingest(plan.clone(), &cx, &mut deployment)?;
        assert_eq!(receipt.manifest.format, "avimjpeg");
        assert_eq!(receipt.capsule_count, 3);
        assert_eq!(receipt.capture_time_label, "unknown");
        assert!(!receipt.absence_certifiable);
        assert!(receipt.manifest.omission_spans.iter().all(|span| span.is_container_structure()));
        let prior = snapshot(&store)?;
        let retried = FileIngestAdapter::ingest(plan, &cx, &mut deployment)?;
        assert_eq!(retried.outcome, FileIngestOutcome::IdempotentExisting);
        assert_eq!(retried.import_identity, receipt.import_identity);
        assert_eq!(snapshot(&store)?, prior);
        fs::remove_file(input)?;
        drop(deployment);

        let mut deployment = ReferenceDeployment::reopen(&store, SITE, &cx)?;
        let retained = RetainedFileImport::open(
            &deployment, receipt.import_identity, RetainedReadLimits::default(), &cx,
        )?;
        assert_eq!(
            retained.verify_source(&deployment, RetainedReadLimits::default(), &cx)?,
            ContentDigest::sha256(&bytes)
        );
        let video = AviMjpeg::parse(&bytes, DemuxLimits::default())?;
        let expected = decode_luma(
            fixture::JPEG,
            ContentDigest::sha256(fixture::JPEG).bytes(),
            ComponentInterpretation::YCbCr,
            DecodeLimits::default(),
            &mut DecodeBudget::new(50_000_000),
        )?;
        for sample in video.samples() {
            let span = &retained.manifest().segment_spans[sample.index];
            assert_eq!(span.offset, sample.source.start as u64);
            assert_eq!(span.len, sample.source.len() as u64);
            assert!(!span.gap_before);
            assert_eq!(
                retained.read_segment(&deployment, sample.index, RetainedReadLimits::default(), &cx)?,
                fixture::JPEG
            );
            let capsule = retained_source_capsule(&deployment, &retained, sample.index)?;
            assert_eq!(capsule.capture, CaptureInterval::new(TimestampNs(0), RECEIVE)?);
            assert_eq!(capsule.clock_basis, ClockBasis::Estimated);
            let decode = RecordedDecodeRequest {
                import_identity: receipt.import_identity,
                segment_index: sample.index,
                interpretation: ComponentInterpretation::YCbCr,
                read_limits: RetainedReadLimits::default(),
                decode_limits: DecodeLimits::default(),
            };
            let frame = RecordedFrame::decode_and_publish(
                &mut deployment, &decode, &mut DecodeBudget::new(50_000_000), &cx,
            )?;
            assert_eq!(frame.pixels(), expected.pixels());
            assert_eq!(frame.receipt().capsule(), &capsule);
            assert_eq!(RecordedFrame::open(&deployment, &decode, &cx)?.pixels(), expected.pixels());
        }
    }
    Ok(())
}

#[test]
fn capture_assumption_uses_stream_fractional_time_with_a_different_assumed_rate() -> Test {
    let root = directory("time")?;
    let input = root.join("capture.avi");
    fs::write(&input, fixture::movie(false, false))?;
    let store = root.join("deployment");
    let cx = context(&store)?;
    let mut deployment = ReferenceDeployment::open(&store, SITE, &cx)?;
    let mut plan = request(&input)?;
    plan.capture_hint = Some(CaptureHint::new(TimestampNs(10_000_000_000), 3, 1.0)?);
    let receipt = FileIngestAdapter::ingest(plan, &cx, &mut deployment)?;
    assert_eq!(receipt.capture_time_label, "operator_assumption");
    for (capsule, offset) in receipt.capsules.iter().zip([0_i128, 33_366_667, 66_733_333]) {
        assert_eq!(
            capsule.capture,
            CaptureInterval::new(
                TimestampNs(10_000_000_000 + offset - 3),
                TimestampNs(10_000_000_000 + offset + 3),
            )?
        );
    }
    Ok(())
}

#[test]
fn two_images_in_one_chunk_and_geometry_mismatch_fail_before_retention() -> Test {
    let root = directory("refusal")?;
    let input = root.join("capture.avi");
    let store = root.join("deployment");
    let cx = context(&store)?;
    let mut deployment = ReferenceDeployment::open(&store, SITE, &cx)?;
    let before = snapshot(&store)?;
    let doubled = [fixture::JPEG, fixture::JPEG].concat();
    let mut dimensions = fixture::movie(false, false);
    let format = dimensions.windows(4).position(|p| p == b"strf").ok_or("strf")?;
    dimensions[format + 12..format + 16].copy_from_slice(&65_u32.to_le_bytes());
    for bytes in [
        fixture::movie_with_frames(&[&doubled], false, false),
        dimensions,
    ] {
        fs::write(&input, bytes)?;
        assert!(FileIngestAdapter::ingest(request(&input)?, &cx, &mut deployment).is_err());
        assert_eq!(snapshot(&store)?, before);
    }
    Ok(())
}

#[test]
fn interlaced_avi1_fields_refuse_before_publication() -> Test {
    let root = directory("fields")?;
    let input = root.join("capture.avi");
    let store = root.join("deployment");
    let cx = context(&store)?;
    let mut deployment = ReferenceDeployment::open(&store, SITE, &cx)?;
    let before = snapshot(&store)?;
    for polarity in [1_u8, 2] {
        let mut jpeg = fixture::JPEG[..2].to_vec();
        jpeg.extend_from_slice(&[0xff, 0xe0, 0, 7, b'A', b'V', b'I', b'1', polarity]);
        jpeg.extend_from_slice(&fixture::JPEG[2..]);
        fs::write(&input, fixture::movie_with_frames(&[&jpeg], false, false))?;
        assert!(FileIngestAdapter::ingest(request(&input)?, &cx, &mut deployment).is_err());
        assert_eq!(snapshot(&store)?, before);
    }
    let mut jpeg = fixture::JPEG[..2].to_vec();
    jpeg.extend_from_slice(&[0xff, 0xe0, 0, 7, b'A', b'V', b'I', b'1', 0]);
    jpeg.extend_from_slice(&fixture::JPEG[2..]);
    fs::write(&input, fixture::movie_with_frames(&[&jpeg], false, false))?;
    let receipt = FileIngestAdapter::ingest(request(&input)?, &cx, &mut deployment)?;
    assert_eq!(receipt.capsule_count, 1);
    Ok(())
}
