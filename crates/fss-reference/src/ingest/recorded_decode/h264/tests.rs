#![forbid(unsafe_code)]
//! Retained Annex-B imports decode through the canonical H.264 codec, bit-exact against the
//! sealed FFmpeg oracle digests committed beside the codec fixtures.

use super::*;
use crate::ingest::{FileFormatHint, FileIngestAdapter, FileIngestRequest};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId, SensorId, StreamId, TimestampNs};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

/// I P P I, 160x128, SPS/PPS repeated before each IDR.
const BASELINE: &[u8] = include_bytes!("../../../../../fss-packet/tests/fixtures/avc/baseline.264");
/// FFmpeg `yuv420p` framehash of `BASELINE`, produced offline by the sealed oracle.
const BASELINE_ORACLE: &str =
    include_str!("../../../../../fss-codec-h264/tests/fixtures/decode/fss_packet_baseline.sha256");
/// High profile with B frames and the 8x8 transform: outside the admitted tool set.
const HIGH: &[u8] = include_bytes!("../../../../../fss-packet/tests/fixtures/avc/high_cropped.264");

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-recorded-h264-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:recorded-h264".to_owned(),
        operation_id: OperationId::parse("operation:recorded-h264")?,
        principal: "principal:recorded-h264".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(4096)
            .build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(b"site:recorded-h264"),
        generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

struct Imported {
    _directory: OwnedDirectory,
    cx: ReplayCx,
    deployment: ReferenceDeployment,
    identity: ContentDigest,
    segments: usize,
}

fn import(name: &str, bytes: &[u8]) -> TestResult<Imported> {
    let directory = OwnedDirectory::new(name)?;
    let root = directory.0.join("deployment");
    let path = directory.0.join("camera.h264");
    fs::write(&path, bytes)?;
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, "site:recorded-h264", &cx)?;
    let mut request = FileIngestRequest::new(
        path.clone(),
        SensorId::parse("sensor:recorded-h264")?,
        StreamId::parse("stream:recorded-h264")?,
    )
    .with_receive_time(TimestampNs(1_000_000_000));
    request.format_hint = Some(FileFormatHint::AnnexB);
    let receipt = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;
    // Decoding must depend on retained custody only, never on the original input path.
    fs::remove_file(path)?;
    Ok(Imported {
        _directory: directory,
        cx,
        deployment,
        identity: receipt.import_identity,
        segments: receipt.manifest.segment_spans.len(),
    })
}

fn request(identity: ContentDigest, first: usize, count: usize) -> RecordedH264Request {
    RecordedH264Request {
        import_identity: identity,
        first_segment: first,
        segment_count: count,
        interpretation: ComponentInterpretation::YCbCr,
        read_limits: RetainedReadLimits::default(),
        decoder_limits: DecoderLimits::default(),
    }
}

fn oracle(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .filter_map(|line| line.split_whitespace().nth(2))
        .map(|digest| format!("sha256:{digest}"))
        .collect()
}

/// Luma planes from the codec crate run directly over the whole original stream.
fn direct_luma(stream: &[u8]) -> TestResult<Vec<Vec<u8>>> {
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let pictures = decoder.decode_annex_b(stream)?;
    decoder.finish()?;
    Ok(pictures.iter().map(|p| p.luma().to_vec()).collect())
}

#[test]
fn retained_annexb_range_matches_ffmpeg_oracle_and_direct_codec_luma() -> TestResult {
    let imported = import("oracle", BASELINE)?;
    assert_eq!(imported.segments, 4);
    let expected = oracle(BASELINE_ORACLE);
    let direct = direct_luma(BASELINE)?;
    assert_eq!(expected.len(), 4);
    assert_eq!(direct.len(), 4);
    let frames = decode_h264_range(
        &imported.deployment,
        request(imported.identity, 0, 4),
        &imported.cx,
    )?;
    assert_eq!(frames.len(), 4);
    for (index, frame) in frames.iter().enumerate() {
        let receipt = frame.receipt();
        assert_eq!(receipt.segment_index(), index as u64);
        assert_eq!(receipt.decode_index(), index as u64);
        assert_eq!(receipt.dimensions(), [160, 128]);
        assert_eq!(receipt.i420_sha256().to_text(), expected[index]);
        assert_eq!(frame.pixels(), direct[index].as_slice());
        assert_eq!(receipt.luma_sha256(), ContentDigest::sha256(&direct[index]));
        assert_eq!(receipt.import_identity(), imported.identity);
        assert!(frame.pgm_bytes().starts_with(b"P5\n160 128\n255\n"));
    }
    assert_eq!(
        frames
            .iter()
            .map(|f| f.receipt().is_idr())
            .collect::<Vec<_>>(),
        [true, false, false, true]
    );
    // Deterministic: an independent second decode reproduces every receipt exactly.
    let again = decode_h264_range(
        &imported.deployment,
        request(imported.identity, 0, 4),
        &imported.cx,
    )?;
    assert_eq!(again, frames);
    Ok(())
}

#[test]
fn a_range_may_start_at_a_later_idr_but_never_at_a_predicted_picture() -> TestResult {
    let imported = import("idr", BASELINE)?;
    let expected = oracle(BASELINE_ORACLE);
    let later = decode_h264_range(
        &imported.deployment,
        request(imported.identity, 3, 1),
        &imported.cx,
    )?;
    assert_eq!(later.len(), 1);
    assert_eq!(later[0].receipt().i420_sha256().to_text(), expected[3]);
    assert_eq!(later[0].receipt().range_start(), 3);
    for start in [1, 2] {
        let refused = decode_h264_range(
            &imported.deployment,
            request(imported.identity, start, 1),
            &imported.cx,
        );
        match refused {
            Err(error @ RecordedDecodeError::H264RangeNotIdr { segment }) => {
                assert_eq!(segment, start);
                assert_eq!(error.stable_id(), "ERR-DECODE-H264-RANGE-NOT-IDR-001");
            }
            other => return Err(format!("expected a not-IDR refusal, got {other:?}").into()),
        }
    }
    assert!(matches!(
        decode_h264_range(
            &imported.deployment,
            request(imported.identity, 3, 2),
            &imported.cx
        ),
        Err(RecordedDecodeError::Unavailable)
    ));
    assert!(matches!(
        decode_h264_range(
            &imported.deployment,
            request(imported.identity, 0, 0),
            &imported.cx
        ),
        Err(RecordedDecodeError::Limit)
    ));
    Ok(())
}

#[test]
fn gray_interpretation_and_jpeg_only_operations_are_typed_refusals() -> TestResult {
    let imported = import("interpretation", BASELINE)?;
    let mut gray = request(imported.identity, 0, 1);
    gray.interpretation = ComponentInterpretation::Grayscale;
    let refused = decode_h264_range(&imported.deployment, gray, &imported.cx);
    assert!(matches!(
        refused,
        Err(RecordedDecodeError::InterpretationMismatch)
    ));
    // The single-frame JPEG path refuses Annex-B instead of feeding it to the JPEG codec.
    let jpeg = super::super::RecordedDecodeRequest {
        import_identity: imported.identity,
        segment_index: 0,
        interpretation: ComponentInterpretation::YCbCr,
        read_limits: RetainedReadLimits::default(),
        decode_limits: super::super::DecodeLimits::default(),
    };
    assert!(matches!(
        super::super::RecordedFrame::open(&imported.deployment, &jpeg, &imported.cx),
        Err(RecordedDecodeError::UnsupportedMedia)
    ));
    Ok(())
}

#[test]
fn truncated_slice_is_a_typed_codec_refusal_after_earlier_frames() -> TestResult {
    // Cut the final IDR slice in half: import custody accepts the bytes as recorded, and the
    // codec must refuse the damaged picture rather than conceal it.
    let last_nal = BASELINE
        .windows(3)
        .rposition(|w| w == [0, 0, 1])
        .ok_or("fixture has no start code")?;
    let truncated = &BASELINE[..last_nal + (BASELINE.len() - last_nal) / 2];
    let imported = import("truncated", truncated)?;
    assert_eq!(imported.segments, 4);
    let mut range = RecordedH264Range::open(
        &imported.deployment,
        request(imported.identity, 0, 4),
        &imported.cx,
    )?;
    for _ in 0..3 {
        assert!(
            range
                .next_frame(&imported.deployment, &imported.cx)?
                .is_some()
        );
    }
    let error = range
        .next_frame(&imported.deployment, &imported.cx)
        .err()
        .ok_or("a truncated IDR slice must not decode")?;
    assert!(
        matches!(
            error,
            RecordedDecodeError::H264(_) | RecordedDecodeError::H264AccessUnit { segment: 3 }
        ),
        "{error:?}"
    );
    assert_eq!(range.decoded(), 3);
    Ok(())
}

#[test]
fn unsupported_profile_is_refused_not_decoded() -> TestResult {
    let imported = import("high", HIGH)?;
    let refused = decode_h264_range(
        &imported.deployment,
        request(imported.identity, 0, imported.segments),
        &imported.cx,
    );
    match refused {
        Err(error @ RecordedDecodeError::H264(fss_codec_h264::DecodeError::Unsupported(_))) => {
            assert_eq!(error.stable_id(), "ERR-DECODE-H264-UNSUPPORTED-001");
        }
        other => return Err(format!("expected an unsupported-tool refusal, got {other:?}").into()),
    }
    Ok(())
}
