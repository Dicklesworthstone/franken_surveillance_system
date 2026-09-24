#![forbid(unsafe_code)]
//! Retained `hevc` imports decode through the canonical H.265 codec, bit-exact against the sealed
//! FFmpeg oracle digests committed beside the codec fixtures (and, for the CRA-led range, the
//! oracle committed in `tests/fixtures/hevc_ingest`). FFmpeg never runs here.

use super::*;
use crate::ingest::{FileFormatHint, FileIngestAdapter, FileIngestError, FileIngestRequest};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId, SensorId, StreamId, TimestampNs};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

macro_rules! codec_fixture {
    ($name:literal) => {
        (
            include_bytes!(concat!(
                "../../../../../fss-codec-h265/tests/fixtures/decode/",
                $name,
                ".h265"
            ))
            .as_slice(),
            include_str!(concat!(
                "../../../../../fss-codec-h265/tests/fixtures/decode/",
                $name,
                ".sha256"
            )),
        )
    };
}

/// libx265 preset medium defaults: B pyramid (display order differs from decode order), WPP,
/// SAO and deblocking.
const DEFAULT: (&[u8], &str) = codec_fixture!("f_qcif_default");
/// `open-gop=1:keyint=6`: IDR, trailing pictures, a mid-stream CRA with a RASL picture.
const OPEN_GOP: (&[u8], &str) = codec_fixture!("b_qcif_opengop");
/// IDR then CRA pictures, intra only.
const CRA: (&[u8], &str) = codec_fixture!("i_qcif_cra");
/// FFmpeg framehash of `OPEN_GOP` decoded from the access unit of its CRA (segment 5) onwards.
const OPEN_GOP_FROM_CRA_ORACLE: &str =
    include_str!("../../../../tests/fixtures/hevc_ingest/b_qcif_opengop_from_cra.sha256");
/// Moving-object scene for the watch pipeline (libx265, IDR then P pictures).
const WATCH: (&[u8], &str) = (
    include_bytes!("../../../../tests/fixtures/hevc_ingest/watch_96x48_moving.h265"),
    include_str!("../../../../tests/fixtures/hevc_ingest/watch_96x48_moving.sha256"),
);
const MAIN10: &[u8] =
    include_bytes!("../../../../../fss-codec-h265/tests/fixtures/decode/unsupported_main10.h265");
const YUV422: &[u8] =
    include_bytes!("../../../../../fss-codec-h265/tests/fixtures/decode/unsupported_422.h265");
const REXT_INTRA: &[u8] = include_bytes!(
    "../../../../../fss-codec-h265/tests/fixtures/decode/unsupported_rext_main_intra.h265"
);
/// An H.264 stream (SPS first) for cross-codec refusals.
const H264: &[u8] = include_bytes!("../../../../../fss-packet/tests/fixtures/avc/baseline.264");

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-recorded-h265-{name}-{}-{attempt}",
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
        trace_id: "trace:recorded-h265".to_owned(),
        operation_id: OperationId::parse("operation:recorded-h265")?,
        principal: "principal:recorded-h265".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(4096)
            .build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(b"site:recorded-h265"),
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
    format: String,
    detector_evidence: String,
}

/// Imports through the real file adapter; `hint: None` exercises auto-detection.
fn try_import(
    name: &str,
    bytes: &[u8],
    hint: Option<FileFormatHint>,
) -> TestResult<Result<Imported, FileIngestError>> {
    let directory = OwnedDirectory::new(name)?;
    let root = directory.0.join("deployment");
    let path = directory.0.join("camera.h265");
    fs::write(&path, bytes)?;
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, "site:recorded-h265", &cx)?;
    let mut request = FileIngestRequest::new(
        path.clone(),
        SensorId::parse("sensor:recorded-h265")?,
        StreamId::parse("stream:recorded-h265")?,
    )
    .with_receive_time(TimestampNs(1_000_000_000));
    request.format_hint = hint;
    let receipt = match FileIngestAdapter::ingest(request, &cx, &mut deployment) {
        Ok(receipt) => receipt,
        Err(error) => return Ok(Err(error)),
    };
    // Decoding must depend on retained custody only, never on the original input path.
    fs::remove_file(path)?;
    Ok(Ok(Imported {
        _directory: directory,
        cx,
        deployment,
        identity: receipt.import_identity,
        segments: receipt.manifest.segment_spans.len(),
        format: receipt.manifest.format.clone(),
        detector_evidence: receipt.manifest.detector_evidence.clone(),
    }))
}

fn import(name: &str, bytes: &[u8]) -> TestResult<Imported> {
    Ok(try_import(name, bytes, None)??)
}

fn request(identity: ContentDigest, first: usize, count: usize) -> RecordedH265Request {
    RecordedH265Request {
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
    let mut pictures = decoder.decode_annex_b(stream)?;
    pictures.extend(decoder.finish()?);
    Ok(pictures.iter().map(|p| p.luma().to_vec()).collect())
}

fn whole_range(imported: &Imported) -> Result<Vec<RecordedH265Frame>, RecordedDecodeError> {
    decode_h265_range(
        &imported.deployment,
        request(imported.identity, 0, imported.segments),
        &imported.cx,
    )
}

#[test]
fn auto_detected_hevc_imports_decode_to_the_ffmpeg_oracle_in_display_order() -> TestResult {
    for (name, (stream, oracle_text)) in [
        ("default", DEFAULT),
        ("opengop", OPEN_GOP),
        ("cra", CRA),
        ("watch", WATCH),
    ] {
        let imported = import(name, stream)?;
        // First NAL is a VPS (0x40 0x01): unambiguously H.265, detected without a hint.
        assert_eq!(imported.format, "hevc", "{name}");
        assert_eq!(imported.detector_evidence, "hevc_nal_header", "{name}");
        let expected = oracle(oracle_text);
        // One retained access unit per coded picture.
        assert_eq!(imported.segments, expected.len(), "{name}");
        let direct = direct_luma(stream)?;
        let frames = whole_range(&imported)?;
        assert_eq!(frames.len(), expected.len(), "{name}");
        let mut segments = Vec::new();
        for (position, frame) in frames.iter().enumerate() {
            let receipt = frame.receipt();
            assert_eq!(
                receipt.i420_sha256().to_text(),
                expected[position],
                "{name} {position}"
            );
            assert_eq!(
                frame.pixels(),
                direct[position].as_slice(),
                "{name} {position}"
            );
            assert_eq!(
                receipt.luma_sha256(),
                ContentDigest::sha256(&direct[position])
            );
            // Without skipped pictures, the coding segment is the decode index.
            assert_eq!(receipt.segment_index(), receipt.decode_index());
            assert_eq!(receipt.import_identity(), imported.identity);
            segments.push(receipt.segment_index());
        }
        assert!(frames[0].receipt().is_idr(), "{name}");
        let mut sorted = segments.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..imported.segments as u64).collect::<Vec<_>>());
        if name == "default" {
            assert_ne!(segments, sorted, "B pyramid must reorder output");
        }
        // Deterministic: an independent second decode reproduces every receipt exactly.
        assert_eq!(whole_range(&imported)?, frames, "{name}");
    }
    Ok(())
}

#[test]
fn a_cra_led_range_skips_its_rasl_picture_exactly_as_the_oracle_does() -> TestResult {
    let (stream, full_oracle) = OPEN_GOP;
    let imported = import("cra-range", stream)?;
    let expected = oracle(OPEN_GOP_FROM_CRA_ORACLE);
    assert_eq!(expected.len(), 6);
    // Consistency of the two FFmpeg oracles: the CRA-led decode is the full decode's last six
    // output pictures; the full decode's sixth picture is the RASL picture it skips.
    assert_eq!(expected, oracle(full_oracle)[6..]);
    let mut range = RecordedH265Range::open(
        &imported.deployment,
        request(imported.identity, 5, 7),
        &imported.cx,
    )?;
    let mut frames = Vec::new();
    while let Some(frame) = range.next_frame(&imported.deployment, &imported.cx)? {
        frames.push(frame);
    }
    assert_eq!(range.skipped_rasl_segments(), [6]);
    assert_eq!(range.decoded(), 6);
    let digests: Vec<String> = frames
        .iter()
        .map(|f| f.receipt().i420_sha256().to_text())
        .collect();
    assert_eq!(digests, expected);
    let first = frames[0].receipt();
    assert_eq!(first.segment_index(), 5);
    assert_eq!(first.nal_unit_type(), 21);
    assert!(first.is_irap() && !first.is_idr());
    assert_eq!(first.range_start(), 5);
    let mut segments: Vec<u64> = frames.iter().map(|f| f.receipt().segment_index()).collect();
    segments.sort_unstable();
    assert_eq!(segments, [5, 7, 8, 9, 10, 11]);
    // From the IDR the same RASL picture is decodable and decoded (full oracle, 12 frames).
    assert_eq!(whole_range(&imported)?.len(), 12);
    Ok(())
}

#[test]
fn ranges_starting_at_non_irap_pictures_are_refused() -> TestResult {
    let imported = import("not-irap", OPEN_GOP.0)?;
    // A trailing picture and the RASL picture of the CRA.
    for start in [1, 6] {
        match decode_h265_range(
            &imported.deployment,
            request(imported.identity, start, 2),
            &imported.cx,
        ) {
            Err(error @ RecordedDecodeError::H265RangeNotIrap { segment }) => {
                assert_eq!(segment, start);
                assert_eq!(error.stable_id(), "ERR-DECODE-H265-RANGE-NOT-IRAP-001");
            }
            other => return Err(format!("expected a not-IRAP refusal, got {other:?}").into()),
        }
    }
    assert!(matches!(
        decode_h265_range(
            &imported.deployment,
            request(imported.identity, 5, 8),
            &imported.cx
        ),
        Err(RecordedDecodeError::Unavailable)
    ));
    assert!(matches!(
        decode_h265_range(
            &imported.deployment,
            request(imported.identity, 0, 0),
            &imported.cx
        ),
        Err(RecordedDecodeError::Limit)
    ));
    Ok(())
}

#[test]
fn main10_422_and_range_extension_streams_are_typed_refusals() -> TestResult {
    for (name, stream) in [("main10", MAIN10), ("yuv422", YUV422), ("rext", REXT_INTRA)] {
        let imported = import(name, stream)?;
        assert_eq!(imported.format, "hevc");
        match whole_range(&imported) {
            Err(error @ RecordedDecodeError::H265(H265DecodeError::Unsupported(_))) => {
                assert_eq!(
                    error.stable_id(),
                    "ERR-DECODE-H265-UNSUPPORTED-001",
                    "{name}"
                );
            }
            other => return Err(format!("{name}: expected unsupported, got {other:?}").into()),
        }
    }
    Ok(())
}

#[test]
fn interpretation_and_cross_codec_operations_are_typed_refusals() -> TestResult {
    let imported = import("interpretation", CRA.0)?;
    let mut gray = request(imported.identity, 0, 1);
    gray.interpretation = ComponentInterpretation::Grayscale;
    assert!(matches!(
        decode_h265_range(&imported.deployment, gray, &imported.cx),
        Err(RecordedDecodeError::InterpretationMismatch)
    ));
    // The H.264 range decoder refuses an `hevc` import instead of misreading its NAL headers.
    let h264 = super::super::h264::RecordedH264Request {
        import_identity: imported.identity,
        first_segment: 0,
        segment_count: 1,
        interpretation: ComponentInterpretation::YCbCr,
        read_limits: RetainedReadLimits::default(),
        decoder_limits: super::super::h264::DecoderLimits::default(),
    };
    assert!(matches!(
        super::super::h264::decode_h264_range(&imported.deployment, h264, &imported.cx),
        Err(RecordedDecodeError::UnsupportedMedia)
    ));
    // And the H.265 range decoder refuses an H.264 import.
    let avc = import("avc", H264)?;
    assert_eq!(avc.format, "annexb");
    assert!(matches!(
        decode_h265_range(&avc.deployment, request(avc.identity, 0, 1), &avc.cx),
        Err(RecordedDecodeError::UnsupportedMedia)
    ));
    Ok(())
}

#[test]
fn truncated_slice_is_a_typed_refusal_after_earlier_frames() -> TestResult {
    // Cut the final picture's slice in half: custody retains the bytes as recorded, the codec
    // must refuse the damaged picture rather than conceal it.
    let (stream, _) = CRA;
    let last_nal = stream
        .windows(3)
        .rposition(|w| w == [0, 0, 1])
        .ok_or("fixture has no start code")?;
    let truncated = &stream[..last_nal + (stream.len() - last_nal) / 2];
    let imported = import("truncated", truncated)?;
    assert_eq!(imported.segments, 3);
    let mut range = RecordedH265Range::open(
        &imported.deployment,
        request(imported.identity, 0, 3),
        &imported.cx,
    )?;
    let mut returned = 0;
    let error = loop {
        match range.next_frame(&imported.deployment, &imported.cx) {
            Ok(Some(_)) => returned += 1,
            Ok(None) => return Err("a truncated slice must not decode".into()),
            Err(error) => break error,
        }
    };
    assert!(
        matches!(
            error,
            RecordedDecodeError::H265(_) | RecordedDecodeError::H265AccessUnit { segment: 2 }
        ),
        "{error:?}"
    );
    assert_eq!(returned, 2);
    assert_eq!(range.decoded(), 2);
    Ok(())
}

/// A stream whose first NAL header is valid in both codecs: `28 01` is an H.265 IDR_N_LP slice
/// header and an H.264 PPS header (`nal_ref_idc` 1, type 8).
fn ambiguous_stream() -> Vec<u8> {
    vec![0, 0, 0, 1, 0x28, 0x01, 0xaf, 0x0b, 0xe0, 0x14, 0x80]
}

#[test]
fn ambiguous_streams_are_refused_until_the_codec_is_declared() -> TestResult {
    match try_import("ambiguous", &ambiguous_stream(), None)? {
        Err(error @ FileIngestError::AmbiguousAnnexBCodec { first_nal_header }) => {
            assert_eq!(first_nal_header, [0x28, 0x01]);
            assert_eq!(error.stable_id(), Some("ERR-INGEST-FORMAT-AMBIGUOUS-001"));
        }
        Err(other) => return Err(format!("expected an ambiguity refusal, got {other:?}").into()),
        Ok(_) => return Err("an ambiguous stream must not be imported by guess".into()),
    }
    // Declared H.265: split by H.265 rules (one IDR_N_LP access unit) and recorded as such.
    let declared = try_import(
        "declared-hevc",
        &ambiguous_stream(),
        Some(FileFormatHint::Hevc),
    )??;
    assert_eq!(declared.format, "hevc");
    assert_eq!(
        declared.detector_evidence,
        "annexb_start_code:operator_declared_hevc"
    );
    assert_eq!(declared.segments, 1);
    // It carries no parameter sets, so the retained segment is marked undecodable (a gap) and
    // the codec refuses it; nothing is concealed.
    assert!(whole_range(&declared).is_err());
    // Declared H.264: the existing Annex-B path, unchanged.
    let avc = try_import(
        "declared-avc",
        &ambiguous_stream(),
        Some(FileFormatHint::AnnexB),
    )??;
    assert_eq!(avc.format, "annexb");
    Ok(())
}

#[test]
fn contradictory_hints_and_garbage_hevc_streams_are_refused() -> TestResult {
    // An H.264 stream declared H.265, and an H.265 stream declared H.264.
    for (name, stream, hint, detected) in [
        ("h264-as-hevc", H264, FileFormatHint::Hevc, "annexb"),
        ("hevc-as-h264", CRA.0, FileFormatHint::AnnexB, "hevc"),
    ] {
        match try_import(name, stream, Some(hint))? {
            Err(
                error @ FileIngestError::FormatConflict {
                    detected: found, ..
                },
            ) => {
                assert_eq!(found.as_str(), detected, "{name}");
                assert_eq!(error.stable_id(), Some("ERR-INGEST-FORMAT-CONFLICT-001"));
            }
            Err(other) => return Err(format!("{name}: expected a conflict, got {other:?}").into()),
            Ok(_) => return Err(format!("{name}: contradictory hint accepted").into()),
        }
    }
    // Declared H.265 but not H.265: nuh_temporal_id_plus1 0, then parameter sets only.
    let zero_temporal_id = [0, 0, 1, 0x26, 0x00, 0xaf, 0x33];
    let parameters_only = [0, 0, 1, 0x40, 0x01, 0x0c, 0, 0, 1, 0x42, 0x01, 0x01];
    for (name, stream, expected) in [
        (
            "zero-tid",
            zero_temporal_id.as_slice(),
            crate::ingest::AnnexBError::InvalidHevcNalHeader { nal: 0, offset: 3 },
        ),
        (
            "no-picture",
            parameters_only.as_slice(),
            crate::ingest::AnnexBError::NoHevcPicture,
        ),
    ] {
        match try_import(name, stream, Some(FileFormatHint::Hevc))? {
            Err(FileIngestError::AnnexB(error)) => assert_eq!(error, expected, "{name}"),
            Err(other) => return Err(format!("{name}: unexpected {other:?}").into()),
            Ok(_) => return Err(format!("{name}: garbage imported").into()),
        }
    }
    // Bytes without any start code are not media at all.
    assert!(matches!(
        try_import("garbage", b"not a video stream", Some(FileFormatHint::Hevc))?,
        Err(FileIngestError::UnknownFormat { .. })
    ));
    Ok(())
}
