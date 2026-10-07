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
/// High profile with B frames and the 8x8 transform (display order differs from decode order).
const HIGH: &[u8] = include_bytes!("../../../../../fss-packet/tests/fixtures/avc/high_cropped.264");
/// FFmpeg `yuv420p` framehash of `HIGH` in output order, produced offline by the sealed oracle.
const HIGH_ORACLE: &str = include_str!(
    "../../../../../fss-codec-h264/tests/fixtures/decode/fss_packet_high_cropped.sha256"
);
/// High 4:2:2 (libx264 `-profile:v high422 -pix_fmt yuv422p`): chroma format outside the tool set.
const HIGH_422: &[u8] =
    include_bytes!("../../../../../fss-codec-h264/tests/fixtures/decode/unsupported_high422.h264");

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
    let mut pictures = decoder.decode_annex_b(stream)?;
    pictures.extend(decoder.finish()?);
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
fn high_profile_b_frames_come_out_in_display_order_bound_to_their_coding_segments() -> TestResult {
    let imported = import("high", HIGH)?;
    let expected = oracle(HIGH_ORACLE);
    let direct = direct_luma(HIGH)?;
    assert_eq!(expected.len(), imported.segments);
    let frames = decode_h264_range(
        &imported.deployment,
        request(imported.identity, 0, imported.segments),
        &imported.cx,
    )?;
    assert_eq!(frames.len(), imported.segments);
    let mut segments = Vec::new();
    for (position, frame) in frames.iter().enumerate() {
        let receipt = frame.receipt();
        assert_eq!(receipt.i420_sha256().to_text(), expected[position]);
        assert_eq!(frame.pixels(), direct[position].as_slice());
        // Each picture is bound to the access unit that coded it: segment = decode index.
        assert_eq!(receipt.segment_index(), receipt.decode_index());
        segments.push(receipt.segment_index());
    }
    assert!(frames[0].receipt().is_idr());
    // B frames: output order is not decode order, and every segment is used exactly once.
    let mut sorted = segments.clone();
    sorted.sort_unstable();
    assert_ne!(segments, sorted, "fixture must exercise reordering");
    assert_eq!(sorted, (0..imported.segments as u64).collect::<Vec<_>>());
    let again = decode_h264_range(
        &imported.deployment,
        request(imported.identity, 0, imported.segments),
        &imported.cx,
    )?;
    assert_eq!(again, frames);
    Ok(())
}

#[test]
fn unsupported_chroma_format_is_refused_not_decoded() -> TestResult {
    let imported = import("high422", HIGH_422)?;
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

/// The exposed Y, Cb and Cr planes reassemble FFmpeg's `yuv420p` frame (the committed oracle
/// digest), the receipt's per-plane digests match them, and RGB follows the declared transform
/// with nearest-cell chroma at every sampled pixel.
fn assert_chroma(
    [luma, cb, cr]: [&[u8]; 3],
    dimensions: [u32; 2],
    chroma: [u32; 2],
    digests: [ContentDigest; 2],
    rgb: &[u8],
    oracle: &str,
) {
    let [width, height] = dimensions.map(|v| v as usize);
    assert_eq!(
        chroma,
        [width.div_ceil(2) as u32, height.div_ceil(2) as u32]
    );
    let plane = (chroma[0] * chroma[1]) as usize;
    assert_eq!((cb.len(), cr.len()), (plane, plane));
    let mut i420 = luma.to_vec();
    i420.extend_from_slice(cb);
    i420.extend_from_slice(cr);
    assert_eq!(ContentDigest::sha256(&i420).to_text(), oracle);
    assert_eq!(
        digests,
        [ContentDigest::sha256(cb), ContentDigest::sha256(cr)]
    );
    assert_eq!(rgb.len(), width * height * 3);
    for index in (0..width * height).step_by(37) {
        let (x, y) = (index % width, index / width);
        let c = (y / 2) * chroma[0] as usize + x / 2;
        assert_eq!(
            &rgb[index * 3..index * 3 + 3],
            &super::super::video_rgb::ycbcr_limited_to_rgb(luma[index], cb[c], cr[c]),
            "pixel ({x}, {y})"
        );
    }
}

#[test]
fn chroma_planes_reassemble_the_ffmpeg_yuv420p_oracle_and_convert_to_rgb() -> TestResult {
    for (name, stream, oracle_text) in [
        ("chroma-baseline", BASELINE, BASELINE_ORACLE),
        ("chroma-high", HIGH, HIGH_ORACLE),
    ] {
        let imported = import(name, stream)?;
        let expected = oracle(oracle_text);
        let frames = decode_h264_range(
            &imported.deployment,
            request(imported.identity, 0, imported.segments),
            &imported.cx,
        )?;
        assert_eq!(frames.len(), expected.len(), "{name}");
        for (position, frame) in frames.iter().enumerate() {
            let receipt = frame.receipt();
            assert_chroma(
                [frame.pixels(), frame.cb(), frame.cr()],
                receipt.dimensions(),
                frame.chroma_dimensions(),
                [receipt.cb_sha256(), receipt.cr_sha256()],
                &frame.to_rgb()?,
                &expected[position],
            );
        }
    }
    Ok(())
}

/// Indexed MP4, `moov` first: the same ten frames, two IDRs, B-picture reordering.
const MP4_FASTSTART: &[u8] =
    include_bytes!("../../../../../fss-container/tests/fixtures/indexed_avc.mp4");
/// The same video interleaved with an AAC track in `mdat`, `moov` last.
const MP4_INTERLEAVED: &[u8] =
    include_bytes!("../../../../../fss-container/tests/fixtures/interleaved_av.mp4");
/// The same video and audio as fragmented MP4 (`moof`/`trun`, `iso5`), two fragments.
const MP4_FRAGMENTED: &[u8] =
    include_bytes!("../../../../../fss-container/tests/fixtures/fragmented_av.mp4");
/// The same video and audio as a QuickTime movie (`qt  ` brand, `mhlr` handlers).
const MOV: &[u8] = include_bytes!("../../../../../fss-container/tests/fixtures/qt_av.mov");
/// FFmpeg `yuv420p` framehash of the MP4 fixtures' video track, in presentation order.
const MP4_ORACLE: &str =
    include_str!("../../../../../fss-container/tests/fixtures/indexed_avc_i420.sha256");

/// `interleaved_av.mp4` remuxed by FFmpeg into Matroska (`-c copy`), seekable (known sizes,
/// Cues) and live (unknown Segment size, written to a pipe).
const MKV: &[u8] = include_bytes!("../../../../../fss-container/tests/fixtures/avc_av.mkv");
const MKV_LIVE: &[u8] = include_bytes!("../../../../../fss-container/tests/fixtures/avc_live.mkv");

fn import_as(name: &str, bytes: &[u8], hint: Option<FileFormatHint>) -> TestResult<Imported> {
    let directory = OwnedDirectory::new(name)?;
    let root = directory.0.join("deployment");
    let path = directory.0.join("camera.media");
    fs::write(&path, bytes)?;
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, "site:recorded-h264", &cx)?;
    let mut request = FileIngestRequest::new(
        path.clone(),
        SensorId::parse("sensor:recorded-h264")?,
        StreamId::parse("stream:recorded-h264")?,
    )
    .with_receive_time(TimestampNs(1_000_000_000));
    request.format_hint = hint;
    let receipt = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;
    fs::remove_file(path)?;
    Ok(Imported {
        _directory: directory,
        cx,
        deployment,
        identity: receipt.import_identity,
        segments: receipt.manifest.segment_spans.len(),
    })
}

fn i420_digests(imported: &Imported, first: usize, count: usize) -> TestResult<Vec<String>> {
    Ok(decode_h264_range(
        &imported.deployment,
        request(imported.identity, first, count),
        &imported.cx,
    )?
    .iter()
    .map(|frame| frame.receipt().i420_sha256().to_text())
    .collect())
}

#[test]
fn retained_mp4_samples_decode_bit_exact_against_the_ffmpeg_oracle() -> TestResult {
    let expected = oracle(MP4_ORACLE);
    assert_eq!(expected.len(), 10);
    for (name, bytes) in [
        ("mp4-faststart", MP4_FASTSTART),
        ("mp4-interleaved", MP4_INTERLEAVED),
        ("mp4-fragmented", MP4_FRAGMENTED),
        ("mp4-quicktime", MOV),
    ] {
        // Sniffed without a hint: the ftyp box selects the MP4 path.
        let imported = import_as(name, bytes, None)?;
        assert_eq!(imported.segments, 10);
        let retained = RetainedFileImport::open(
            &imported.deployment,
            imported.identity,
            RetainedReadLimits::default(),
            &imported.cx,
        )?;
        let manifest = retained.manifest();
        assert_eq!(manifest.format, "mp4avc");
        assert_eq!(manifest.detector_evidence, "mp4_ftyp");
        // Every byte is a sample or typed structure; no sample follows a source gap.
        assert!(manifest.segment_spans.iter().all(|span| !span.gap_before));
        assert!(
            manifest
                .omission_spans
                .iter()
                .all(|span| span.is_container_structure())
        );
        let accounted: u64 = manifest
            .segment_spans
            .iter()
            .map(|span| span.len)
            .sum::<u64>()
            + manifest
                .omission_spans
                .iter()
                .map(|span| span.len)
                .sum::<u64>();
        assert_eq!(accounted, bytes.len() as u64);
        let parameter_sets = manifest
            .omission_spans
            .iter()
            .filter(|span| span.reason == "mp4_avc_parameter_set:nal_length_bytes=4")
            .count();
        assert_eq!(parameter_sets, 2);
        // Each segment is the sample's exact original length-prefixed bytes.
        for (index, span) in manifest.segment_spans.iter().enumerate() {
            let segment = retained.read_segment(
                &imported.deployment,
                index,
                RetainedReadLimits::default(),
                &imported.cx,
            )?;
            let range = span.offset as usize..(span.offset + span.len) as usize;
            assert_eq!(segment.as_slice(), &bytes[range]);
        }
        let frames = decode_h264_range(
            &imported.deployment,
            request(imported.identity, 0, 10),
            &imported.cx,
        )?;
        assert_eq!(frames.len(), 10);
        for (index, frame) in frames.iter().enumerate() {
            assert_eq!(frame.receipt().i420_sha256().to_text(), expected[index]);
            assert_eq!(frame.receipt().dimensions(), [64, 48]);
        }
        // Display order: decode indexes of a two-B-frame GOP map back to their samples.
        let idr: Vec<bool> = frames.iter().map(|f| f.receipt().is_idr()).collect();
        assert_eq!(idr.iter().filter(|idr| **idr).count(), 2);
        assert!(idr[0]);
        // The second GOP is independently decodable from its IDR sample.
        assert_eq!(i420_digests(&imported, 5, 5)?, expected[5..].to_vec());
    }
    Ok(())
}

#[test]
fn mp4_and_its_annexb_extraction_decode_to_identical_frames() -> TestResult {
    let parsed = fss_container::demux::AvcMp4::parse(
        MP4_INTERLEAVED,
        None,
        fss_container::demux::DemuxLimits::default(),
    )?;
    let extraction = parsed.annex_b(0, 10)?;
    let annexb = import_as(
        "mp4-extraction",
        extraction.bytes(),
        Some(FileFormatHint::AnnexB),
    )?;
    let mp4 = import_as(
        "mp4-original",
        MP4_INTERLEAVED,
        Some(FileFormatHint::Mp4Avc),
    )?;
    assert_eq!(annexb.segments, mp4.segments);
    assert_eq!(i420_digests(&annexb, 0, 10)?, i420_digests(&mp4, 0, 10)?);
    Ok(())
}

#[test]
fn mp4_ranges_refuse_predicted_starts_and_damaged_or_mislabelled_files() -> TestResult {
    let imported = import_as("mp4-refusals", MP4_FASTSTART, Some(FileFormatHint::Mp4Avc))?;
    for start in [1, 2, 3, 4, 6] {
        match decode_h264_range(
            &imported.deployment,
            request(imported.identity, start, 1),
            &imported.cx,
        ) {
            Err(RecordedDecodeError::H264RangeNotIdr { segment }) => assert_eq!(segment, start),
            other => return Err(format!("expected a not-IDR refusal, got {other:?}").into()),
        }
    }
    // A truncated file is refused by the demuxer, whole, with a stable identity.
    let directory = OwnedDirectory::new("mp4-truncated")?;
    let root = directory.0.join("deployment");
    let path = directory.0.join("camera.mp4");
    fs::write(&path, &MP4_FASTSTART[..MP4_FASTSTART.len() - 7])?;
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, "site:recorded-h264", &cx)?;
    let request = FileIngestRequest::new(
        path.clone(),
        SensorId::parse("sensor:recorded-h264")?,
        StreamId::parse("stream:recorded-h264")?,
    )
    .with_receive_time(TimestampNs(1_000_000_000));
    match FileIngestAdapter::ingest(request.clone(), &cx, &mut deployment) {
        Err(error @ crate::ingest::FileIngestError::Mp4Refused { .. }) => {
            assert_eq!(error.stable_id(), Some("ERR-INGEST-MP4-REFUSED-001"));
        }
        other => return Err(format!("expected an MP4 refusal, got {other:?}").into()),
    }
    // Declaring Annex-B for an MP4 file is a conflict, never a reinterpretation.
    fs::write(&path, MP4_FASTSTART)?;
    match FileIngestAdapter::ingest(
        request.with_format_hint(FileFormatHint::AnnexB),
        &cx,
        &mut deployment,
    ) {
        Err(error @ crate::ingest::FileIngestError::FormatConflict { .. }) => {
            assert_eq!(error.stable_id(), Some("ERR-INGEST-FORMAT-CONFLICT-001"));
        }
        other => return Err(format!("expected a format conflict, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn mp4_capture_hints_follow_container_presentation_times() -> TestResult {
    let directory = OwnedDirectory::new("mp4-capture")?;
    let root = directory.0.join("deployment");
    let path = directory.0.join("camera.mp4");
    fs::write(&path, MP4_FASTSTART)?;
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, "site:recorded-h264", &cx)?;
    let start = 100_000_000_000_i128;
    let mut ingest = FileIngestRequest::new(
        path,
        SensorId::parse("sensor:recorded-h264")?,
        StreamId::parse("stream:recorded-h264")?,
    )
    .with_receive_time(TimestampNs(1_000_000_000_000));
    // The assumed rate (deliberately wrong) is not used for MP4 timing.
    ingest.capture_hint = Some(crate::ingest::CaptureHint::new(
        TimestampNs(start),
        1_000_000,
        7.0,
    )?);
    let receipt = FileIngestAdapter::ingest(ingest, &cx, &mut deployment)?;
    let frames = decode_h264_range(&deployment, request(receipt.import_identity, 0, 10), &cx)?;
    // Ten frames at 5 fps on a 10240 Hz media clock: display index k is 200 ms * k after start,
    // whatever its decode (segment) position.
    for (display, frame) in frames.iter().enumerate() {
        let capture = frame.receipt().capsule().capture;
        let centre = start + display as i128 * 200_000_000;
        assert_eq!(capture.earliest.0, centre - 1_000_000);
        assert_eq!(capture.latest.0, centre + 1_000_000);
    }
    // B-frame reordering: decode order differs from display order here.
    let segments: Vec<u64> = frames.iter().map(|f| f.receipt().segment_index()).collect();
    assert_ne!(segments, (0..10).collect::<Vec<u64>>());
    Ok(())
}

#[test]
fn lazily_sealed_receipts_are_identical_and_do_not_affect_equality() -> TestResult {
    let imported = import("lazy-receipt", BASELINE)?;
    let expected = oracle(BASELINE_ORACLE);
    let unread = decode_h264_range(
        &imported.deployment,
        request(imported.identity, 0, 4),
        &imported.cx,
    )?;
    let read = decode_h264_range(
        &imported.deployment,
        request(imported.identity, 0, 4),
        &imported.cx,
    )?;
    for (index, frame) in read.iter().enumerate() {
        // Sealing one copy's receipt changes neither equality nor any digest.
        assert_eq!(frame.receipt().i420_sha256().to_text(), expected[index]);
        assert_eq!(frame, &unread[index]);
        assert_eq!(frame.segment_index(), frame.receipt().segment_index());
        assert_eq!(frame.dimensions(), frame.receipt().dimensions());
        assert_eq!(frame.capsule_digest(), frame.receipt().capsule_digest());
        assert_eq!(
            frame.receipt().luma_sha256(),
            ContentDigest::sha256(frame.pixels())
        );
        assert_eq!(frame.receipt().digest(), unread[index].receipt().digest());
    }
    Ok(())
}

#[test]
fn retained_matroska_frames_decode_bit_exact_and_tile_the_file() -> TestResult {
    let expected = oracle(MP4_ORACLE);
    for (name, bytes) in [("mkv-seekable", MKV), ("mkv-live", MKV_LIVE)] {
        // Sniffed without a hint: the EBML header selects the Matroska path.
        let imported = import_as(name, bytes, None)?;
        assert_eq!(imported.segments, 10);
        let retained = RetainedFileImport::open(
            &imported.deployment,
            imported.identity,
            RetainedReadLimits::default(),
            &imported.cx,
        )?;
        let manifest = retained.manifest();
        assert_eq!(manifest.format, "mkvavc");
        assert_eq!(manifest.detector_evidence, "ebml_header");
        assert!(manifest.segment_spans.iter().all(|span| !span.gap_before));
        assert!(
            manifest
                .omission_spans
                .iter()
                .all(|span| { span.is_container_structure() && span.reason.starts_with("mkv_") })
        );
        let accounted: u64 = manifest
            .segment_spans
            .iter()
            .map(|span| span.len)
            .sum::<u64>()
            + manifest
                .omission_spans
                .iter()
                .map(|span| span.len)
                .sum::<u64>();
        assert_eq!(accounted, bytes.len() as u64);
        assert_eq!(
            manifest
                .omission_spans
                .iter()
                .filter(|span| span.reason == "mkv_avc_parameter_set:nal_length_bytes=4")
                .count(),
            2
        );
        assert!(
            manifest
                .omission_spans
                .iter()
                .any(|span| span.reason == "mkv_element:cluster")
        );
        assert_eq!(i420_digests(&imported, 0, 10)?, expected);
        assert_eq!(i420_digests(&imported, 5, 5)?, expected[5..].to_vec());
    }
    // The Matroska frames are the MP4 samples' exact bytes, so their decodes are identical.
    let mp4 = import_as("mkv-mp4-twin", MP4_INTERLEAVED, None)?;
    let mkv = import_as("mkv-twin", MKV, Some(FileFormatHint::MkvAvc))?;
    assert_eq!(i420_digests(&mp4, 0, 10)?, i420_digests(&mkv, 0, 10)?);
    Ok(())
}

#[test]
fn matroska_capture_hints_follow_block_timestamps_and_damage_is_refused_whole() -> TestResult {
    let directory = OwnedDirectory::new("mkv-capture")?;
    let root = directory.0.join("deployment");
    let path = directory.0.join("camera.mkv");
    fs::write(&path, MKV)?;
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, "site:recorded-h264", &cx)?;
    let start = 100_000_000_000_i128;
    let mut ingest = FileIngestRequest::new(
        path.clone(),
        SensorId::parse("sensor:recorded-h264")?,
        StreamId::parse("stream:recorded-h264")?,
    )
    .with_receive_time(TimestampNs(1_000_000_000_000));
    ingest.capture_hint = Some(crate::ingest::CaptureHint::new(
        TimestampNs(start),
        1_000_000,
        7.0,
    )?);
    let receipt = FileIngestAdapter::ingest(ingest.clone(), &cx, &mut deployment)?;
    let frames = decode_h264_range(&deployment, request(receipt.import_identity, 0, 10), &cx)?;
    // Millisecond block timestamps 200 ms apart in display order, the earliest at the start.
    for (display, frame) in frames.iter().enumerate() {
        let capture = frame.receipt().capsule().capture;
        let centre = start + display as i128 * 200_000_000;
        assert_eq!(capture.earliest.0, centre - 1_000_000);
        assert_eq!(capture.latest.0, centre + 1_000_000);
    }
    // A damaged cluster (CRC-32 mismatch) is refused whole with a stable identity.
    let mut damaged = MKV.to_vec();
    let middle = damaged.len() / 2;
    damaged[middle] ^= 0x40;
    fs::write(&path, &damaged)?;
    match FileIngestAdapter::ingest(ingest.clone(), &cx, &mut deployment) {
        Err(error @ crate::ingest::FileIngestError::MatroskaRefused { .. }) => {
            assert_eq!(error.stable_id(), Some("ERR-INGEST-MKV-REFUSED-001"));
        }
        other => return Err(format!("expected a Matroska refusal, got {other:?}").into()),
    }
    // Declaring MP4 for a Matroska file is a conflict, never a reinterpretation.
    fs::write(&path, MKV)?;
    match FileIngestAdapter::ingest(
        ingest.with_format_hint(FileFormatHint::Mp4Avc),
        &cx,
        &mut deployment,
    ) {
        Err(error @ crate::ingest::FileIngestError::FormatConflict { .. }) => {
            assert_eq!(error.stable_id(), Some("ERR-INGEST-FORMAT-CONFLICT-001"));
        }
        other => return Err(format!("expected a format conflict, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn recordings_cut_by_their_writer_keep_complete_frames_and_record_the_lost_tail() -> TestResult {
    let expected = oracle(MP4_ORACLE);
    // A live Matroska recording cut inside its third Cluster (power loss): its first two
    // CRC-bound Clusters (nine frames) survive. A fragmented MP4 cut inside its second fragment:
    // the first fragment (five frames) survives.
    for (name, bytes, cut, frames) in [
        ("cut-mkv", MKV_LIVE, 5_400, 9),
        ("cut-fmp4", MP4_FRAGMENTED, 6_000, 5),
    ] {
        let imported = import_as(name, &bytes[..cut], None)?;
        assert_eq!(imported.segments, frames);
        let retained = RetainedFileImport::open(
            &imported.deployment,
            imported.identity,
            RetainedReadLimits::default(),
            &imported.cx,
        )?;
        let manifest = retained.manifest();
        let lost: Vec<_> = manifest
            .omission_spans
            .iter()
            .filter(|span| !span.is_container_structure())
            .collect();
        assert_eq!(lost.len(), 1);
        assert_eq!(
            lost[0].reason,
            crate::ingest::CONTAINER_TRUNCATED_TAIL_REASON
        );
        assert_eq!(lost[0].offset + lost[0].len, cut as u64);
        let last = &manifest.segment_spans[frames - 1];
        assert!(last.offset + last.len <= lost[0].offset);
        // Every complete frame decodes exactly as in the whole recording.
        assert_eq!(
            i420_digests(&imported, 0, frames)?,
            expected[..frames].to_vec()
        );
    }
    Ok(())
}
