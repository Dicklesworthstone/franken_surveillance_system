#![forbid(unsafe_code)]
//! Real retained movies: exact selected occurrences, native pixels, bounds and private output.

use super::{OwnedDirectory, TestResult, command, field, success};
use fss_codec_jpeg_encode::{EncodeBudget, EncodeConfig, EncodeLimits, PixelFormat, encode_jpeg};
use fss_container::demux::{AvcMp4, DemuxLimits, VideoCodec};
use fss_container::matroska_gray::{GrayMatroskaConfig, PlaybackRate};
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec, SensorId,
};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_reference::{ReferenceDeployment, ReplayCx};
use std::collections::BTreeMap;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const AVC: &[u8] = include_bytes!("../../../fss-container/tests/fixtures/indexed_avc.mp4");
const HEVC: &[u8] = include_bytes!("../../../fss-container/tests/fixtures/hevc_av.mp4");
const SITE: &str = "site:media-cli";

struct Movie {
    directory: OwnedDirectory,
    root: PathBuf,
    identity: String,
}

impl Movie {
    fn import(label: &str, source: &[u8]) -> TestResult<Self> {
        let directory = OwnedDirectory::new(label)?;
        let root = directory.0.join("deployment");
        let path = directory.0.join("original.mp4");
        fs::write(&path, source)?;
        let output = command(&root, "import")
            .arg("--input")
            .arg(&path)
            .args([
                "--sensor",
                "sensor:media-cli",
                "--stream",
                "stream:media-cli",
                "--receive-time-ns",
                "1000000000",
            ])
            .output()?;
        success(&output);
        let identity = field(&output, "import_identity")?;
        // Every subsequent process must recover the original from retained custody.
        fs::remove_file(path)?;
        Ok(Self {
            directory,
            root,
            identity,
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.0.join(name)
    }

    fn export(&self, query: Range<u64>, format: &str, path: &Path) -> Command {
        let mut result = command(&self.root, "export-movie");
        result
            .args([
                "--import-id",
                &self.identity,
                "--start-movie-tick",
                &query.start.to_string(),
                "--end-movie-tick",
                &query.end.to_string(),
                "--interpretation",
                "ycbcr",
                "--max-dimension",
                "64",
                "--max-pixels",
                "4096",
                "--output-format",
                format,
            ])
            .arg("--output")
            .arg(path);
        if format == "mjpeg" {
            result.args(["--jpeg-quality", "85"]);
        }
        if format == "gray-mkv" {
            result.args(["--output-rate", "30000/1001"]);
        }
        result
    }

    fn journals(&self) -> TestResult<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(self.root.join("ledger/journal.fssj"))?,
            fs::read(self.root.join("effects/journal.fssj"))?,
        ))
    }
}

#[derive(Clone)]
struct Image {
    dimensions: [u32; 2],
    pixels: Vec<u8>,
}

/// Decode the complete original directly with the native codec, independent of the new
/// movie-export planner/cache and its retained range adapter. Selection expectations below
/// are fixed source indices, not copied from the implementation's selection report.
fn native_images(source: &[u8]) -> TestResult<BTreeMap<usize, Image>> {
    let movie = AvcMp4::parse(source, None, DemuxLimits::default())?;
    let elementary = movie.annex_b(0, movie.samples().len())?;
    let mut images = BTreeMap::new();
    match movie.codec() {
        VideoCodec::Avc => {
            let mut decoder = fss_codec_h264::Decoder::new(Default::default())?;
            let mut pictures = decoder.decode_annex_b(elementary.bytes())?;
            pictures.extend(decoder.finish()?);
            for picture in pictures {
                let previous = images.insert(
                    usize::try_from(picture.decode_index())?,
                    Image {
                        dimensions: [picture.width(), picture.height()],
                        pixels: picture.luma().to_vec(),
                    },
                );
                assert!(previous.is_none(), "duplicate source picture in fixture");
            }
        }
        VideoCodec::Hevc => {
            let mut decoder = fss_codec_h265::Decoder::new(Default::default())?;
            let mut pictures = decoder.decode_annex_b(elementary.bytes())?;
            pictures.extend(decoder.finish()?);
            for picture in pictures {
                let previous = images.insert(
                    usize::try_from(picture.decode_index())?,
                    Image {
                        dimensions: [picture.width(), picture.height()],
                        pixels: picture.luma().to_vec(),
                    },
                );
                assert!(previous.is_none(), "duplicate source picture in fixture");
            }
        }
    }
    assert_eq!(images.len(), movie.samples().len());
    assert!(images.values().all(|image| image.dimensions == [64, 48]));
    Ok(images)
}

fn selected(images: &BTreeMap<usize, Image>, indices: &[usize]) -> TestResult<Vec<Image>> {
    indices
        .iter()
        .map(|index| {
            images
                .get(index)
                .cloned()
                .ok_or_else(|| "missing fixture picture".into())
        })
        .collect()
}

fn rendered(format: &str, images: &[Image]) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut budget = EncodeBudget::new(100_000_000);
    for (ordinal, image) in images.iter().enumerate() {
        let [width, height] = image.dimensions;
        match format {
            "pgm" => {
                bytes.extend_from_slice(format!("P5\n{width} {height}\n255\n").as_bytes());
                bytes.extend_from_slice(&image.pixels);
            }
            "mjpeg" => bytes.extend_from_slice(
                encode_jpeg(
                    width,
                    height,
                    &image.pixels,
                    ContentDigest::sha256(&image.pixels).bytes(),
                    EncodeConfig {
                        quality: 85,
                        format: PixelFormat::Grayscale,
                    },
                    &EncodeLimits::default(),
                    &mut budget,
                )?
                .bytes(),
            ),
            "gray-mkv" => {
                let config =
                    GrayMatroskaConfig::new(image.dimensions, PlaybackRate::new(30_000, 1001)?)?;
                if ordinal == 0 {
                    bytes.extend_from_slice(config.initialization()?.bytes());
                }
                bytes.extend_from_slice(config.frame(ordinal as u64)?.prefix());
                bytes.extend_from_slice(&image.pixels);
            }
            _ => return Err("unknown test format".into()),
        }
    }
    Ok(bytes)
}

fn values(output: &Output, name: &str) -> TestResult<Vec<String>> {
    let prefix = format!("{name}=");
    Ok(std::str::from_utf8(&output.stdout)?
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix).map(str::to_owned))
        .collect())
}

fn incomplete(output: &Output) -> TestResult {
    assert!(!output.status.success());
    let text = std::str::from_utf8(&output.stdout)?;
    for marker in [
        "movie_export_complete=true",
        "selection_media_exported=true",
        "pgm_sha256=",
        "mjpeg_sha256=",
        "gray_mkv_sha256=",
        "mjpeg_frame_receipts_sha256=",
        "gray_mkv_frame_receipts_sha256=",
        "mjpeg_export_complete=true",
        "gray_mkv_export_complete=true",
    ] {
        assert!(
            !text.contains(marker),
            "failed export certified {marker}: {text}"
        );
    }
    Ok(())
}

#[test]
fn movie_export_selects_b_pictures_in_movie_order_in_all_three_formats() -> TestResult {
    let movie = Movie::import("movie-export-formats", AVC)?;
    let images = selected(&native_images(AVC)?, &[3, 1])?;
    assert_ne!(images[0].pixels, images[1].pixels);
    let cache_bytes = images.iter().map(|image| image.pixels.len()).sum::<usize>();
    let before = movie.journals()?;
    let mut receipts = None;
    for format in ["pgm", "mjpeg", "gray-mkv"] {
        let expected = rendered(format, &images)?;
        let path = movie.path(&format!("selected.{format}"));
        let output = movie
            .export(400..800, format, &path)
            .args([
                "--max-output-bytes",
                &expected.len().to_string(),
                "--max-cached-luma-bytes",
                &cache_bytes.to_string(),
            ])
            .output()?;
        success(&output);
        assert_eq!(fs::read(&path)?, expected);
        assert_eq!(field(&output, "movie_export_complete")?, "true");
        assert_eq!(field(&output, "selection_media_exported")?, "true");
        assert_eq!(field(&output, "movie_output_frames")?, "2");
        assert_eq!(field(&output, "movie_cached_frames")?, "2");
        assert_eq!(
            field(&output, "movie_cached_luma_bytes")?.parse::<usize>()?,
            cache_bytes
        );
        assert_eq!(field(&output, "movie_decoded_frames")?, "4");
        assert_eq!(values(&output, "frame_segment")?, ["3", "1"]);
        assert_eq!(values(&output, "movie_output_index")?, ["0", "1"]);
        let current_receipts = values(&output, "frame_receipt_digest")?;
        assert_eq!(current_receipts.len(), 2);
        if let Some(previous) = &receipts {
            assert_eq!(previous, &current_receipts);
        }
        receipts = Some(current_receipts);
        let rows = values(&output, "movie_sample")?;
        assert_eq!(rows.len(), 2);
        assert!(rows[0].contains("segment=3 "));
        assert!(rows[1].contains("segment=1 "));
        assert!(rows[0].contains("movie_interval=4096000/10240,6144000/10240"));
        assert!(rows[1].contains("movie_interval=6144000/10240,8192000/10240"));
        let prefix = if format == "gray-mkv" {
            "gray_mkv"
        } else {
            format
        };
        assert_eq!(
            field(&output, &format!("{prefix}_sha256"))?,
            ContentDigest::sha256(&expected).to_text()
        );
        assert_eq!(field(&output, &format!("{prefix}_frames"))?, "2");
        if format == "gray-mkv" {
            assert_eq!(
                field(&output, "gray_mkv_timing")?,
                "operator_requested_uniform_rate"
            );
            assert_eq!(
                field(&output, "gray_mkv_source_capture_timing_preserved")?,
                "false"
            );
        }
        assert_eq!(
            std::str::from_utf8(&output.stdout)?.lines().last(),
            Some("movie_export_complete=true")
        );
        assert_eq!(movie.journals()?, before);
    }
    Ok(())
}

fn word(bytes: &[u8], at: usize) -> TestResult<u32> {
    Ok(u32::from_be_bytes(
        bytes
            .get(at..at + 4)
            .ok_or("short fixture word")?
            .try_into()?,
    ))
}

fn box_at(bytes: &[u8], parent: Range<usize>, kind: &[u8; 4]) -> TestResult<Range<usize>> {
    let mut at = parent.start;
    while at < parent.end {
        let size = word(bytes, at)? as usize;
        let end = at.checked_add(size).ok_or("fixture box overflow")?;
        if size < 8 || end > parent.end {
            return Err("invalid fixture box size".into());
        }
        if bytes.get(at + 4..at + 8) == Some(kind.as_slice()) {
            return Ok(at..end);
        }
        at = end;
    }
    Err("missing fixture box".into())
}

fn child(bytes: &[u8], parent: &Range<usize>, kind: &[u8; 4]) -> TestResult<Range<usize>> {
    box_at(bytes, parent.start + 8..parent.end, kind)
}

/// Replace only the real fixture's edit table and adjust containing sizes/chunk offsets.
/// Encoded SPS/PPS and all ten original sample payloads remain unchanged.
fn repeated_edits() -> TestResult<Vec<u8>> {
    let mut bytes = AVC.to_vec();
    let moov = box_at(&bytes, 0..bytes.len(), b"moov")?;
    let trak = child(&bytes, &moov, b"trak")?;
    let edts = child(&bytes, &trak, b"edts")?;
    let elst = child(&bytes, &edts, b"elst")?;
    let mvhd = child(&bytes, &moov, b"mvhd")?;
    let tkhd = child(&bytes, &trak, b"tkhd")?;
    let mdia = child(&bytes, &trak, b"mdia")?;
    let minf = child(&bytes, &mdia, b"minf")?;
    let stbl = child(&bytes, &minf, b"stbl")?;
    let stco = child(&bytes, &stbl, b"stco")?;
    assert_eq!(bytes[elst.start + 8], 0);
    assert_eq!(bytes[mvhd.start + 8], 0);
    assert_eq!(bytes[tkhd.start + 8], 0);
    // At movie scale 1000 / media scale 10240: [3,1], then [0], repeated once.
    let edits = [(400_u32, 8192_i32), (200, 4096), (400, 8192), (200, 4096)];
    let mut replacement = Vec::new();
    replacement.extend_from_slice(&(16_u32 + 12 * edits.len() as u32).to_be_bytes());
    replacement.extend_from_slice(b"elst");
    replacement.extend_from_slice(&0_u32.to_be_bytes());
    replacement.extend_from_slice(&(edits.len() as u32).to_be_bytes());
    for (duration, media_time) in edits {
        replacement.extend_from_slice(&duration.to_be_bytes());
        replacement.extend_from_slice(&media_time.to_be_bytes());
        replacement.extend_from_slice(&0x0001_0000_u32.to_be_bytes());
    }
    let growth = u32::try_from(replacement.len() - elst.len())?;
    for parent in [&moov, &trak, &edts] {
        let size = word(&bytes, parent.start)?
            .checked_add(growth)
            .ok_or("box size overflow")?;
        bytes[parent.start..parent.start + 4].copy_from_slice(&size.to_be_bytes());
    }
    for at in [mvhd.start + 24, tkhd.start + 28] {
        bytes[at..at + 4].copy_from_slice(&1200_u32.to_be_bytes());
    }
    for index in 0..word(&bytes, stco.start + 12)? as usize {
        let at = stco.start + 16 + 4 * index;
        let offset = word(&bytes, at)?;
        assert!(
            offset as usize >= moov.end,
            "fixture media must follow moov"
        );
        bytes[at..at + 4].copy_from_slice(
            &offset
                .checked_add(growth)
                .ok_or("chunk offset overflow")?
                .to_be_bytes(),
        );
    }
    bytes.splice(elst, replacement);
    Ok(bytes)
}

#[test]
fn movie_export_repeats_backwards_edits_without_duplicating_cached_frames_or_decode_work()
-> TestResult {
    let source = repeated_edits()?;
    let movie = Movie::import("movie-export-repeated", &source)?;
    let original = native_images(AVC)?;
    let expected_indices = [3, 1, 0, 3, 1, 0];
    let images = selected(&original, &expected_indices)?;
    let expected = rendered("pgm", &images)?;
    let cache_bytes = original
        .get(&0)
        .ok_or("missing fixture picture")?
        .pixels
        .len()
        * 3;
    let before = movie.journals()?;
    let first = movie
        .export(0..400, "pgm", &movie.path("first.pgm"))
        .output()?;
    success(&first);
    let output = movie
        .export(0..1200, "pgm", &movie.path("repeated.pgm"))
        .args([
            "--max-cached-luma-bytes",
            &cache_bytes.to_string(),
            "--max-output-bytes",
            &expected.len().to_string(),
        ])
        .output()?;
    success(&output);
    assert_eq!(fs::read(movie.path("repeated.pgm"))?, expected);
    assert_eq!(
        values(&output, "frame_segment")?,
        ["3", "1", "0", "3", "1", "0"]
    );
    assert_eq!(
        values(&output, "movie_output_index")?,
        ["0", "1", "2", "3", "4", "5"]
    );
    assert_eq!(field(&output, "movie_output_frames")?, "6");
    assert_eq!(field(&output, "movie_cached_frames")?, "3");
    assert_eq!(field(&output, "movie_decoded_frames")?, "4");
    assert_eq!(
        field(&output, "movie_cached_luma_bytes")?.parse::<usize>()?,
        cache_bytes
    );
    assert_eq!(
        field(&output, "decode_work_units")?,
        field(&first, "decode_work_units")?
    );
    let receipts = values(&output, "frame_receipt_digest")?;
    assert_eq!(receipts.len(), 6);
    assert_eq!(&receipts[..3], &receipts[3..]);
    assert_eq!(movie.journals()?, before);
    Ok(())
}

#[test]
fn movie_decode_work_and_original_read_allowances_are_shared_across_random_access_spans()
-> TestResult {
    let movie = Movie::import("movie-export-shared", AVC)?;
    let before = movie.journals()?;
    let first = movie
        .export(0..1000, "pgm", &movie.path("first-span.pgm"))
        .output()?;
    let second = movie
        .export(1000..2000, "pgm", &movie.path("second-span.pgm"))
        .output()?;
    let full_path = movie.path("all.pgm");
    let full = movie.export(0..2000, "pgm", &full_path).output()?;
    success(&first);
    success(&second);
    success(&full);
    assert_eq!(field(&full, "decode_span_count")?, "2");
    assert_eq!(field(&full, "movie_decoded_frames")?, "10");
    for (option, used_field) in [
        ("--work-units", "decode_work_units"),
        ("--max-decode-read-bytes", "movie_decode_source_bytes_read"),
    ] {
        let first_used = field(&first, used_field)?.parse::<u64>()?;
        let second_used = field(&second, used_field)?.parse::<u64>()?;
        let total = field(&full, used_field)?.parse::<u64>()?;
        assert!(first_used > 0 && second_used > 0);
        assert_eq!(total, first_used + second_used, "{used_field}");
        for (attempt, maximum) in [1, first_used.max(second_used), total - 1, total]
            .into_iter()
            .enumerate()
        {
            let path = movie.path(&format!("{used_field}-{attempt}.pgm"));
            let output = movie
                .export(0..2000, "pgm", &path)
                .args([option, &maximum.to_string()])
                .output()?;
            if maximum == total {
                success(&output);
                assert_eq!(fs::read(&path)?, fs::read(&full_path)?);
            } else {
                incomplete(&output)?;
                assert!(
                    !path.exists(),
                    "materialization refusal created an output file"
                );
            }
            assert!(field(&output, used_field)?.parse::<u64>()? <= maximum);
            assert_eq!(movie.journals()?, before);
        }
    }
    Ok(())
}

#[test]
fn movie_cache_output_and_encode_exhaustion_never_certify_a_shorter_selection() -> TestResult {
    let movie = Movie::import("movie-export-bounds", AVC)?;
    let images = selected(&native_images(AVC)?, &[3, 1])?;
    let before = movie.journals()?;
    let cache = images.iter().map(|image| image.pixels.len()).sum::<usize>();
    let path = movie.path("cache-refused.pgm");
    let output = movie
        .export(400..800, "pgm", &path)
        .args(["--max-cached-luma-bytes", &(cache - 1).to_string()])
        .output()?;
    incomplete(&output)?;
    assert!(!path.exists());
    let first = rendered("pgm", &images[..1])?;
    let all = rendered("pgm", &images)?;
    for maximum in [first.len(), all.len() - 1] {
        let path = movie.path(&format!("bytes-{maximum}.pgm"));
        let output = movie
            .export(400..800, "pgm", &path)
            .args(["--max-output-bytes", &maximum.to_string()])
            .output()?;
        incomplete(&output)?;
        assert_eq!(fs::read(path)?, first);
    }
    let full = movie
        .export(400..800, "mjpeg", &movie.path("full.mjpeg"))
        .output()?;
    success(&full);
    let work = field(&full, "encode_work_units")?.parse::<u64>()?;
    assert!(work > 0);
    let output = movie
        .export(400..800, "mjpeg", &movie.path("short.mjpeg"))
        .args(["--encode-work-units", &(work - 1).to_string()])
        .output()?;
    incomplete(&output)?;
    assert!(field(&output, "encode_work_units")?.parse::<u64>()? < work);
    assert_eq!(movie.journals()?, before);
    Ok(())
}

#[test]
fn movie_hevc_exports_idr_selection_but_refuses_requested_rasl_skipped_after_cra() -> TestResult {
    let movie = Movie::import("movie-export-hevc", HEVC)?;
    let before = movie.journals()?;
    let expected = rendered("pgm", &selected(&native_images(HEVC)?, &[0, 2])?)?;
    let path = movie.path("hevc-idr.pgm");
    let output = movie.export(0..400, "pgm", &path).output()?;
    success(&output);
    assert_eq!(values(&output, "frame_segment")?, ["0", "2"]);
    assert_eq!(fs::read(path)?, expected);

    // The retained source is valid. Starting at coding segment 3 (CRA) deliberately skips
    // its leading RASL pictures 4 and 5. Movie [600,800) requires original segment 5.
    let decoded = command(&movie.root, "decode")
        .args([
            "--import-id",
            &movie.identity,
            "--segment",
            "3",
            "--segment-count",
            "3",
            "--interpretation",
            "ycbcr",
            "--max-dimension",
            "64",
            "--max-pixels",
            "4096",
        ])
        .output()?;
    success(&decoded);
    assert_eq!(values(&decoded, "frame_segment")?, ["3"]);
    let path = movie.path("missing-requested.pgm");
    incomplete(&movie.export(600..800, "pgm", &path).output()?)?;
    assert!(!path.exists());
    assert_eq!(movie.journals()?, before);
    Ok(())
}

fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:movie-export-test".into(),
        operation_id: OperationId::parse("operation:movie-export-test")?,
        principal: "principal:test".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(&authority, root)?)
}

#[test]
fn movie_empty_selection_and_missing_original_custody_create_no_output() -> TestResult {
    let movie = Movie::import("movie-export-source", AVC)?;
    let path = movie.path("empty.pgm");
    incomplete(&movie.export(5000..6000, "pgm", &path).output()?)?;
    assert!(!path.exists());
    let cx = context(&movie.root)?;
    let deployment = ReferenceDeployment::open(&movie.root, SITE, &cx)?;
    let retained = RetainedFileImport::open(
        &deployment,
        ContentDigest::parse(&movie.identity)?,
        RetainedReadLimits::default(),
        &cx,
    )?;
    let digest = *retained
        .manifest()
        .ordered_chunks
        .first()
        .ok_or("missing source chunk")?;
    let object = deployment.publisher().spool().object_path(digest);
    drop(deployment);
    cx.drain_and_finalize();
    fs::rename(object, movie.path("withheld-source-object"))?;
    let path = movie.path("unavailable.pgm");
    incomplete(&movie.export(400..800, "pgm", &path).output()?)?;
    assert!(!path.exists());
    Ok(())
}

#[test]
fn movie_export_preserves_current_mask_pixels_in_lossless_outputs() -> TestResult {
    use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};

    let movie = Movie::import("movie-export-mask", AVC)?;
    let cx = context(&movie.root)?;
    let mut deployment = ReferenceDeployment::open(&movie.root, SITE, &cx)?;
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:media-cli")?,
        [64, 48],
        &[[0, 0, 64, 48]],
    )?;
    let approval = preview_mask(&deployment, &policy)?.approval;
    declare_mask(&mut deployment, &policy, approval, &cx)?;
    drop(deployment);
    cx.drain_and_finalize();
    let before = movie.journals()?;
    let mut images = selected(&native_images(AVC)?, &[3, 1])?;
    for image in &mut images {
        image.pixels.fill(16);
    }
    for format in ["pgm", "gray-mkv"] {
        let path = movie.path(&format!("masked.{format}"));
        let output = movie.export(400..800, format, &path).output()?;
        success(&output);
        assert_eq!(fs::read(path)?, rendered(format, &images)?);
        assert_eq!(values(&output, "frame_segment")?, ["3", "1"]);
        assert_eq!(movie.journals()?, before);
    }
    Ok(())
}

#[test]
fn movie_export_requires_its_output_and_rate_and_keeps_selection_metadata_only() -> TestResult {
    let movie = Movie::import("movie-export-admission", AVC)?;
    let before = movie.journals()?;
    for (index, extra) in [
        vec!["--interpretation", "ycbcr"], // Missing output.
        vec!["--output", "destination"],   // Missing explicit interpretation.
        vec![
            "--interpretation",
            "ycbcr",
            "--output",
            "destination",
            "--output-format",
            "gray-mkv",
        ],
    ]
    .into_iter()
    .enumerate()
    {
        let destination = movie.path(&format!("admission-{index}"));
        let mut request = command(&movie.root, "export-movie");
        request.args([
            "--import-id",
            &movie.identity,
            "--start-movie-tick",
            "400",
            "--end-movie-tick",
            "800",
        ]);
        for value in extra {
            if value == "destination" {
                request.arg(&destination);
            } else {
                request.arg(value);
            }
        }
        incomplete(&request.output()?)?;
        assert!(!destination.exists());
    }
    let selection = command(&movie.root, "select-movie")
        .args([
            "--import-id",
            &movie.identity,
            "--start-movie-tick",
            "400",
            "--end-movie-tick",
            "800",
        ])
        .output()?;
    success(&selection);
    assert_eq!(field(&selection, "selection_complete")?, "true");
    assert_eq!(field(&selection, "selection_media_exported")?, "false");
    assert_eq!(field(&selection, "selection_decoded_frames")?, "0");
    let path = movie.path("metadata-must-not-export.pgm");
    let refused = command(&movie.root, "select-movie")
        .args([
            "--import-id",
            &movie.identity,
            "--start-movie-tick",
            "400",
            "--end-movie-tick",
            "800",
        ])
        .arg("--output")
        .arg(&path)
        .output()?;
    incomplete(&refused)?;
    assert!(!path.exists());
    // No trailing manifest write may fail after the movie's terminal completion marker.
    // In particular, an alias of the create-only media destination must refuse before I/O.
    let alias = movie.path("media-and-manifest.pgm");
    let refused = movie
        .export(400..800, "pgm", &alias)
        .arg("--manifest-out")
        .arg(&alias)
        .output()?;
    incomplete(&refused)?;
    assert!(!alias.exists());
    assert_eq!(movie.journals()?, before);
    Ok(())
}
