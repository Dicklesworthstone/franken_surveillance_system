#![forbid(unsafe_code)]
//! Real codec fixtures, independent decoded pixels, exact edits and late refusal fences.

use super::*;
use crate::ingest::privacy_mask::{MASK_FILL_LUMA, PrivacyMaskPolicy, declare_mask, preview_mask};
use crate::ingest::{FileIngestAdapter, FileIngestReceipt, FileIngestRequest};
use crate::{ADP_FILE_ROW_ID, ADP_REPLAY_ROW_ID};
use fss_container::demux::{AvcMp4, DemuxLimits};
use fss_core::{
    BudgetVector, ContextAuthority, OperationId, RootAuthoritySpec, StreamId, TimestampNs,
};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:review-render-contract";
const SENSOR: &str = "sensor:review-render-contract";
const AVC: &[u8] = include_bytes!("../../../../fss-container/tests/fixtures/indexed_avc.mp4");
const HEVC: &[u8] = include_bytes!("../../../../fss-container/tests/fixtures/hevc_av.mp4");

fn directory(label: &str) -> TestResult<PathBuf> {
    let base = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    for attempt in 0..128 {
        let path = base.join(format!(
            "fss-review-render-{label}-{}-{attempt}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err("test directory reservation exhausted".into())
}

fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:review-render-contract".to_owned(),
        operation_id: OperationId::parse("operation:review-render-contract")?,
        principal: "principal:review-render-contract".to_owned(),
        capabilities: vec![ADP_FILE_ROW_ID.to_owned(), ADP_REPLAY_ROW_ID.to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:internal".to_owned(),
        retention_scope: "retention:ephemeral".to_owned(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(&authority, root)?)
}

fn snapshot(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) -> TestResult {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                visit(root, &entry.path(), result)?;
            } else if entry.file_type()?.is_file() {
                result.insert(
                    entry.path().strip_prefix(root)?.to_path_buf(),
                    fs::read(entry.path())?,
                );
            } else {
                return Err("nonregular test-owned entry".into());
            }
        }
        Ok(())
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result)?;
    Ok(result)
}

struct Fixture {
    root: PathBuf,
    deployment: ReferenceDeployment,
    import: FileIngestReceipt,
    cx: ReplayCx,
}

impl Fixture {
    fn new(label: &str, bytes: &[u8]) -> TestResult<Self> {
        let dir = directory(label)?;
        let original = dir.join("original.mp4");
        fs::write(&original, bytes)?;
        let root = dir.join("deployment");
        let cx = context(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut request = FileIngestRequest::new(
            original.clone(),
            SensorId::parse(SENSOR)?,
            StreamId::parse("stream:review-render-contract")?,
        )
        .with_receive_time(TimestampNs(2_000_000_000));
        request.limits.chunk_bytes = 1024;
        request.limits.max_batch_deltas = 3;
        let import = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;
        fs::rename(original, dir.join("former-original.mp4"))?;
        drop(deployment);
        let deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        Ok(Self {
            root,
            deployment,
            import,
            cx,
        })
    }

    fn request(&self, query: Range<u64>) -> ReviewMovieRequest {
        ReviewMovieRequest {
            import_identity: self.import.import_identity,
            movie_start_tick: query.start,
            movie_end_tick: query.end,
            limits: ReviewMovieLimits {
                max_dimension: 64,
                max_pixels: 4096,
                ..ReviewMovieLimits::default()
            },
        }
    }

    fn render(&self, query: Range<u64>) -> Result<RenderedReviewMovie, ReviewRenderError> {
        render_movie(&self.deployment, &self.request(query), &self.cx)
    }
}

#[derive(Clone)]
struct Image {
    dimensions: [u32; 2],
    pixels: Vec<u8>,
}

// Decode the original fixture independently of retained readers, range selection and review
// output caching. Tests use fixed original sample indices and literal presentation intervals.
fn native_images(source: &[u8]) -> TestResult<BTreeMap<usize, Image>> {
    let movie = AvcMp4::parse(source, None, DemuxLimits::default())?;
    let elementary = movie.annex_b(0, movie.samples().len())?;
    let mut result = BTreeMap::new();
    macro_rules! decode {
        ($codec:ident) => {{
            let mut decoder = $codec::Decoder::new(Default::default())?;
            let mut pictures = decoder.decode_annex_b(elementary.bytes())?;
            pictures.extend(decoder.finish()?);
            for picture in pictures {
                let prior = result.insert(
                    usize::try_from(picture.decode_index())?,
                    Image {
                        dimensions: [picture.width(), picture.height()],
                        pixels: picture.luma().to_vec(),
                    },
                );
                assert!(prior.is_none());
            }
        }};
    }
    match movie.codec() {
        VideoCodec::Avc => decode!(fss_codec_h264),
        VideoCodec::Hevc => decode!(fss_codec_h265),
    }
    assert_eq!(result.len(), movie.samples().len());
    assert!(result.values().all(|image| image.dimensions == [64, 48]));
    Ok(result)
}

fn expected_movie(
    images: &BTreeMap<usize, Image>,
    segments: &[usize],
    intervals: &[(u64, u64)],
    duration: u64,
) -> TestResult<Vec<u8>> {
    assert_eq!(segments.len(), intervals.len());
    let config = TimedGrayMatroskaConfig::new([64, 48], duration)?;
    let mut bytes = config.initialization()?.bytes().to_vec();
    for (ordinal, (segment, (start, end))) in segments.iter().zip(intervals).enumerate() {
        bytes.extend_from_slice(config.frame(ordinal as u64, *start, *end)?.prefix());
        bytes.extend_from_slice(
            &images
                .get(segment)
                .ok_or("missing original picture")?
                .pixels,
        );
    }
    Ok(bytes)
}

#[test]
fn avc_review_preserves_b_picture_order_partial_trims_and_complete_read_only_receipts() -> TestResult
{
    let f = Fixture::new("trim", AVC)?;
    let before = snapshot(&f.root)?;
    let expected = expected_movie(
        &native_images(AVC)?,
        &[3, 1],
        &[(0, 150_000_000), (150_000_000, 300_000_000)],
        300_000_000,
    )?;
    let rendered = f.render(450..750)?;
    assert_eq!(rendered.bytes(), expected);
    assert_eq!(rendered.media_digest(), ContentDigest::sha256(&expected));
    assert_eq!(rendered.dimensions(), [64, 48]);
    assert_eq!(rendered.frames(), 2);
    assert_eq!(rendered.duration_ns(), 300_000_000);
    assert_eq!(rendered.sensor().as_str(), SENSOR);
    assert_eq!(rendered.privacy(), &MaskBinding::NoPolicy);
    assert_eq!(rendered.selection().capture_time_label, "unknown");
    assert_eq!(
        rendered.receipt_digest(),
        ContentDigest::sha256(rendered.receipt_bytes())
    );
    assert!(rendered.receipt_bytes().len() < MAX_REVIEW_RENDER_RECEIPT_BYTES);
    for digest in [f.import.import_root, f.import.manifest_digest]
        .into_iter()
        .chain(f.import.manifest.ordered_chunks.iter().copied())
    {
        assert!(rendered.source_dependency_digests().contains(&digest));
    }
    let again = f.render(450..750)?;
    assert_eq!(again.bytes(), rendered.bytes());
    assert_eq!(again.receipt_bytes(), rendered.receipt_bytes());
    let used = rendered.decode_source_bytes();
    rendered.revalidate(&f.deployment, &f.cx)?;
    assert_eq!(rendered.decode_source_bytes(), used + AVC.len() as u64);
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn current_partial_mask_changes_only_declared_pixels_before_movie_caching() -> TestResult {
    let mut f = Fixture::new("partial-mask", AVC)?;
    let original = f.render(400..800)?;
    let policy = PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [64, 48], &[[8, 4, 16, 8]])?;
    let approval = preview_mask(&f.deployment, &policy)?.approval;
    declare_mask(&mut f.deployment, &policy, approval, &f.cx)?;
    let before = snapshot(&f.root)?;
    let mut images = native_images(AVC)?;
    for image in images.values_mut() {
        for y in 4..12 {
            image.pixels[y * 64 + 8..y * 64 + 24].fill(MASK_FILL_LUMA);
        }
    }
    let expected = expected_movie(
        &images,
        &[3, 1],
        &[(0, 200_000_000), (200_000_000, 400_000_000)],
        400_000_000,
    )?;
    let masked = f.render(400..800)?;
    assert_eq!(masked.bytes(), expected);
    assert_ne!(masked.bytes(), original.bytes());
    assert_ne!(masked.lineage_digest(), original.lineage_digest());
    assert_eq!(
        masked.privacy(),
        &current_mask(&f.deployment, &SensorId::parse(SENSOR)?)?
    );
    assert!(original.revalidate(&f.deployment, &f.cx).is_err());
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn receipt_remains_input_stable_after_an_unrelated_authority_append() -> TestResult {
    let mut f = Fixture::new("receipt-basis", AVC)?;
    let first = f.render(400..800)?;
    let unrelated = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:other-review-camera")?,
        [64, 48],
        &[[0, 0, 8, 8]],
    )?;
    let approval = preview_mask(&f.deployment, &unrelated)?.approval;
    declare_mask(&mut f.deployment, &unrelated, approval, &f.cx)?;
    let before = snapshot(&f.root)?;
    let second = f.render(400..800)?;
    assert_ne!(first.anchor(), second.anchor());
    assert_eq!(first.source_anchor(), second.source_anchor());
    assert_eq!(first.bytes(), second.bytes());
    assert_eq!(first.receipt_bytes(), second.receipt_bytes());
    // Old in-memory materialization still cannot bypass the live authority fence.
    assert!(first.revalidate(&f.deployment, &f.cx).is_err());
    assert_eq!(snapshot(&f.root)?, before);
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

// Change only edit-table metadata and necessary enclosing sizes/chunk offsets. The native
// encoded pictures are byte-for-byte the independently decoded fixture used above.
fn edited_fixture() -> TestResult<Vec<u8>> {
    let edits = [
        (100_u32, -1_i32),
        (400, 8192),
        (200, -1),
        (200, 4096),
        (400, 8192),
        (300, -1),
    ];
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
    let growth = u32::try_from(
        replacement
            .len()
            .checked_sub(elst.len())
            .ok_or("fixture edits shrink")?,
    )?;
    for parent in [&moov, &trak, &edts] {
        let size = word(&bytes, parent.start)?
            .checked_add(growth)
            .ok_or("box size overflow")?;
        bytes[parent.start..parent.start + 4].copy_from_slice(&size.to_be_bytes());
    }
    let duration: u32 = edits.iter().map(|(duration, _)| *duration).sum();
    for at in [mvhd.start + 24, tkhd.start + 28] {
        bytes[at..at + 4].copy_from_slice(&duration.to_be_bytes());
    }
    for index in 0..word(&bytes, stco.start + 12)? as usize {
        let at = stco.start + 16 + 4 * index;
        let offset = word(&bytes, at)?;
        assert!(offset as usize >= moov.end);
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
fn repeated_edits_reuse_pixels_and_preserve_leading_internal_trailing_holes() -> TestResult {
    let f = Fixture::new("gaps-repetitions", &edited_fixture()?)?;
    let before = snapshot(&f.root)?;
    let expected = expected_movie(
        &native_images(AVC)?,
        &[3, 1, 0, 3, 1],
        &[
            (50_000_000, 250_000_000),
            (250_000_000, 450_000_000),
            (650_000_000, 850_000_000),
            (850_000_000, 1_050_000_000),
            (1_050_000_000, 1_250_000_000),
        ],
        1_650_000_000,
    )?;
    let mut request = f.request(50..1700);
    request.limits.max_cached_luma_bytes = 3 * 64 * 48;
    request.limits.max_output_bytes = expected.len() as u64;
    let rendered = render_movie(&f.deployment, &request, &f.cx)?;
    assert_eq!(rendered.bytes(), expected);
    assert_eq!(rendered.frames(), 5);
    assert_eq!(rendered.selection().selection.gaps.len(), 4);
    assert_eq!(
        rendered
            .selection()
            .selection
            .decode_spans
            .iter()
            .map(|span| span.sample_count)
            .sum::<usize>(),
        4
    );
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn hevc_idr_pixels_are_exact_and_missing_requested_rasl_refuses_complete_output() -> TestResult {
    let f = Fixture::new("hevc", HEVC)?;
    let before = snapshot(&f.root)?;
    let expected = expected_movie(
        &native_images(HEVC)?,
        &[0, 2],
        &[(0, 200_000_000), (200_000_000, 400_000_000)],
        400_000_000,
    )?;
    assert_eq!(f.render(0..400)?.bytes(), expected);
    // Segment 5 is a RASL picture skipped after the selected CRA at segment 3. Native
    // decoding reaches successful EOF, but a required presentation picture is unavailable.
    assert!(matches!(
        f.render(600..800),
        Err(ReviewRenderError::Output(MovieOutputError::Missing))
    ));
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn complete_output_cache_work_and_source_revalidation_share_strict_limits() -> TestResult {
    let f = Fixture::new("allowances", AVC)?;
    let before = snapshot(&f.root)?;
    let baseline = f.render(0..2000)?;
    let full_reads = baseline.decode_source_bytes();
    let full_work = baseline.decode_work_units();
    let full_media = baseline.bytes().len() as u64;
    assert!(full_reads > 2 * AVC.len() as u64);
    for (index, field) in ["media", "cache", "work", "source"].iter().enumerate() {
        let mut request = f.request(0..2000);
        match *field {
            "media" => request.limits.max_output_bytes = full_media - 1,
            "cache" => request.limits.max_cached_luma_bytes = 10 * 64 * 48 - 1,
            "work" => request.limits.max_decode_work_units = full_work - 1,
            "source" => request.limits.max_decode_read_bytes = full_reads - 1,
            _ => return Err("unknown allowance".into()),
        }
        assert!(
            render_movie(&f.deployment, &request, &f.cx).is_err(),
            "refusal case {index}"
        );
        assert_eq!(snapshot(&f.root)?, before);
    }
    let mut exact = f.request(0..2000);
    exact.limits.max_output_bytes = full_media;
    exact.limits.max_cached_luma_bytes = 10 * 64 * 48;
    exact.limits.max_decode_work_units = full_work;
    exact.limits.max_decode_read_bytes = full_reads;
    let rendered = render_movie(&f.deployment, &exact, &f.cx)?;
    assert_eq!(rendered.bytes(), baseline.bytes());
    assert_eq!(rendered.decode_source_bytes(), full_reads);
    assert!(rendered.revalidate(&f.deployment, &f.cx).is_err());
    assert_eq!(rendered.decode_source_bytes(), full_reads);
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn cancellation_during_output_or_after_final_reads_releases_no_complete_result_or_writes()
-> TestResult {
    let f = Fixture::new("cancel", AVC)?;
    let before = snapshot(&f.root)?;
    for stage in [
        "review_movie:decode_span",
        "review_movie:output",
        "review_movie:revalidate_complete",
        "review_movie:receipt_occurrence",
        "review_movie:receipt_complete",
        "review_movie:release_complete",
    ] {
        let cx = context(&f.root)?;
        cx.set_cancel_at_checkpoint(stage);
        assert!(
            render_movie(&f.deployment, &f.request(400..800), &cx).is_err(),
            "stage {stage}"
        );
        assert!(cx.is_drain_completed(), "stage {stage}");
        assert_eq!(snapshot(&f.root)?, before);
    }
    Ok(())
}
