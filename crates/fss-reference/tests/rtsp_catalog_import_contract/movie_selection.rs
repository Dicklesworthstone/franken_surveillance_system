#![forbid(unsafe_code)]
//! Movie-time selection retains complete native catalog/page provenance and global sample indices.
//! These are retained metadata/decode contracts, not reviewer grants or CLI-export qualification.

use super::*;
use fss_container::demux::{
    AvcMp4, DemuxError, DemuxLimits, MovieGapKind, MovieInterval, MovieSelection,
    MovieSelectionLimits, VideoCodec,
};
use fss_reference::ingest::retained::MAX_MOVIE_ORIGIN_READ_BYTES;
use fss_reference::ingest::rtsp_import::pages::{
    ADAPTER as PAGES_ADAPTER, MAX_PAGES, RtspCatalogPagesImportRequest, import_rtsp_catalog_pages,
};
use fss_reference::ingest::{FileIngestError, RetainedMovieSelection};
use std::ops::Range;

#[allow(dead_code)]
#[path = "../support/import_integrity.rs"]
mod integrity;

const SCALE: u32 = 90_000;
// The existing catalog verifier reserves its complete bounded proof read before I/O, then
// charges every catalog root/index and native recording root/child, including shared objects.
const CATALOG_PROOF_RESERVATION: u64 = 4 * 1024 * 1024;

fn origin_allowance(f: &Fixture) -> u64 {
    CATALOG_PROOF_RESERVATION + f.original_bytes
}

fn interval(start: u64, end: u64) -> MovieInterval {
    MovieInterval {
        start_numerator: u128::from(start) * u128::from(SCALE),
        end_numerator: u128::from(end) * u128::from(SCALE),
        denominator: SCALE,
    }
}

fn select(
    f: &Fixture,
    retained: &RetainedFileImport,
    query: Range<u64>,
    allowance: u64,
    cx: &ReplayCx,
) -> Test<RetainedMovieSelection> {
    Ok(retained.select_movie_interval_with_origin_limit(
        f.target()?,
        query,
        RetainedReadLimits::default(),
        MovieSelectionLimits::default(),
        allowance,
        cx,
    )?)
}

fn assert_binding(
    f: &Fixture,
    receipt: &RtspCatalogImportReceipt,
    retained: &RetainedFileImport,
    report: &RetainedMovieSelection,
    adapter: &str,
) -> Test {
    assert_eq!(report.import_identity, receipt.import.import_identity);
    assert_eq!(report.import_root, receipt.import.import_root);
    assert_eq!(report.manifest_digest, receipt.import.manifest_digest);
    assert_eq!(&report.authority_anchor, retained.authority_anchor());
    assert_eq!(report.source_adapter_id, adapter);
    assert_eq!(
        report.source_adapter_generation,
        retained.manifest().adapter_generation
    );
    assert_eq!(report.input_sha256, ContentDigest::sha256(&f.mp4));
    assert_eq!(report.input_bytes, f.mp4.len() as u64);
    assert_eq!(report.source_bytes_read, f.mp4.len() as u64);
    assert_eq!(report.origin_read_bytes_charged, origin_allowance(f));
    assert_eq!(report.maximum_origin_read_bytes, origin_allowance(f));
    assert_eq!(report.capture_time_label, receipt.import.capture_time_label);
    assert_eq!(report.selection.movie_timescale, SCALE);
    assert_eq!(report.selection.media_timescale, SCALE);
    let parsed = AvcMp4::parse(&f.mp4, None, DemuxLimits::default())?;
    assert_eq!(report.track_id, parsed.track_id());
    assert_eq!(report.codec, parsed.codec());
    assert_eq!(
        report.selection,
        parsed.select_movie_interval(
            report.selection.query.clone(),
            MovieSelectionLimits::default(),
        )?
    );
    for sample in &report.selection.samples {
        let span = &retained.manifest().segment_spans[sample.sample_index];
        assert_eq!(sample.source.start as u64, span.offset);
        assert_eq!(sample.source.len() as u64, span.len);
        assert_eq!(
            ContentDigest::sha256(&f.mp4[sample.source.clone()]),
            span.segment_sha256
        );
        assert_eq!(sample.edit_index, None);
    }
    Ok(())
}

/// Open and finish every quoted native range, as the movie renderer must before releasing a
/// selected frame. The original global index survives each independent decoder bootstrap.
fn drain_spans(f: &Fixture, report: &RetainedMovieSelection) -> Test {
    for span in &report.selection.decode_spans {
        let mut observed = Vec::new();
        match report.codec {
            VideoCodec::Avc => {
                let mut decoder = RecordedH264Range::open(
                    f.target()?,
                    RecordedH264Request {
                        import_identity: report.import_identity,
                        first_segment: span.first_sample,
                        segment_count: span.sample_count,
                        interpretation: ComponentInterpretation::YCbCr,
                        read_limits: RetainedReadLimits::default(),
                        decoder_limits: AvcLimits::default(),
                    },
                    &f.cx,
                )?;
                while let Some(frame) = decoder.next_frame(f.target()?, &f.cx)? {
                    assert!(!frame.pixels().is_empty());
                    observed.push(usize::try_from(frame.segment_index())?);
                }
            }
            VideoCodec::Hevc => {
                let mut decoder = RecordedH265Range::open(
                    f.target()?,
                    RecordedH265Request {
                        import_identity: report.import_identity,
                        first_segment: span.first_sample,
                        segment_count: span.sample_count,
                        interpretation: ComponentInterpretation::YCbCr,
                        read_limits: RetainedReadLimits::default(),
                        decoder_limits: HevcLimits::default(),
                    },
                    &f.cx,
                )?;
                while let Some(frame) = decoder.next_frame(f.target()?, &f.cx)? {
                    assert!(!frame.pixels().is_empty());
                    observed.push(usize::try_from(frame.segment_index())?);
                }
            }
        }
        observed.sort_unstable();
        assert_eq!(
            observed,
            (span.first_sample..span.first_sample + span.sample_count).collect::<Vec<_>>()
        );
        assert!(
            span.requested_samples
                .iter()
                .all(|sample| observed.contains(sample))
        );
    }
    Ok(())
}

fn assert_samples(selection: &MovieSelection, expected: &[(usize, u64, u64)]) {
    assert_eq!(selection.samples.len(), expected.len());
    for (sample, &(index, start, end)) in selection.samples.iter().zip(expected) {
        assert_eq!(sample.sample_index, index);
        assert_eq!(sample.interval, interval(start, end));
    }
    assert!(selection.gaps.is_empty());
}

// Reuse the parent fixture's real recording/catalog publication and exact native byte oracle.
// One independently sealed window per page makes the second page begin at global sample four.
fn avc_pages(
    label: &str,
    first_start: u64,
    gap: u64,
    different_config: bool,
) -> Test<(Fixture, RtspCatalogPagesImportRequest)> {
    let first =
        recording_support::repeated(501, 4, 1, first_start as u32)?.prepare_at(first_start)?;
    let second_start = first_start + 4 * 3600 + gap;
    let second = if different_config {
        recording_support::repeated_from(
            502,
            4,
            2000,
            second_start as u32,
            include_bytes!("../../../fss-packet/tests/fixtures/avc/high_cropped.264"),
        )?
        .prepare_at(second_start)?
    } else {
        recording_support::repeated(502, 4, 2000, second_start as u32)?.prepare_at(second_start)?
    };
    let a = slot(0)?;
    let b = slot(1)?;
    let first_page = prepare_catalog(
        scope(first.summary()),
        &[CatalogWindow {
            slot: &a,
            recording: &first,
        }],
    )?;
    let second_page = prepare_catalog(
        scope(first.summary()),
        &[CatalogWindow {
            slot: &b,
            recording: &second,
        }],
    )?;
    let (f, pages) = Fixture::from_catalogs(
        label,
        RtspImportCodec::Avc,
        &[&first, &second],
        vec![Page::Avc(first_page), Page::Avc(second_page)],
    )?;
    let common = &f.request;
    let request = RtspCatalogPagesImportRequest {
        codec: common.codec,
        pages,
        scope: common.scope.clone(),
        receive_time: common.receive_time,
        capture_origin: common.capture_origin,
        max_pages: MAX_PAGES,
        max_windows: common.max_windows,
        max_frames: common.max_frames,
        max_original_bytes: common.max_original_bytes,
        max_media_bytes: common.max_media_bytes,
    };
    Ok((f, request))
}

fn run_pages(
    f: &mut Fixture,
    request: &RtspCatalogPagesImportRequest,
) -> Test<RtspCatalogImportReceipt> {
    let receipt = import_rtsp_catalog_pages(
        f.source.as_ref().ok_or("source")?,
        f.target.as_mut().ok_or("target")?,
        request,
        &Owner(Cell::new(true)),
        &f.cx,
        &mut work(),
    )?;
    assert_eq!(receipt.pages, 2);
    Ok(receipt.catalog)
}

#[test]
fn avc_catalog_clip_crosses_native_windows_without_renumbering_or_extending_presentations() -> Test
{
    let mut f = Fixture::avc("movie-catalog-avc", 4, 0, false)?;
    let receipt = f.run()?;
    f.verify_fragment_remux(&receipt)?;
    let retained = f.retained(&receipt)?;
    let before = integrity::snapshot(&f.directory.0.join("destination"))?;
    let report = select(&f, &retained, 12_600..16_200, origin_allowance(&f), &f.cx)?;
    assert_binding(&f, &receipt, &retained, &report, ADAPTER)?;
    assert_eq!(report.codec, VideoCodec::Avc);
    assert_samples(
        &report.selection,
        &[(3, 12_600, 14_400), (4, 14_400, 16_200)],
    );
    assert_eq!(
        report
            .selection
            .decode_spans
            .iter()
            .map(|span| (
                span.first_sample,
                span.sample_count,
                span.requested_samples.clone()
            ))
            .collect::<Vec<_>>(),
        [(3, 1, vec![3]), (4, 1, vec![4])]
    );
    drain_spans(&f, &report)?;
    assert_eq!(
        integrity::snapshot(&f.directory.0.join("destination"))?,
        before
    );
    Ok(())
}

#[test]
fn hevc_catalog_clip_keeps_reordered_global_indices_and_independent_decode_preroll() -> Test {
    let mut f = Fixture::hevc("movie-catalog-hevc")?;
    let receipt = f.run()?;
    f.verify_fragment_remux(&receipt)?;
    let retained = f.retained(&receipt)?;
    let before = integrity::snapshot(&f.directory.0.join("destination"))?;
    let report = select(&f, &retained, 63_000..117_000, origin_allowance(&f), &f.cx)?;
    assert_binding(&f, &receipt, &retained, &report, ADAPTER)?;
    assert_eq!(report.codec, VideoCodec::Hevc);
    assert_samples(
        &report.selection,
        &[
            (3, 63_000, 72_000),
            (4, 72_000, 90_000),
            (6, 90_000, 108_000),
            (5, 108_000, 117_000),
        ],
    );
    assert!(report.selection.decode_spans.len() >= 2);
    for span in &report.selection.decode_spans {
        let end = span.first_sample + span.sample_count;
        assert!(end <= 4 || span.first_sample >= 4);
    }
    assert!(
        report
            .selection
            .decode_spans
            .iter()
            .any(|span| { span.sample_count > span.requested_samples.len() }),
        "the non-IDR final picture of the first window needs its native bootstrap"
    );
    drain_spans(&f, &report)?;
    assert_eq!(
        integrity::snapshot(&f.directory.0.join("destination"))?,
        before
    );
    Ok(())
}

#[test]
fn cold_page_selection_preserves_nonzero_native_tfdt_and_complete_origin_without_archive() -> Test {
    let (mut f, mut request) = avc_pages("movie-pages-cold", 90_000, 0, false)?;
    request.capture_origin = None;
    let receipt = run_pages(&mut f, &request)?;
    assert_eq!(receipt.decode_interval, 90_000..118_800);
    f.verify_fragment_remux(&receipt)?;
    let retained = f.retained(&receipt)?;
    let warm = select(&f, &retained, 102_600..106_200, origin_allowance(&f), &f.cx)?;
    drop(retained);
    drop(f.source.take());
    fs::rename(
        f.directory.0.join("archive"),
        f.directory.0.join("offline-archive"),
    )?;
    drop(f.target.take());
    f.cx = context(&f.directory.0.join("destination"))?;
    f.target = Some(ReferenceDeployment::open(
        &f.directory.0.join("destination"),
        SITE,
        &f.cx,
    )?);
    let retained = f.retained(&receipt)?;
    let before = integrity::snapshot(&f.directory.0.join("destination"))?;
    let cold = select(&f, &retained, 102_600..106_200, origin_allowance(&f), &f.cx)?;
    assert_eq!(cold, warm);
    assert_binding(&f, &receipt, &retained, &cold, PAGES_ADAPTER)?;
    assert_eq!(cold.capture_time_label, "unknown");
    assert_samples(
        &cold.selection,
        &[(3, 102_600, 104_400), (4, 104_400, 106_200)],
    );
    drain_spans(&f, &cold)?;
    let leading = select(&f, &retained, 0..90_001, origin_allowance(&f), &f.cx)?;
    assert_eq!(leading.selection.samples.len(), 1);
    assert_eq!(leading.selection.samples[0].sample_index, 0);
    assert_eq!(
        leading.selection.samples[0].interval,
        interval(90_000, 90_001)
    );
    assert_eq!(leading.selection.gaps.len(), 1);
    assert_eq!(leading.selection.gaps[0].interval, interval(0, 90_000));
    assert_eq!(leading.selection.gaps[0].kind, MovieGapKind::Unrepresented);
    assert_eq!(
        integrity::snapshot(&f.directory.0.join("destination"))?,
        before
    );
    Ok(())
}

#[test]
fn exact_catalog_and_page_origin_allowance_includes_proof_and_every_unselected_original() -> Test {
    assert_eq!(
        MAX_MOVIE_ORIGIN_READ_BYTES,
        MAX_ORIGINAL_BYTES + CATALOG_PROOF_RESERVATION
    );
    for pages in [false, true] {
        let (mut f, request) = if pages {
            let (f, request) = avc_pages("movie-pages-budget", 0, 0, false)?;
            (f, Some(request))
        } else {
            (Fixture::avc("movie-catalog-budget", 4, 0, false)?, None)
        };
        let receipt = match &request {
            Some(request) => run_pages(&mut f, request)?,
            None => f.run()?,
        };
        let retained = f.retained(&receipt)?;
        let required = origin_allowance(&f);
        let before = integrity::snapshot(&f.directory.0.join("destination"))?;
        let exact = select(&f, &retained, 0..1, required, &f.cx)?;
        assert_eq!(exact.origin_read_bytes_charged, required);
        assert_eq!(exact.maximum_origin_read_bytes, required);
        assert_eq!(exact.source_bytes_read, f.mp4.len() as u64);
        assert_samples(&exact.selection, &[(0, 0, 1)]);
        assert!(exact.selection.decode_bytes < exact.source_bytes_read);
        for allowance in [0, CATALOG_PROOF_RESERVATION - 1, required - 1] {
            let refused = retained.select_movie_interval_with_origin_limit(
                f.target()?,
                0..1,
                RetainedReadLimits::default(),
                MovieSelectionLimits::default(),
                allowance,
                &f.cx,
            );
            assert!(matches!(
                refused,
                Err(FileIngestError::SpoolCapacityExceeded {
                    limit: "movie_origin_read_bytes",
                    required: attempted,
                    available,
                }) if available == allowance && attempted > allowance
            ));
        }
        let default = retained.select_movie_interval(
            f.target()?,
            0..1,
            RetainedReadLimits::default(),
            MovieSelectionLimits::default(),
            &f.cx,
        )?;
        assert_eq!(default.selection, exact.selection);
        assert_eq!(
            default.maximum_origin_read_bytes,
            MAX_MOVIE_ORIGIN_READ_BYTES
        );
        assert_eq!(default.origin_read_bytes_charged, required);
        let empty = select(&f, &retained, 1_000_000..1_000_001, required, &f.cx)?;
        assert!(empty.selection.samples.is_empty());
        assert!(empty.selection.decode_spans.is_empty());
        assert_eq!(empty.origin_read_bytes_charged, required);
        assert_eq!(empty.source_bytes_read, f.mp4.len() as u64);
        assert!(
            retained
                .select_movie_interval_with_origin_limit(
                    f.target()?,
                    0..1,
                    RetainedReadLimits {
                        max_source_bytes: f.mp4.len() as u64 - 1,
                        ..RetainedReadLimits::default()
                    },
                    MovieSelectionLimits::default(),
                    required,
                    &f.cx,
                )
                .is_err()
        );
        assert_eq!(
            integrity::snapshot(&f.directory.0.join("destination"))?,
            before
        );
    }
    Ok(())
}

#[test]
fn page_boundary_does_not_renew_selected_decode_sample_or_byte_allowances() -> Test {
    let (mut f, request) = avc_pages("movie-pages-decode-budget", 0, 0, false)?;
    let receipt = run_pages(&mut f, &request)?;
    let retained = f.retained(&receipt)?;
    let before = integrity::snapshot(&f.directory.0.join("destination"))?;
    let report = select(&f, &retained, 12_600..19_800, origin_allowance(&f), &f.cx)?;
    assert_samples(
        &report.selection,
        &[
            (3, 12_600, 14_400),
            (4, 14_400, 18_000),
            (5, 18_000, 19_800),
        ],
    );
    let count: usize = report
        .selection
        .decode_spans
        .iter()
        .map(|s| s.sample_count)
        .sum();
    assert_eq!(count, 3);
    let exact = MovieSelectionLimits {
        max_decode_samples: count,
        max_source_bytes: report.selection.decode_bytes,
        max_annex_b_bytes: report.selection.annex_b_bytes,
        ..MovieSelectionLimits::default()
    };
    let repeated = retained.select_movie_interval_with_origin_limit(
        f.target()?,
        12_600..19_800,
        RetainedReadLimits::default(),
        exact,
        origin_allowance(&f),
        &f.cx,
    )?;
    assert_eq!(repeated, report);
    for limits in [
        MovieSelectionLimits {
            max_decode_samples: count - 1,
            ..exact
        },
        MovieSelectionLimits {
            max_source_bytes: exact.max_source_bytes - 1,
            ..exact
        },
        MovieSelectionLimits {
            max_annex_b_bytes: exact.max_annex_b_bytes - 1,
            ..exact
        },
    ] {
        assert!(matches!(
            retained.select_movie_interval_with_origin_limit(
                f.target()?,
                12_600..19_800,
                RetainedReadLimits::default(),
                limits,
                origin_allowance(&f),
                &f.cx,
            ),
            Err(FileIngestError::Mp4Refused {
                refusal: DemuxError::Limit
            })
        ));
    }
    assert_eq!(
        integrity::snapshot(&f.directory.0.join("destination"))?,
        before
    );
    Ok(())
}

#[test]
fn corrupt_or_missing_unselected_windows_and_pages_refuse_even_empty_movie_queries() -> Test {
    for case in 0..4 {
        let (mut f, request) = if case >= 2 {
            let (f, request) = avc_pages(&format!("movie-pages-damage-{case}"), 0, 0, false)?;
            (f, Some(request))
        } else {
            (
                Fixture::avc(&format!("movie-catalog-damage-{case}"), 4, 0, false)?,
                None,
            )
        };
        let receipt = match &request {
            Some(request) => run_pages(&mut f, request)?,
            None => f.run()?,
        };
        let retained = f.retained(&receipt)?;
        // A previously successful handle cannot substitute its warm state for current custody.
        select(&f, &retained, 0..1, origin_allowance(&f), &f.cx)?;
        let digest = match &request {
            Some(request) if case == 2 => {
                let root = request.pages[1].root;
                ObjectManifest::from_canonical_bytes(f.originals.get(&root).ok_or("page root")?)?
                    .metadata_digest()
                    .ok_or("page index")?
            }
            Some(request) => request.pages[1].root,
            None => f.original_packs[1],
        };
        let path = f.target()?.publisher().spool().object_path(digest);
        if matches!(case, 0 | 2) {
            let mut bytes = fs::read(&path)?;
            *bytes.last_mut().ok_or("empty native object")? ^= 1;
            let mut permissions = fs::metadata(&path)?.permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            permissions.set_readonly(false);
            fs::set_permissions(&path, permissions)?;
            fs::write(&path, bytes)?;
        } else {
            fs::rename(&path, path.with_extension("withheld-by-test"))?;
        }
        let before = integrity::snapshot(&f.directory.0.join("destination"))?;
        for query in [0..1, 1_000_000..1_000_001] {
            assert!(select(&f, &retained, query, origin_allowance(&f), &f.cx).is_err());
        }
        assert_eq!(
            integrity::snapshot(&f.directory.0.join("destination"))?,
            before
        );
        assert_eq!(
            f.source.as_ref().ok_or("archive")?.spool().read(digest)?,
            *f.originals.get(&digest).ok_or("original archive bytes")?
        );
    }
    Ok(())
}

#[test]
fn catalog_and_page_movie_inputs_refuse_native_gaps_or_changed_initialization() -> Test {
    for (gap, changed) in [(3600, false), (0, true)] {
        for pages in [false, true] {
            let label = format!("movie-continuity-{gap}-{changed}-{pages}");
            let (mut f, request) = if pages {
                let (f, request) = avc_pages(&label, 90_000, gap, changed)?;
                (f, Some(request))
            } else {
                (Fixture::avc(&label, 4, gap, changed)?, None)
            };
            let before = integrity::snapshot(&f.directory.0.join("destination"))?;
            let refused = match &request {
                Some(request) => run_pages(&mut f, request),
                None => f.run(),
            };
            assert!(refused.is_err());
            assert_eq!(
                integrity::snapshot(&f.directory.0.join("destination"))?,
                before
            );
        }
    }
    Ok(())
}

#[test]
fn cancellation_during_catalog_origin_replay_and_final_selection_is_atomic() -> Test {
    for pages in [false, true] {
        let (mut f, request) = if pages {
            let (f, request) = avc_pages("movie-pages-cancel", 0, 0, false)?;
            (f, Some(request))
        } else {
            (Fixture::avc("movie-catalog-cancel", 4, 0, false)?, None)
        };
        let receipt = match &request {
            Some(request) => run_pages(&mut f, request)?,
            None => f.run()?,
        };
        let retained = f.retained(&receipt)?;
        let before = integrity::snapshot(&f.directory.0.join("destination"))?;
        for (stage, occurrence) in [
            ("file_retained:movie_source", 1),
            ("rtsp_import:source_custody", 1),
            ("file_retained:movie_origin", 1),
            ("file_retained:movie_origin", 10),
            ("file_retained:movie_select", 2),
            ("file_retained:movie_complete", 1),
        ] {
            let cancelled = context(&f.directory.0.join("destination"))?;
            cancelled.set_cancel_at_checkpoint_occurrence(stage, occurrence);
            assert!(
                matches!(
                    retained.select_movie_interval_with_origin_limit(
                        f.target()?,
                        12_600..16_200,
                        RetainedReadLimits::default(),
                        MovieSelectionLimits::default(),
                        origin_allowance(&f),
                        &cancelled,
                    ),
                    Err(FileIngestError::CancellationRequested { .. })
                ),
                "{stage} occurrence {occurrence}, pages={pages}"
            );
            assert!(cancelled.is_drain_completed());
            assert_eq!(
                integrity::snapshot(&f.directory.0.join("destination"))?,
                before
            );
        }
        let retry = select(&f, &retained, 12_600..16_200, origin_allowance(&f), &f.cx)?;
        assert_samples(
            &retry.selection,
            &[(3, 12_600, 14_400), (4, 14_400, 16_200)],
        );
        assert_eq!(
            integrity::snapshot(&f.directory.0.join("destination"))?,
            before
        );
    }
    Ok(())
}
