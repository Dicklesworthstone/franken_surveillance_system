#![forbid(unsafe_code)]
//! Matroska presentation queries preserve complete original custody and explicit uncertainty.

use super::*;
use fss_container::demux::MatroskaVideo;
use fss_reference::retained_source::{ImmutableRetainedReadLimits, ImmutableRetainedSource};

const WHOLE: Range<u64> = 0..3_000_000_000;
const NARROW: Range<u64> = 400_000_000..600_000_000;

fn parsed(source: &[u8]) -> Result<MatroskaVideo<'_>, DemuxError> {
    MatroskaVideo::parse_recovering_tail(source, None, DemuxLimits::default(), &mut || Ok(()))
}

#[test]
fn cold_avc_hevc_and_live_sources_keep_exact_nanosecond_mapping_and_custody() -> TestResult {
    for (name, format, codec) in [
        ("avc_av.mkv", "mkvavc", VideoCodec::Avc),
        ("avc_live.mkv", "mkvavc", VideoCodec::Avc),
        ("hevc_av.mkv", "mkvhevc", VideoCodec::Hevc),
    ] {
        let f = Fixture::new("matroska-movie-cold", name)?;
        let before = snapshot(&f.root)?;
        let original = parsed(&f.source)?;
        let report = f.select(WHOLE)?;
        assert_eq!(report.import_identity, f.receipt.import_identity, "{name}");
        assert_eq!(report.import_root, f.receipt.import_root, "{name}");
        assert_eq!(report.manifest_digest, f.receipt.manifest_digest, "{name}");
        assert_eq!(&report.authority_anchor, f.retained.authority_anchor());
        assert_eq!(report.source_format, format, "{name}");
        assert_eq!(report.track_id, original.track_number(), "{name}");
        assert_eq!(report.codec, codec, "{name}");
        assert_eq!(report.input_sha256, ContentDigest::sha256(&f.source));
        assert_eq!(report.source_bytes_read, f.source.len() as u64);
        assert_eq!(report.input_bytes, report.source_bytes_read);
        assert_eq!(report.origin_read_bytes_charged, 0);
        assert_eq!(report.capture_time_label, "unknown");
        assert_eq!(report.selection.movie_timescale, 1_000_000_000);
        assert_eq!(report.selection.media_timescale, 1_000_000_000);
        assert_eq!(report.selection.samples.len(), original.samples().len());
        assert_eq!(
            report.selection,
            original.select_movie_interval(WHOLE, MovieSelectionLimits::default())?,
            "{name}"
        );
        assert!(!report.selection.gaps.is_empty(), "{name}");
        for selected in &report.selection.samples {
            let retained = &f.receipt.manifest.segment_spans[selected.sample_index];
            assert_eq!(selected.source.start as u64, retained.offset);
            assert_eq!(selected.source.len() as u64, retained.len);
        }
        assert_eq!(snapshot(&f.root)?, before, "{name}");
    }
    Ok(())
}

#[test]
fn webm_document_type_keeps_the_same_presentation_and_original_identity_scope() -> TestResult {
    let mut bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fss-container/tests/fixtures/avc_av.mkv"
    ))
    .to_vec();
    let at = bytes
        .windows(8)
        .position(|window| window == b"matroska")
        .ok_or("missing Matroska document type")?;
    bytes[at..at + 8].copy_from_slice(b"webm\0\0\0\0");
    let f = Fixture::from_bytes("webm-movie", bytes)?;
    let before = snapshot(&f.root)?;
    let report = f.select(NARROW)?;
    assert_eq!(report.source_format, "mkvavc");
    assert_eq!(report.input_sha256, ContentDigest::sha256(&f.source));
    assert_eq!(
        report.selection,
        parsed(&f.source)?.select_movie_interval(NARROW, MovieSelectionLimits::default())?
    );
    assert!(report.selection.decode_bytes > report.selection.sample_bytes);
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn a_cut_live_cluster_preserves_tail_bytes_without_claiming_the_missing_frame() -> TestResult {
    let mut bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fss-container/tests/fixtures/avc_live.mkv"
    ))
    .to_vec();
    let cluster = parsed(&bytes)?
        .elements()
        .iter()
        .rev()
        .find(|element| element.name == "cluster")
        .ok_or("missing live cluster")?
        .range
        .clone();
    bytes.truncate(cluster.start + cluster.len() / 2);
    let f = Fixture::from_bytes("matroska-movie-tail", bytes)?;
    let before = snapshot(&f.root)?;
    let original = parsed(&f.source)?;
    assert_eq!(original.truncated_tail(), Some(cluster.start));
    let report = f.select(WHOLE)?;
    assert_eq!(report.selection.samples.len(), 9);
    assert_eq!(report.source_bytes_read, f.source.len() as u64);
    assert_eq!(
        report.selection,
        original.select_movie_interval(WHOLE, MovieSelectionLimits::default())?
    );
    assert!(!report.selection.gaps.is_empty());
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn a_narrow_decode_allowance_never_exempts_unselected_original_bytes() -> TestResult {
    let f = Fixture::new("matroska-movie-budget", "avc_av.mkv")?;
    let before = snapshot(&f.root)?;
    let expected = f.select(NARROW)?;
    assert!(!expected.selection.samples.is_empty());
    assert!(expected.selection.decode_bytes < f.source.len() as u64);
    let exact = MovieSelectionLimits {
        max_source_bytes: expected.selection.decode_bytes,
        ..MovieSelectionLimits::default()
    };
    let report = f.retained.select_movie_interval_with_origin_limit(
        &f.deployment,
        NARROW,
        RetainedReadLimits::default(),
        exact,
        0,
        &f.context,
    )?;
    assert_eq!(report.selection, expected.selection);
    assert_eq!(report.source_bytes_read, f.source.len() as u64);
    assert_eq!(report.maximum_origin_read_bytes, 0);
    assert!(matches!(
        f.retained.select_movie_interval(
            &f.deployment,
            NARROW,
            RetainedReadLimits::default(),
            MovieSelectionLimits {
                max_source_bytes: exact.max_source_bytes - 1,
                ..exact
            },
            &f.context,
        ),
        Err(FileIngestError::MatroskaRefused {
            refusal: DemuxError::Limit
        })
    ));
    assert!(
        f.retained
            .select_movie_interval(
                &f.deployment,
                NARROW,
                RetainedReadLimits {
                    max_source_bytes: f.source.len() as u64 - 1,
                    ..RetainedReadLimits::default()
                },
                exact,
                &f.context,
            )
            .is_err()
    );
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn missing_duration_refuses_time_selection_but_keeps_a_valid_ordinal_import() -> TestResult {
    let mut bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fss-container/tests/fixtures/avc_av.mkv"
    ))
    .to_vec();
    let tracks = parsed(&bytes)?
        .elements()
        .iter()
        .find(|element| element.name == "tracks")
        .ok_or("missing tracks")?
        .range
        .clone();
    // Preserve every source offset while replacing the optional DefaultDuration with an
    // unknown element and the Tracks CRC with a same-width Void. Ordinal import needs neither.
    let at = bytes[tracks.clone()]
        .windows(3)
        .position(|window| window == [0x23, 0xe3, 0x83])
        .ok_or("missing default duration")?
        + tracks.start;
    bytes[at] = 0x22;
    let id_len = bytes[tracks.start].leading_zeros() as usize + 1;
    let size = tracks.start + id_len;
    let data = size + bytes[size].leading_zeros() as usize + 1;
    assert_eq!(&bytes[data..data + 2], &[0xbf, 0x84]);
    bytes[data] = 0xec;
    assert_eq!(parsed(&bytes)?.default_duration_ns(), None);
    let f = Fixture::from_bytes("matroska-movie-no-duration", bytes)?;
    assert_eq!(f.receipt.manifest.segment_spans.len(), 10);
    let before = snapshot(&f.root)?;
    for query in [NARROW, 20_000_000_000..20_000_000_001] {
        assert!(matches!(
            f.select(query),
            Err(FileIngestError::MatroskaRefused {
                refusal: DemuxError::Unsupported
            })
        ));
    }
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn unselected_corrupt_source_refuses_even_when_the_query_is_entirely_a_gap() -> TestResult {
    let f = Fixture::new("matroska-movie-corrupt", "hevc_av.mkv")?;
    let digest = *f
        .receipt
        .manifest
        .ordered_chunks
        .last()
        .ok_or("source chunk")?;
    let path = f.deployment.publisher().spool().object_path(digest);
    let mut bytes = fs::read(&path)?;
    *bytes.last_mut().ok_or("empty retained object")? ^= 1;
    let mut permissions = fs::metadata(&path)?.permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    fs::set_permissions(&path, permissions)?;
    fs::write(path, bytes)?;
    let before = snapshot(&f.root)?;
    assert!(f.select(20_000_000_000..20_000_000_001).is_err());
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn matroska_cancellation_and_invalid_query_refusals_are_atomic_and_typed() -> TestResult {
    let mut f = Fixture::new("matroska-movie-cancel", "avc_av.mkv")?;
    let before = snapshot(&f.root)?;
    for (stage, occurrence) in [
        ("file_retained:movie_source", 3),
        ("file_retained:movie_parse", 2),
        ("file_retained:movie_index", 3),
        ("file_retained:movie_select", 2),
        ("file_retained:open", 2),
        ("file_retained:movie_complete", 1),
    ] {
        let cancelled = cx(&format!(
            "matroska-cut-{occurrence}-{}",
            stage.replace(':', "-")
        ))?;
        cancelled.set_cancel_at_checkpoint_occurrence(stage, occurrence);
        assert!(
            matches!(
                f.retained.select_movie_interval(
                    &f.deployment,
                    WHOLE,
                    RetainedReadLimits::default(),
                    MovieSelectionLimits::default(),
                    &cancelled,
                ),
                Err(FileIngestError::CancellationRequested { .. })
            ),
            "{stage}"
        );
    }
    f.deployment.publisher_mut().tighten_read_budget(0, 0)?;
    assert!(matches!(
        f.select(1..1),
        Err(FileIngestError::MatroskaRefused {
            refusal: DemuxError::Timeline
        })
    ));
    assert_eq!(
        f.deployment
            .publisher()
            .spool()
            .read_budget_usage()
            .used_read_attempts,
        0
    );
    assert!(matches!(
        f.select(NARROW),
        Err(FileIngestError::Spool(
            SpoolError::ReadBudgetExceeded { .. }
        ))
    ));
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn immutable_writer_held_selection_and_final_validation_share_one_allowance() -> TestResult {
    let f = Fixture::new("matroska-movie-immutable", "hevc_av.mkv")?;
    let expected = f.select(NARROW)?;
    let before = snapshot(&f.root)?;
    let cx = super::immutable::read_context(&f.root)?;
    let limits = super::immutable::limits();
    let select = |source: &ImmutableRetainedSource<'_>| {
        f.retained.select_movie_interval(
            source,
            NARROW,
            RetainedReadLimits::default(),
            MovieSelectionLimits::default(),
            &cx,
        )
    };
    let measured = ImmutableRetainedSource::open(&f.root, limits, &cx)?;
    assert_eq!(select(&measured)?, expected);
    measured.revalidate()?;
    let used = measured.usage();
    let exact = ImmutableRetainedReadLimits {
        max_read_bytes: usize::try_from(used.read_bytes)?,
        max_read_objects: usize::try_from(used.read_objects)?,
        ..limits
    };
    let admitted = ImmutableRetainedSource::open(&f.root, exact, &cx)?;
    assert_eq!(select(&admitted)?, expected);
    admitted.revalidate()?;
    assert_eq!(admitted.usage(), used);
    for short in [
        ImmutableRetainedReadLimits {
            max_read_bytes: exact.max_read_bytes - 1,
            ..exact
        },
        ImmutableRetainedReadLimits {
            max_read_objects: exact.max_read_objects - 1,
            ..exact
        },
    ] {
        let source = ImmutableRetainedSource::open(&f.root, short, &cx)?;
        assert_eq!(select(&source)?, expected);
        assert!(source.revalidate().is_err());
        assert!(
            source.revalidate().is_err(),
            "final refusal refilled its read budget"
        );
    }
    assert_eq!(snapshot(&f.root)?, before);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn an_open_matroska_handle_cannot_select_deleted_evidence() -> TestResult {
    let mut f = Fixture::new("matroska-movie-deleted", "avc_av.mkv")?;
    let plan = plan_deletion(&f.deployment, f.receipt.import_identity, &f.context)?;
    assert!(plan.blockers.is_empty());
    let principal = "operator:retained-matroska-deletion-test";
    let digest = plan.digest()?;
    commit_deletion(
        &mut f.deployment,
        digest,
        plan.approval_digest(principal)?,
        principal,
        &f.context,
    )?;
    let before = snapshot(&f.root)?;
    assert!(matches!(
        f.select(NARROW),
        Err(FileIngestError::EvidenceDeleted { import_identity, plan_digest })
            if import_identity == f.receipt.import_identity && plan_digest == digest
    ));
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}
