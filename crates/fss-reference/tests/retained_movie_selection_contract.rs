#![forbid(unsafe_code)]
//! Movie-time metadata remains bound to original bytes, completed custody and read admission.

#[allow(dead_code)]
#[path = "support/import_integrity.rs"]
mod support;

use std::{
    fs,
    ops::Range,
    path::{Path, PathBuf},
};

use fss_container::demux::{AvcMp4, DemuxError, DemuxLimits, MovieSelectionLimits, VideoCodec};
use fss_core::ContentDigest;
use fss_object::SpoolError;
use fss_reference::deletion::{commit_deletion, plan_deletion};
use fss_reference::ingest::{
    FileIngestAdapter, FileIngestError, FileIngestReceipt, RetainedFileImport,
    RetainedMovieSelection, RetainedReadLimits,
};
use fss_reference::{ReferenceDeployment, ReplayCx};
use support::{TestResult, cx, directory, request, snapshot};

const SITE: &str = "site:retained-movie-query";

struct Fixture {
    root: PathBuf,
    deployment: ReferenceDeployment,
    receipt: FileIngestReceipt,
    retained: RetainedFileImport,
    context: ReplayCx,
    source: Vec<u8>,
}

impl Fixture {
    fn new(label: &str, name: &str) -> TestResult<Self> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fss-container/tests/fixtures")
            .join(name);
        Self::from_bytes(label, fs::read(path)?)
    }

    fn from_bytes(label: &str, source: Vec<u8>) -> TestResult<Self> {
        let dir = directory(label)?;
        let input = dir.join("original.mp4");
        fs::write(&input, &source)?;
        let root = dir.join("deployment");
        let context = cx(label)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &context)?;
        let mut import = request()?;
        import.path = input.clone();
        import.format_hint = None;
        import.limits.chunk_bytes = 1024;
        import.limits.max_batch_deltas = 3;
        let receipt = FileIngestAdapter::ingest(import, &context, &mut deployment)?;
        // The original pathname is absent after restart; all queries must use retained custody.
        fs::rename(input, dir.join("former-original.mp4"))?;
        drop(deployment);
        let deployment = ReferenceDeployment::open(&root, SITE, &context)?;
        let retained = RetainedFileImport::open(
            &deployment,
            receipt.import_identity,
            RetainedReadLimits::default(),
            &context,
        )?;
        Ok(Self {
            root,
            deployment,
            receipt,
            retained,
            context,
            source,
        })
    }

    fn select(&self, query: Range<u64>) -> Result<RetainedMovieSelection, FileIngestError> {
        self.retained.select_movie_interval(
            &self.deployment,
            query,
            RetainedReadLimits::default(),
            MovieSelectionLimits::default(),
            &self.context,
        )
    }
}

#[test]
fn cold_chunked_original_produces_exact_movie_mapping_without_any_write() -> TestResult {
    let f = Fixture::new("movie-cold-partitioned", "indexed_avc.mp4")?;
    let before = snapshot(&f.root)?;
    let report = f.select(0..2000)?;
    assert_eq!(report.import_identity, f.receipt.import_identity);
    assert_eq!(report.import_root, f.receipt.import_root);
    assert_eq!(report.manifest_digest, f.receipt.manifest_digest);
    assert_eq!(&report.authority_anchor, f.retained.authority_anchor());
    assert_eq!(report.input_sha256, ContentDigest::sha256(&f.source));
    assert_eq!(report.input_bytes, 4338);
    assert_eq!(report.source_bytes_read, 4338);
    assert_eq!(report.track_id, 1);
    assert_eq!(report.codec, VideoCodec::Avc);
    assert_eq!(report.capture_time_label, "unknown");
    assert_eq!(report.selection.movie_timescale, 1000);
    assert_eq!(report.selection.samples.len(), 10);
    assert!(report.selection.gaps.is_empty());
    let direct = AvcMp4::parse(&f.source, None, DemuxLimits::default())?
        .select_movie_interval(0..2000, MovieSelectionLimits::default())?;
    assert_eq!(report.selection, direct);
    for sample in &report.selection.samples {
        let retained = &f.receipt.manifest.segment_spans[sample.sample_index];
        assert_eq!(sample.source.start as u64, retained.offset);
        assert_eq!(sample.source.len() as u64, retained.len);
    }
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn audio_mov_fragmented_and_inband_sources_use_their_original_movie_tables() -> TestResult {
    for (index, name) in [
        "interleaved_av.mp4",
        "fragmented_av.mp4",
        "hevc_av.mp4",
        "hevc_fragmented_av.mp4",
        "qt_av.mov",
        "qt_hevc.mov",
        "inband/avc3_partial_change.mp4",
        "inband/hev1_partial_change.mp4",
    ]
    .iter()
    .enumerate()
    {
        let f = Fixture::new(&format!("movie-layout-{index}"), name)?;
        let before = snapshot(&f.root)?;
        let original = AvcMp4::parse_inband(&f.source, None, DemuxLimits::default())?;
        let query = 0..u64::from(original.movie_timescale()) * 10;
        let expected =
            original.select_movie_interval(query.clone(), MovieSelectionLimits::default())?;
        let report = f.select(query)?;
        assert_eq!(report.selection, expected, "{name}");
        assert_eq!(report.codec, original.codec(), "{name}");
        assert_eq!(report.source_bytes_read, f.source.len() as u64, "{name}");
        assert!(!report.selection.samples.is_empty(), "{name}");
        assert_eq!(snapshot(&f.root)?, before, "{name}");
    }
    Ok(())
}

#[test]
fn recoverable_fragment_tail_is_authenticated_without_inventing_more_samples() -> TestResult {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fss-container/tests/fixtures/fragmented_av.mp4");
    let mut source = fs::read(path)?;
    // Cut inside the second mdat; the same importer/parser admission retains only complete
    // fragments, preserving the remainder as an explicit source-linked truncated tail.
    let mut at = 0;
    let mut mdats = 0;
    let mut cut = None;
    while at + 8 <= source.len() {
        let len = u32::from_be_bytes(source[at..at + 4].try_into()?) as usize;
        if len < 8 || at + len > source.len() {
            return Err("invalid fixture atom".into());
        }
        if &source[at + 4..at + 8] == b"mdat" {
            mdats += 1;
            if mdats == 2 {
                cut = Some(at + len / 2);
                break;
            }
        }
        at += len;
    }
    source.truncate(cut.ok_or("missing second fixture mdat")?);
    let f = Fixture::from_bytes("movie-truncated-tail", source)?;
    let before = snapshot(&f.root)?;
    let parsed =
        AvcMp4::parse_inband_recovering_tail(&f.source, None, DemuxLimits::default(), &mut || {
            Ok(())
        })?;
    assert!(parsed.truncated_tail().is_some());
    let report = f.select(0..10_000)?;
    assert_eq!(
        report.selection,
        parsed.select_movie_interval(0..10_000, MovieSelectionLimits::default())?
    );
    assert!(report.selection.samples.len() < 10);
    assert!(!report.selection.gaps.is_empty());
    assert_eq!(report.source_bytes_read, f.source.len() as u64);
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn selected_decode_budget_never_substitutes_for_full_source_read_admission() -> TestResult {
    let f = Fixture::new("movie-budget", "indexed_avc.mp4")?;
    let before = snapshot(&f.root)?;
    let narrow = f.select(0..1)?;
    assert!(!narrow.selection.samples.is_empty());
    assert!(narrow.selection.decode_bytes < f.source.len() as u64);
    let exact_decode = MovieSelectionLimits {
        max_source_bytes: narrow.selection.decode_bytes,
        ..MovieSelectionLimits::default()
    };
    let report = f.retained.select_movie_interval(
        &f.deployment,
        0..1,
        RetainedReadLimits::default(),
        exact_decode,
        &f.context,
    )?;
    assert_eq!(report.source_bytes_read, f.source.len() as u64);
    assert_eq!(report.selection, narrow.selection);
    assert!(matches!(
        f.retained.select_movie_interval(
            &f.deployment,
            0..1,
            RetainedReadLimits::default(),
            MovieSelectionLimits {
                max_source_bytes: narrow.selection.decode_bytes - 1,
                ..exact_decode
            },
            &f.context,
        ),
        Err(FileIngestError::Mp4Refused {
            refusal: DemuxError::Limit
        })
    ));
    assert!(
        f.retained
            .select_movie_interval(
                &f.deployment,
                0..1,
                RetainedReadLimits {
                    max_source_bytes: f.source.len() as u64 - 1,
                    ..RetainedReadLimits::default()
                },
                exact_decode,
                &f.context,
            )
            .is_err()
    );
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn cached_handle_refuses_corrupt_custody_even_for_a_query_with_no_selected_samples() -> TestResult {
    for target in 0..3 {
        let f = Fixture::new(&format!("movie-corruption-{target}"), "indexed_avc.mp4")?;
        let digest = match target {
            0 => f.receipt.import_root,
            1 => f.receipt.manifest_digest,
            _ => *f
                .receipt
                .manifest
                .ordered_chunks
                .last()
                .ok_or("missing chunk")?,
        };
        let path = f.deployment.publisher().spool().object_path(digest);
        let mut bytes = fs::read(&path)?;
        *bytes.last_mut().ok_or("empty test object")? ^= 1;
        let mut permissions = fs::metadata(&path)?.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        fs::set_permissions(&path, permissions)?;
        fs::write(path, bytes)?;
        let before = snapshot(&f.root)?;
        assert!(f.select(1_000_000..1_000_001).is_err(), "target {target}");
        assert_eq!(snapshot(&f.root)?, before);
    }
    Ok(())
}

#[test]
fn missing_root_or_source_chunk_refuses_without_a_partial_selection() -> TestResult {
    for source in [false, true] {
        let f = Fixture::new(&format!("movie-missing-{source}"), "indexed_avc.mp4")?;
        let digest = if source {
            f.receipt.manifest.ordered_chunks[0]
        } else {
            f.receipt.import_root
        };
        let path = f.deployment.publisher().spool().object_path(digest);
        fs::rename(&path, path.with_extension("withheld-by-test"))?;
        let before = snapshot(&f.root)?;
        assert!(f.select(0..1000).is_err());
        assert_eq!(snapshot(&f.root)?, before);
    }
    Ok(())
}

#[test]
fn cancellation_at_source_parse_index_selection_or_final_revalidation_is_atomic() -> TestResult {
    let f = Fixture::new("movie-cancellation", "indexed_avc.mp4")?;
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
            "movie-cut-{occurrence}-{}",
            stage.replace(':', "-")
        ))?;
        cancelled.set_cancel_at_checkpoint_occurrence(stage, occurrence);
        assert!(
            matches!(
                f.retained.select_movie_interval(
                    &f.deployment,
                    0..2000,
                    RetainedReadLimits::default(),
                    MovieSelectionLimits::default(),
                    &cancelled,
                ),
                Err(FileIngestError::CancellationRequested { .. })
            ),
            "{stage}"
        );
        assert_eq!(snapshot(&f.root)?, before);
    }
    Ok(())
}

#[test]
fn exhausted_owner_read_budget_remains_typed_and_invalid_queries_do_no_io() -> TestResult {
    let mut f = Fixture::new("movie-spool-budget", "indexed_avc.mp4")?;
    f.deployment.publisher_mut().tighten_read_budget(0, 0)?;
    let before = snapshot(&f.root)?;
    for (start, end) in [(0, 0), (2, 1)] {
        let query = start..end;
        assert!(matches!(
            f.select(query),
            Err(FileIngestError::Mp4Refused {
                refusal: DemuxError::Timeline
            })
        ));
    }
    assert!(matches!(
        f.retained.select_movie_interval(
            &f.deployment,
            0..1,
            RetainedReadLimits::default(),
            MovieSelectionLimits {
                max_rows: 0,
                ..MovieSelectionLimits::default()
            },
            &f.context,
        ),
        Err(FileIngestError::Mp4Refused {
            refusal: DemuxError::Limit
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
        f.select(0..1),
        Err(FileIngestError::Spool(
            SpoolError::ReadBudgetExceeded { .. }
        ))
    ));
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn an_open_handle_cannot_select_deleted_evidence() -> TestResult {
    let mut f = Fixture::new("movie-deleted", "indexed_avc.mp4")?;
    let plan = plan_deletion(&f.deployment, f.receipt.import_identity, &f.context)?;
    assert!(plan.blockers.is_empty());
    let principal = "operator:retained-movie-deletion-test";
    let digest = plan.digest()?;
    commit_deletion(
        &mut f.deployment,
        digest,
        plan.approval_digest(principal)?,
        principal,
        &f.context,
    )?;
    let before = snapshot(&f.root)?;
    assert!(
        matches!(f.select(0..1), Err(FileIngestError::EvidenceDeleted {
        import_identity, plan_digest,
    }) if import_identity == f.receipt.import_identity && plan_digest == digest)
    );
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}
