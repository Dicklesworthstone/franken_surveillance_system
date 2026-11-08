#![forbid(unsafe_code)]
//! Real retained RTSP origins must replay before an exact movie selection is released.

#[allow(dead_code)]
#[path = "../support/import_integrity.rs"]
mod integrity;

use super::*;
use fss_container::demux::{AvcMp4, DemuxError, DemuxLimits, MovieSelectionLimits, VideoCodec};
use fss_reference::ingest::FileIngestError;
use fss_reference::ingest::retained::MAX_MOVIE_ORIGIN_READ_BYTES;
use integrity::snapshot;

fn original_bytes(fixture: &Fixture) -> u64 {
    fixture
        .original
        .iter()
        .map(|(_, bytes)| bytes.len() as u64)
        .sum()
}

#[test]
fn both_native_origins_select_after_archive_removal_and_destination_restart() -> Test {
    for codec in [RtspImportCodec::Avc, RtspImportCodec::Hevc] {
        let mut f = Fixture::new(&format!("movie-cold-{}", codec.as_str()), codec)?;
        let imported = f.run()?;
        drop(f.source.take());
        fs::remove_dir_all(&f.source_dir.0)?;
        drop(f.target.take());
        f.cx = context(&f.target_dir.0)?;
        f.target = Some(ReferenceDeployment::open(
            &f.target_dir.0,
            "site:rtsp-import",
            &f.cx,
        )?);
        let retained = f.retained(&imported)?;
        let before = snapshot(&f.target_dir.0)?;
        let report = retained.select_movie_interval(
            f.target()?,
            0..90_000,
            RetainedReadLimits::default(),
            MovieSelectionLimits::default(),
            &f.cx,
        )?;
        let direct = AvcMp4::parse(&f.mp4, None, DemuxLimits::default())?
            .select_movie_interval(0..90_000, MovieSelectionLimits::default())?;
        assert_eq!(report.selection, direct);
        assert_eq!(report.selection.samples.len(), imported.frames);
        assert_eq!(report.selection.movie_timescale, 90_000);
        assert_eq!(report.selection.media_timescale, 90_000);
        assert_eq!(report.import_identity, imported.import_identity);
        assert_eq!(report.import_root, imported.import_root);
        assert_eq!(report.manifest_digest, imported.manifest_digest);
        assert_eq!(&report.authority_anchor, retained.authority_anchor());
        assert_eq!(report.source_adapter_id, ADAPTER);
        assert_eq!(
            report.source_adapter_generation,
            retained.manifest().adapter_generation
        );
        assert_eq!(report.input_sha256, ContentDigest::sha256(&f.mp4));
        assert_eq!(report.input_bytes, f.mp4.len() as u64);
        assert_eq!(report.source_bytes_read, f.mp4.len() as u64);
        assert_eq!(report.origin_read_bytes_charged, original_bytes(&f));
        assert_eq!(
            report.maximum_origin_read_bytes,
            MAX_MOVIE_ORIGIN_READ_BYTES
        );
        assert_eq!(report.capture_time_label, "unknown");
        assert_eq!(
            report.codec,
            match codec {
                RtspImportCodec::Avc => VideoCodec::Avc,
                RtspImportCodec::Hevc => VideoCodec::Hevc,
            }
        );
        for selected in &report.selection.samples {
            let span = &retained.manifest().segment_spans[selected.sample_index];
            assert_eq!(selected.source.start as u64, span.offset);
            assert_eq!(selected.source.len() as u64, span.len);
        }
        assert_eq!(snapshot(&f.target_dir.0)?, before);
    }
    Ok(())
}

#[test]
fn nonzero_decode_origin_and_signed_composition_keep_native_movie_ticks() -> Test {
    let packets = hevc_recording_support::packets()?;
    let mut timings = hevc_recording_support::timings(4);
    for timing in &mut timings {
        timing.decode_time += 90_000;
    }
    timings[1].composition_offset = 18_000;
    timings[2].composition_offset = -18_000;
    let plan = hevc_recording_support::prepare(&packets, &timings)?;
    let mut f = Fixture::from_plan(
        "movie-presentation",
        RtspImportCodec::Hevc,
        plan.publication_plan(),
    )?;
    let imported = f.run()?;
    let retained = f.retained(&imported)?;
    let before = snapshot(&f.target_dir.0)?;
    let report = retained.select_movie_interval(
        f.target()?,
        112_500..139_500,
        RetainedReadLimits::default(),
        MovieSelectionLimits::default(),
        &f.cx,
    )?;
    assert_eq!(
        report
            .selection
            .samples
            .iter()
            .map(|sample| sample.sample_index)
            .collect::<Vec<_>>(),
        [2, 1]
    );
    assert!(report.selection.gaps.is_empty());
    for (sample, expected) in report
        .selection
        .samples
        .iter()
        .zip([112_500_u128..126_000, 126_000..139_500])
    {
        assert_eq!(sample.interval.denominator, 90_000);
        assert_eq!(sample.interval.start_numerator, expected.start * 90_000);
        assert_eq!(sample.interval.end_numerator, expected.end * 90_000);
        assert_eq!(sample.edit_index, None);
    }
    assert_eq!(report.capture_time_label, "unknown");
    let before_origin = retained.select_movie_interval(
        f.target()?,
        0..90_000,
        RetainedReadLimits::default(),
        MovieSelectionLimits::default(),
        &f.cx,
    )?;
    assert!(before_origin.selection.samples.is_empty());
    assert_eq!(before_origin.selection.gaps.len(), 1);
    assert_eq!(before_origin.origin_read_bytes_charged, original_bytes(&f));
    assert_eq!(snapshot(&f.target_dir.0)?, before);
    Ok(())
}

#[test]
fn native_origin_quota_is_exact_independent_and_reserved_before_payload_io() -> Test {
    let mut f = Fixture::new("movie-origin-budget", RtspImportCodec::Hevc)?;
    let imported = f.run()?;
    let retained = f.retained(&imported)?;
    let total = original_bytes(&f);
    let before = snapshot(&f.target_dir.0)?;
    let report = retained.select_movie_interval_with_origin_limit(
        f.target()?,
        0..1,
        RetainedReadLimits::default(),
        MovieSelectionLimits::default(),
        total,
        &f.cx,
    )?;
    assert_eq!(report.origin_read_bytes_charged, total);
    assert_eq!(report.maximum_origin_read_bytes, total);
    assert_eq!(report.source_bytes_read, f.mp4.len() as u64);
    assert!(matches!(
        retained.select_movie_interval_with_origin_limit(
            f.target()?,
            0..1,
            RetainedReadLimits::default(),
            MovieSelectionLimits::default(),
            total - 1,
            &f.cx,
        ),
        Err(FileIngestError::SpoolCapacityExceeded {
            limit: "movie_origin_read_bytes",
            required,
            available,
        }) if required == total && available == total - 1
    ));
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
                total,
                &f.cx,
            )
            .is_err()
    );
    let attempts = f
        .target()?
        .publisher()
        .spool()
        .read_budget_usage()
        .used_read_attempts;
    assert!(matches!(
        retained.select_movie_interval_with_origin_limit(
            f.target()?,
            0..1,
            RetainedReadLimits::default(),
            MovieSelectionLimits::default(),
            MAX_MOVIE_ORIGIN_READ_BYTES + 1,
            &f.cx,
        ),
        Err(FileIngestError::Mp4Refused {
            refusal: DemuxError::Limit
        })
    ));
    assert_eq!(
        f.target()?
            .publisher()
            .spool()
            .read_budget_usage()
            .used_read_attempts,
        attempts
    );
    // Membership names the native root without reading its payload. Withhold that object: a
    // zero allowance must refuse at the reservation, before a missing-object read could fail.
    let (digest, bytes) = f.original.first().ok_or("native root")?;
    let path = f.target()?.publisher().spool().object_path(*digest);
    let withheld = path.with_extension("movie-origin-budget-withheld");
    fs::rename(&path, &withheld)?;
    let result = retained.select_movie_interval_with_origin_limit(
        f.target()?,
        0..1,
        RetainedReadLimits::default(),
        MovieSelectionLimits::default(),
        0,
        &f.cx,
    );
    fs::rename(withheld, path)?;
    assert!(matches!(
        result,
        Err(FileIngestError::SpoolCapacityExceeded {
            limit: "movie_origin_read_bytes",
            required,
            available: 0,
        }) if required == bytes.len() as u64
    ));
    assert_eq!(snapshot(&f.target_dir.0)?, before);
    Ok(())
}

#[test]
fn intact_mp4_cannot_replace_missing_originals_or_recipe_even_for_empty_queries() -> Test {
    for codec in [RtspImportCodec::Avc, RtspImportCodec::Hevc] {
        let mut f = Fixture::new(&format!("movie-missing-{}", codec.as_str()), codec)?;
        let imported = f.run()?;
        let retained = f.retained(&imported)?;
        let before = snapshot(&f.target_dir.0)?;
        for digest in f
            .original
            .iter()
            .map(|(digest, _)| *digest)
            .chain(std::iter::once(imported.proof))
        {
            let path = f.target()?.publisher().spool().object_path(digest);
            let withheld = path.with_extension("movie-origin-withheld");
            fs::rename(&path, &withheld)?;
            let result = retained.select_movie_interval(
                f.target()?,
                1_000_000..1_000_001,
                RetainedReadLimits::default(),
                MovieSelectionLimits::default(),
                &f.cx,
            );
            fs::rename(withheld, path)?;
            assert!(result.is_err(), "missing {digest}");
            assert_eq!(snapshot(&f.target_dir.0)?, before);
        }
        let source = f.original.get(1).ok_or("native packets")?.0;
        let path = f.target()?.publisher().spool().object_path(source);
        let original_object = fs::read(&path)?;
        let mut damaged = original_object.clone();
        *damaged.last_mut().ok_or("native object bytes")? ^= 1;
        fs::write(&path, damaged)?;
        let result = retained.select_movie_interval(
            f.target()?,
            0..1,
            RetainedReadLimits::default(),
            MovieSelectionLimits::default(),
            &f.cx,
        );
        fs::write(path, original_object)?;
        assert!(result.is_err());
        assert_eq!(snapshot(&f.target_dir.0)?, before);
    }
    Ok(())
}

#[test]
fn native_replay_and_final_custody_cancellation_release_no_selection_or_writes() -> Test {
    let mut f = Fixture::new("movie-native-cancel", RtspImportCodec::Hevc)?;
    let imported = f.run()?;
    let retained = f.retained(&imported)?;
    let before = snapshot(&f.target_dir.0)?;
    for (stage, occurrence) in [
        ("file_retained:movie_origin", 1),
        ("file_retained:movie_origin", 3),
        ("file_retained:movie_origin", 5),
        ("file_retained:open", 2),
        ("file_retained:movie_complete", 1),
    ] {
        let cancelled = context(&f.target_dir.0)?;
        cancelled.set_cancel_at_checkpoint_occurrence(stage, occurrence);
        assert!(matches!(
            retained.select_movie_interval(
                f.target()?,
                0..90_000,
                RetainedReadLimits::default(),
                MovieSelectionLimits::default(),
                &cancelled,
            ),
            Err(FileIngestError::CancellationRequested { .. })
        ));
        assert_eq!(snapshot(&f.target_dir.0)?, before);
    }
    Ok(())
}

#[test]
fn an_open_native_handle_cannot_select_deleted_recording_evidence() -> Test {
    use fss_reference::deletion::{commit_deletion, plan_deletion};
    let mut f = Fixture::new("movie-native-deleted", RtspImportCodec::Avc)?;
    let imported = f.run()?;
    let retained = f.retained(&imported)?;
    let plan = plan_deletion(f.target()?, imported.import_identity, &f.cx)?;
    assert!(plan.blockers.is_empty());
    let principal = "operator:rtsp-movie-deletion-test";
    let digest = plan.digest()?;
    commit_deletion(
        f.target.as_mut().ok_or("target")?,
        digest,
        plan.approval_digest(principal)?,
        principal,
        &f.cx,
    )?;
    let before = snapshot(&f.target_dir.0)?;
    assert!(matches!(
        retained.select_movie_interval(
            f.target()?,
            0..1,
            RetainedReadLimits::default(),
            MovieSelectionLimits::default(),
            &f.cx,
        ),
        Err(FileIngestError::EvidenceDeleted {
            import_identity,
            plan_digest,
        }) if import_identity == imported.import_identity && plan_digest == digest
    ));
    assert_eq!(snapshot(&f.target_dir.0)?, before);
    Ok(())
}
