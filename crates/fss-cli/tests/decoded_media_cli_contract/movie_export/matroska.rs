#![forbid(unsafe_code)]
//! Original MKV/WebM -> immutable timeline selection -> exact screened native review bytes.

use super::*;

const AVC_MKV: &[u8] = include_bytes!("../../../../fss-container/tests/fixtures/avc_av.mkv");
const HEVC_MKV: &[u8] = include_bytes!("../../../../fss-container/tests/fixtures/hevc_av.mkv");
const AVC_MP4: &[u8] =
    include_bytes!("../../../../fss-container/tests/fixtures/interleaved_av.mp4");

#[test]
fn matroska_exports_original_avc_and_hevc_pictures_at_exact_presentation_times() -> TestResult {
    // These MKV fixtures are byte-preserving remuxes of the independent MP4 decode oracles.
    // Their 128 ms lead is retained; timestamps and expected indices are fixture facts.
    for (name, source, oracle, start, indices) in [
        ("mkv-avc-export", AVC_MKV, AVC_MP4, 528_000_000, [3, 1]),
        ("mkv-hevc-export", HEVC_MKV, HEVC, 128_000_000, [0, 2]),
    ] {
        let movie = Movie::import(name, source)?;
        let images = selected(&native_images(oracle)?, &indices)?;
        let before = movie.journals()?;
        let end = start + 400_000_000;
        let path = movie.path("selected.pgm");
        let output = movie.export(start..end, "pgm", &path).output()?;
        success(&output);
        assert_eq!(fs::read(&path)?, rendered("pgm", &images)?);
        assert_eq!(field(&output, "selection_movie_tick_unit")?, "nanosecond");
        assert_eq!(field(&output, "movie_timescale")?, "1000000000");
        assert_eq!(field(&output, "media_timescale")?, "1000000000");
        assert_eq!(field(&output, "movie_output_frames")?, "2");
        assert_eq!(
            field(&output, "movie_output_lineage_domain")?,
            "fss.file_movie_output.v2"
        );
        assert_eq!(
            values(&output, "frame_segment")?,
            indices.map(|index| index.to_string())
        );

        let timed_path = movie.path("selected.mkv");
        let timed = movie.export_movie_timed(start..end, &timed_path).output()?;
        success(&timed);
        assert_movie_timing(&timed, 400_000_000)?;
        assert_eq!(
            fs::read(&timed_path)?,
            rendered_movie_timed(
                &images,
                &[(0, 200_000_000), (200_000_000, 400_000_000)],
                400_000_000
            )?
        );
        assert_eq!(movie.journals()?, before);
    }
    Ok(())
}

#[test]
fn matroska_hevc_requested_rasl_refuses_export_without_output_or_journal_changes() -> TestResult {
    let movie = Movie::import("mkv-hevc-requested-rasl", HEVC_MKV)?;
    let before = movie.journals()?;
    // Source segment 5 presents at 728 ms. Its closest random-access bootstrap is CRA
    // segment 3 (1128 ms); starting there skips leading RASL segments 4 and 5. Container
    // selection may quote that span, but export must not replace the missing wanted picture.
    let selection = command(&movie.root, "select-movie")
        .args([
            "--import-id",
            &movie.identity,
            "--start-movie-tick",
            "728000000",
            "--end-movie-tick",
            "928000000",
        ])
        .output()?;
    success(&selection);
    assert_eq!(field(&selection, "selection_source_format")?, "mkvhevc");
    assert_eq!(field(&selection, "selected_presentation_count")?, "1");
    assert!(values(&selection, "movie_sample")?[0].contains("segment=5 "));
    assert!(values(&selection, "decode_span")?[0].contains("start_segment=3 segment_count=3 "));

    for timed in [false, true] {
        let path = movie.path(if timed {
            "missing-rasl.mkv"
        } else {
            "missing-rasl.pgm"
        });
        let output = if timed {
            movie
                .export_movie_timed(728_000_000..928_000_000, &path)
                .output()?
        } else {
            movie
                .export(728_000_000..928_000_000, "pgm", &path)
                .output()?
        };
        incomplete(&output)?;
        assert_eq!(values(&output, "movie_skipped_rasl_segment")?, ["4", "5"]);
        assert!(!path.exists());
        assert_eq!(movie.journals()?, before);
    }
    Ok(())
}

#[test]
fn matroska_and_webm_selection_coexist_with_an_open_writer_without_media_disclosure() -> TestResult
{
    let mut webm = AVC_MKV.to_vec();
    let at = webm
        .windows(8)
        .position(|value| value == b"matroska")
        .ok_or("document type")?;
    webm[at..at + 8].copy_from_slice(b"webm\0\0\0\0");
    for (label, bytes) in [
        ("mkv-writer-preview", AVC_MKV),
        ("webm-writer-preview", webm.as_slice()),
    ] {
        let movie = Movie::import(label, bytes)?;
        let cx = context(&movie.root)?;
        let writer = ReferenceDeployment::open(&movie.root, SITE, &cx)?;
        let before = movie.journals()?;
        let output = command(&movie.root, "select-movie")
            .args([
                "--import-id",
                &movie.identity,
                "--start-movie-tick",
                "528000000",
                "--end-movie-tick",
                "928000000",
            ])
            .output()?;
        success(&output);
        assert_eq!(field(&output, "selection_source_format")?, "mkvavc");
        assert_eq!(field(&output, "selection_movie_tick_unit")?, "nanosecond");
        assert_eq!(field(&output, "deployment_mutated")?, "false");
        assert_eq!(field(&output, "selected_presentation_count")?, "2");
        assert_eq!(field(&output, "selection_decoded_frames")?, "0");
        assert_eq!(field(&output, "selection_media_exported")?, "false");
        assert_eq!(field(&output, "selection_absence_certifiable")?, "false");
        assert_eq!(field(&output, "selection_complete")?, "true");
        let rows = values(&output, "movie_sample")?;
        assert!(rows[0].contains("segment=3 "));
        assert!(rows[1].contains("segment=1 "));
        assert_eq!(movie.journals()?, before);
        drop(writer);
    }
    Ok(())
}

#[test]
fn matroska_export_refuses_preroll_and_source_limits_without_creating_output() -> TestResult {
    let movie = Movie::import("mkv-export-budget", AVC_MKV)?;
    let before = movie.journals()?;
    for (ordinal, option, value) in [
        (0, "--max-decode-samples", "2"),
        (1, "--max-source-bytes", "1"),
        (2, "--selection-work-units", "1"),
    ] {
        let path = movie.path(&format!("refused-{ordinal}.pgm"));
        let output = movie
            .export(528_000_000..928_000_000, "pgm", &path)
            .args([option, value])
            .output()?;
        incomplete(&output)?;
        assert!(!path.exists());
        assert_eq!(movie.journals()?, before);
    }
    Ok(())
}
