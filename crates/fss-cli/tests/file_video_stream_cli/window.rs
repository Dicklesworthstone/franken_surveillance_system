#![forbid(unsafe_code)]
//! Real retained video trimming under explicit source-time assumptions.

use super::*;
use fss_codec_jpeg_encode::{EncodeBudget, EncodeConfig, EncodeLimits, PixelFormat, encode_jpeg};

fn timed_setup(codec: &str) -> Test<(Directory, String, usize)> {
    let directory = Directory::new(&format!("window-{codec}"))?;
    let (bytes, format, count) = if codec == "avc" {
        (AVC, "annexb", 3)
    } else {
        (HEVC, "hevc", 8)
    };
    let input = directory.0.join("timed-source.bin");
    fs::write(&input, bytes)?;
    let output = run_command(
        Command::new(env!("CARGO_BIN_EXE_fss-file"))
            .arg("import")
            .arg("--root").arg(directory.root())
            .args(["--site", SITE, "--input"]).arg(&input)
            .args([
                "--sensor", "sensor:window-camera", "--stream", "stream:window-camera",
                "--receive-time-ns", "1000000000", "--media-format", format,
                "--capture-start-ns", "100000000", "--capture-uncertainty-ns", "1000",
                "--assumed-fps", "10",
            ]),
    )?;
    let imported = fields(&successful(output)?)?;
    let identity = one(&imported, "import_identity")?.to_owned();
    fs::remove_file(input)?;
    Ok((directory, identity, count))
}

fn window_request(base: &[OsString], output: &std::path::Path, window: &str, clock: &str, format: &str) -> Vec<OsString> {
    let mut request = export_args(base, output, 16 * 1024 * 1024);
    request.extend([
        "--output-format".into(), format.into(),
        "--output-window-ns".into(), window.into(),
        "--output-clock-basis".into(), clock.into(),
    ]);
    request
}

#[test]
fn both_native_codecs_export_only_selected_frames_with_exact_pgm_and_jpeg_bytes() -> Test {
    for codec in ["avc", "hevc"] {
        let (directory, identity, count) = timed_setup(codec)?;
        let base = args(&directory, &identity, count);
        let full_path = directory.0.join("full.pgm");
        let full = fields(&successful(raw(&export_args(&base, &full_path, 16 * 1024 * 1024))?)?)?;
        let bytes = fs::read(full_path)?;
        let width = HEADER.len() + PIXELS;
        assert_eq!(bytes.len(), count * width);
        let source_segments = full.get("frame_segment").ok_or("missing source segments")?;
        let wanted = source_segments.iter().position(|segment| segment == "1").ok_or("selected source segment absent")?;
        let expected_pgm = &bytes[wanted * width..(wanted + 1) * width];
        let luma = &expected_pgm[HEADER.len()..];
        let expected_jpeg = encode_jpeg(
            176, 144, luma, ContentDigest::sha256(luma).bytes(),
            EncodeConfig { quality: 85, format: PixelFormat::Grayscale },
            &EncodeLimits::default(), &mut EncodeBudget::new(100_000_000),
        )?;
        let before = journals(&directory)?;
        for format in ["pgm", "mjpeg"] {
            let output = directory.0.join(format!("selected.{format}"));
            let report = fields(&successful(raw(&window_request(
                &base, &output, "150000000:250000000", "estimated", format,
            ))?)?)?;
            assert_eq!(fs::read(&output)?, if format == "pgm" { expected_pgm } else { expected_jpeg.bytes() });
            assert_eq!(one(&report, "output_window_complete")?, "true");
            assert_eq!(one(&report, "output_window_time_provenance")?, "operator_assumption");
            assert_eq!(one(&report, "output_window_clock_basis")?, "estimated");
            assert_eq!(one(&report, "output_window_observed_frames")?, count.to_string());
            assert_eq!(one(&report, "output_window_selected_frames")?, "1");
            assert_eq!(one(&report, "output_window_skipped_frames")?, (count - 1).to_string());
            assert_eq!(one(&report, "output_window_selected_earliest_ns")?, "199999000");
            assert_eq!(one(&report, "output_window_selected_latest_ns")?, "200001000");
            assert_eq!(report.get("frame_segment"), Some(&vec!["1".to_owned()]));
            assert_eq!(one(&report, "output_window_timing_embedded")?, "false");
            assert_eq!(one(&report, "output_window_coverage_asserted")?, "false");
            assert_eq!(journals(&directory)?, before);
        }
    }
    Ok(())
}

#[test]
fn unknown_time_wrong_clock_empty_selection_and_uncertain_boundary_refuse_without_success() -> Test {
    let (unknown, identity, count) = setup("avc")?;
    let base = args(&unknown, &identity, count);
    let output = unknown.0.join("unknown.mjpeg");
    let response = raw(&window_request(&base, &output, "0:2000000000", "estimated", "mjpeg"))?;
    incomplete(&response);
    assert!(!output.exists());
    assert!(String::from_utf8_lossy(&response.stderr).contains("retained timing assumptions"));

    let (directory, identity, count) = timed_setup("avc")?;
    let base = args(&directory, &identity, count);
    for (name, interval, clock, reason) in [
        ("clock", "0:1000000000", "utc_disciplined", "clock basis mismatch"),
        ("empty", "0:50000000", "estimated", "selected no frames"),
        ("left-boundary", "100000000:250000000", "estimated", "crosses window boundary"),
    ] {
        let path = directory.0.join(format!("{name}.mjpeg"));
        let response = raw(&window_request(&base, &path, interval, clock, "mjpeg"))?;
        incomplete(&response);
        assert!(!path.exists());
        let stdout = String::from_utf8_lossy(&response.stdout);
        assert!(!stdout.contains("output_window_complete=true"));
        assert!(!stdout.contains("mjpeg_sha256="));
        assert!(String::from_utf8_lossy(&response.stderr).contains(reason));
    }
    Ok(())
}

#[test]
fn a_later_boundary_refusal_cannot_certify_an_already_written_prefix() -> Test {
    let (directory, identity, count) = timed_setup("avc")?;
    let base = args(&directory, &identity, count);
    let path = directory.0.join("incomplete.mjpeg");
    let response = raw(&window_request(&base, &path, "0:200000000", "estimated", "mjpeg"))?;
    incomplete(&response);
    assert!(path.is_file());
    assert!(!fs::read(path)?.is_empty());
    let stdout = String::from_utf8_lossy(&response.stdout);
    assert!(stdout.contains("mjpeg_export_complete=false"));
    assert!(!stdout.contains("output_window_complete=true"));
    assert!(!stdout.contains("mjpeg_sha256="));
    assert!(String::from_utf8_lossy(&response.stderr).contains("crosses window boundary"));
    Ok(())
}
