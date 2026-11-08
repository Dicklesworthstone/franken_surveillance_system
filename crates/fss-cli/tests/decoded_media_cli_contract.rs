#![forbid(unsafe_code)]
//! Cross-process recorded-source -> canonical decode -> retained output -> pixel-change workflow.

use fss_core::ContentDigest;
use fss_reference::ingest::recorded_decode::RecordedDecodeReceipt;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "decoded_media_cli_contract/range.rs"]
mod range;
#[path = "decoded_media_cli_contract/movie_export.rs"]
mod movie_export;
#[path = "decoded_media_cli_contract/rtsp_movie_export.rs"]
mod rtsp_movie_export;

const JPEG: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
type TestResult<T = ()> = Result<T, Box<dyn Error>>;
struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-media-cli-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
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

fn command(root: &Path, action: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-file"));
    command
        .arg(action)
        .arg("--root")
        .arg(root)
        .args(["--site", "site:media-cli"]);
    command
}
fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
fn field(output: &Output, name: &str) -> TestResult<String> {
    let prefix = format!("{name}=");
    String::from_utf8(output.stdout.clone())?
        .lines()
        .find_map(|line| line.strip_prefix(&prefix).map(str::to_owned))
        .ok_or_else(|| std::io::Error::other(format!("missing field {name}")).into())
}
fn imported(name: &str) -> TestResult<(OwnedDirectory, PathBuf, String)> {
    imported_with_timing(name, false)
}
fn imported_with_timing(name: &str, timed: bool) -> TestResult<(OwnedDirectory, PathBuf, String)> {
    let directory = OwnedDirectory::new(name)?;
    let root = directory.0.join("deployment");
    let input = directory.0.join("recording.mjpeg");
    fs::write(&input, [JPEG, JPEG].concat())?;
    let mut import = command(&root, "import");
    import.arg("--input")
        .arg(&input)
        .args([
            "--sensor",
            "sensor:media-cli",
            "--stream",
            "stream:media-cli",
            "--receive-time-ns",
            "1000000000",
        ]);
    if timed {
        import.args([
            "--capture-start-ns", "100000000", "--capture-uncertainty-ns", "1000",
            "--assumed-fps", "10",
        ]);
    }
    let output = import.output()?;
    success(&output);
    let id = field(&output, "import_identity")?;
    fs::remove_file(input)?;
    Ok((directory, root, id))
}
fn frame_command(root: &Path, action: &str, id: &str) -> Command {
    let mut command = command(root, action);
    command.args([
        "--import-id",
        id,
        "--segment",
        "1",
        "--interpretation",
        "gray",
    ]);
    command
}

#[test]
fn retained_jpeg_decode_read_and_replay_apply_the_same_source_time_window() -> TestResult {
    let (directory, root, id) = imported_with_timing("window-replay", true)?;
    let mut first_bytes = None;
    let mut first_selection = None;
    for action in ["decode", "read-decoded", "verify-decoded"] {
        let path = directory.0.join(format!("{action}.pgm"));
        let output = frame_command(&root, action, &id)
            .arg("--output").arg(&path)
            .args(["--output-window-ns", "150000000:250000000", "--output-clock-basis", "estimated"])
            .output()?;
        success(&output);
        assert_eq!(field(&output, "output_window_complete")?, "true");
        assert_eq!(field(&output, "output_window_selected_frames")?, "1");
        assert_eq!(field(&output, "output_window_selected_earliest_ns")?, "199999000");
        assert_eq!(field(&output, "output_window_selected_latest_ns")?, "200001000");
        let bytes = fs::read(path)?;
        let selection = field(&output, "output_window_selection_digest")?;
        if let Some(first) = &first_bytes {
            assert_eq!(&bytes, first);
            assert_eq!(Some(&selection), first_selection.as_ref());
        } else {
            first_bytes = Some(bytes);
            first_selection = Some(selection);
        }
    }
    for (name, interval, basis) in [
        ("outside", "0:50000000", "estimated"),
        ("boundary", "200000000:250000000", "estimated"),
        ("wrong-clock", "150000000:250000000", "utc_disciplined"),
    ] {
        let path = directory.0.join(format!("{name}.jpg"));
        let receipt = directory.0.join(format!("{name}.receipt"));
        let output = frame_command(&root, "read-decoded", &id)
            .arg("--output").arg(&path)
            .arg("--receipt-out").arg(&receipt)
            .args(["--output-format", "mjpeg", "--output-window-ns", interval, "--output-clock-basis", basis])
            .output()?;
        assert!(!output.status.success());
        assert!(!path.exists());
        assert!(!receipt.exists());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("output_window_complete=true"));
    }
    Ok(())
}
fn motion_command(root: &Path, id: &str, report: &Path, comparisons: &str) -> Command {
    let mut command = command(root, "motion");
    command
        .args([
            "--import-id",
            id,
            "--start-segment",
            "0",
            "--frame-count",
            "2",
            "--interpretation",
            "gray",
            "--pixel-delta",
            "1",
            "--minimum-changed-pixels",
            "1",
            "--max-comparisons",
            comparisons,
        ])
        .arg("--report-out")
        .arg(report);
    command
}

#[test]
fn decode_reopen_export_and_verify_run_in_separate_processes() -> TestResult {
    let (directory, root, id) = imported("restart")?;
    let output_path = directory.0.join("first.pgm");
    let receipt_path = directory.0.join("decode.receipt");
    let decoded = frame_command(&root, "decode", &id)
        .arg("--output")
        .arg(&output_path)
        .arg("--receipt-out")
        .arg(&receipt_path)
        .output()?;
    success(&decoded);
    assert_eq!(field(&decoded, "decode_complete")?, "true");
    assert_eq!(field(&decoded, "clock_basis")?, "estimated");
    assert_eq!(field(&decoded, "capture_earliest_ns")?, "0");
    assert_eq!(field(&decoded, "capture_latest_ns")?, "1000000000");
    assert_eq!(field(&decoded, "absence_certifiable")?, "false");
    let receipt = RecordedDecodeReceipt::decode(
        &fs::read(&receipt_path)?,
        ContentDigest::parse(field(&decoded, "decode_receipt_digest")?)?,
    )?;
    assert_eq!(
        receipt.identity().to_text(),
        field(&decoded, "decode_identity")?
    );
    assert!(fs::read(&output_path)?.starts_with(b"P5\n"));
    let restored_path = directory.0.join("restored.pgm");
    let restored = frame_command(&root, "read-decoded", &id)
        .arg("--output")
        .arg(&restored_path)
        .output()?;
    success(&restored);
    assert_eq!(field(&restored, "this_request_decode_work_units")?, "0");
    assert_eq!(
        field(&restored, "decode_root")?,
        field(&decoded, "decode_root")?
    );
    assert_eq!(fs::read(&restored_path)?, fs::read(&output_path)?);
    let replay = frame_command(&root, "verify-decoded", &id).output()?;
    success(&replay);
    assert_eq!(field(&replay, "replay_verified")?, "true");
    let retry = frame_command(&root, "decode", &id).output()?;
    success(&retry);
    assert_eq!(
        field(&retry, "decode_authority_sequence")?,
        field(&decoded, "decode_authority_sequence")?
    );
    assert_eq!(
        field(&retry, "decode_receipt_digest")?,
        field(&decoded, "decode_receipt_digest")?
    );
    Ok(())
}

#[test]
fn retained_jpeg_decode_reopen_and_replay_export_identical_bounded_mjpeg() -> TestResult {
    use fss_codec_jpeg_encode::{EncodeBudget, EncodeConfig, EncodeLimits, PixelFormat, encode_jpeg};
    let (directory, root, id) = imported("mjpeg")?;
    let pgm_path = directory.0.join("screened.pgm");
    let decoded = frame_command(&root, "decode", &id).arg("--output").arg(&pgm_path).output()?;
    success(&decoded);
    let width = field(&decoded, "width")?.parse::<u32>()?;
    let height = field(&decoded, "height")?.parse::<u32>()?;
    let pgm = fs::read(pgm_path)?;
    let header = format!("P5\n{width} {height}\n255\n");
    assert!(pgm.starts_with(header.as_bytes()));
    let luma = &pgm[header.len()..];
    let mut budget = EncodeBudget::new(100_000_000);
    let expected = encode_jpeg(width, height, luma,
        ContentDigest::parse(field(&decoded, "luma_sha256")?)?.bytes(),
        EncodeConfig { quality: 85, format: PixelFormat::Grayscale },
        &EncodeLimits::default(), &mut budget)?;
    let mut lineage = None;
    for command in ["decode", "read-decoded", "verify-decoded"] {
        let path = directory.0.join(format!("{command}.mjpeg"));
        let output = frame_command(&root, command, &id).arg("--output").arg(&path)
            .args(["--output-format", "mjpeg", "--jpeg-quality", "85", "--encode-work-units", &budget.used().to_string(),
                "--max-output-bytes", &expected.bytes().len().to_string()]).output()?;
        success(&output);
        assert_eq!(fs::read(&path)?, expected.bytes());
        assert_eq!(field(&output, "mjpeg_sha256")?, ContentDigest::sha256(expected.bytes()).to_text());
        assert_eq!(field(&output, "mjpeg_frames")?, "1");
        assert_eq!(field(&output, "remaining_encode_work_units")?, "0");
        assert_eq!(field(&output, "mjpeg_export_complete")?, "true");
        assert_eq!(field(&output, "decode_root")?, field(&decoded, "decode_root")?);
        assert_eq!(field(&output, "decode_receipt_digest")?, field(&decoded, "decode_receipt_digest")?);
        assert_eq!(field(&output, "privacy_mask_binding")?, field(&decoded, "privacy_mask_binding")?);
        let this_lineage = field(&output, "mjpeg_frame_receipts_sha256")?;
        if let Some(previous) = &lineage { assert_eq!(previous, &this_lineage); }
        lineage = Some(this_lineage);
    }
    let path = directory.0.join("zero.mjpeg");
    let refused = frame_command(&root, "read-decoded", &id).arg("--output").arg(&path)
        .args(["--output-format", "mjpeg", "--encode-work-units", "0"]).output()?;
    assert!(!refused.status.success());
    assert_eq!(field(&refused, "mjpeg_export_complete")?, "false");
    assert!(!String::from_utf8_lossy(&refused.stdout).contains("mjpeg_sha256="));
    assert!(!path.exists());
    success(&frame_command(&root, "read-decoded", &id).output()?);
    Ok(())
}

#[test]
fn retained_jpeg_lossless_matroska_preserves_pixels_roots_and_selected_lineage() -> TestResult {
    use fss_container::matroska_gray::{GrayMatroskaConfig, PlaybackRate};

    let (directory, root, id) = imported_with_timing("gray-mkv", true)?;
    let window = [
        "--output-window-ns",
        "150000000:250000000",
        "--output-clock-basis",
        "estimated",
    ];
    let pgm_path = directory.0.join("screened.pgm");
    let receipt_path = directory.0.join("screened.receipt");
    let decoded = frame_command(&root, "decode", &id)
        .arg("--output")
        .arg(&pgm_path)
        .arg("--receipt-out")
        .arg(&receipt_path)
        .args(window)
        .output()?;
    success(&decoded);
    let receipt = RecordedDecodeReceipt::decode(
        &fs::read(&receipt_path)?,
        ContentDigest::parse(field(&decoded, "decode_receipt_digest")?)?,
    )?;
    assert_eq!(receipt.identity().to_text(), field(&decoded, "decode_identity")?);
    let width = field(&decoded, "width")?.parse::<u32>()?;
    let height = field(&decoded, "height")?.parse::<u32>()?;
    assert_eq!(receipt.dimensions(), [width, height]);
    let pgm = fs::read(&pgm_path)?;
    let header = format!("P5\n{width} {height}\n255\n");
    assert!(pgm.starts_with(header.as_bytes()));
    let luma = &pgm[header.len()..];
    assert_eq!(ContentDigest::sha256(luma).to_text(), field(&decoded, "luma_sha256")?);

    // Playback starts at zero at the explicitly requested cadence. The source
    // remains segment 1 with its estimated capture interval near 200 ms.
    let config = GrayMatroskaConfig::new([width, height], PlaybackRate::new(30_000, 1_001)?)?;
    let initialization = config.initialization()?;
    let framing = config.frame(0)?;
    assert_eq!(framing.payload_bytes(), luma.len());
    assert_eq!(framing.timestamp_ns(), 0);
    assert_eq!(framing.duration_ns(), 33_366_666);
    let expected = [initialization.bytes(), framing.prefix(), luma].concat();
    let expected_digest = ContentDigest::sha256(&expected).to_text();
    let exact_limit = expected.len().to_string();
    let mut lineage = None;
    for action in ["decode", "read-decoded", "verify-decoded"] {
        let path = directory.0.join(format!("{action}.mkv"));
        let output = frame_command(&root, action, &id)
            .arg("--output")
            .arg(&path)
            .args([
                "--output-format",
                "gray-mkv",
                "--output-rate",
                "30000/1001",
                "--max-output-bytes",
                &exact_limit,
            ])
            .args(window)
            .output()?;
        success(&output);
        assert_eq!(fs::read(&path)?, expected);
        assert_eq!(field(&output, "gray_mkv_sha256")?, expected_digest);
        assert_eq!(field(&output, "gray_mkv_bytes")?, exact_limit);
        assert_eq!(field(&output, "gray_mkv_frames")?, "1");
        assert_eq!(field(&output, "gray_mkv_width")?, width.to_string());
        assert_eq!(field(&output, "gray_mkv_height")?, height.to_string());
        assert_eq!(field(&output, "gray_mkv_rate_numerator")?, "30000");
        assert_eq!(field(&output, "gray_mkv_rate_denominator")?, "1001");
        assert_eq!(field(&output, "gray_mkv_duration_ns")?, "33366666");
        assert_eq!(field(&output, "gray_mkv_pixel_format")?, "grayscale_luma");
        assert_eq!(field(&output, "gray_mkv_lossy")?, "false");
        assert_eq!(field(&output, "gray_mkv_exact_luma_preserved")?, "true");
        assert_eq!(field(&output, "gray_mkv_timing")?, "operator_requested_uniform_rate");
        assert_eq!(field(&output, "gray_mkv_source_capture_timing_preserved")?, "false");
        assert_eq!(field(&output, "gray_mkv_export_complete")?, "true");
        assert_eq!(field(&output, "decode_complete")?, "true");
        for name in [
            "decode_identity",
            "decode_root",
            "decode_receipt_digest",
            "decode_authority_sequence",
            "source_import_identity",
            "source_segment",
            "source_capsule_digest",
            "source_encoded_digest",
            "luma_sha256",
            "privacy_mask_binding",
            "privacy_mask_binding_digest",
            "privacy_mask_policy",
            "applied_redaction_transform",
            "output_window_selection_digest",
        ] {
            assert_eq!(field(&output, name)?, field(&decoded, name)?, "{action}: {name}");
        }
        assert_eq!(field(&output, "clock_basis")?, "estimated");
        assert_eq!(field(&output, "capture_earliest_ns")?, "199999000");
        assert_eq!(field(&output, "capture_latest_ns")?, "200001000");
        assert_eq!(field(&output, "output_window_complete")?, "true");
        assert_eq!(field(&output, "output_window_selected_frames")?, "1");
        assert_eq!(field(&output, "output_window_selected_earliest_ns")?, "199999000");
        assert_eq!(field(&output, "output_window_selected_latest_ns")?, "200001000");
        let this_lineage = field(&output, "gray_mkv_frame_receipts_sha256")?;
        if let Some(previous) = &lineage {
            assert_eq!(previous, &this_lineage);
        }
        lineage = Some(this_lineage);
        if action == "read-decoded" {
            assert_eq!(field(&output, "this_request_decode_work_units")?, "0");
        }
        assert_eq!(field(&output, "replay_verified")?, (action == "verify-decoded").to_string());
    }

    // The cap includes the initialization, Cluster/BlockGroup framing and luma.
    // One byte short must fail before either output or receipt is created.
    let short_path = directory.0.join("one-byte-short.mkv");
    let short_receipt = directory.0.join("one-byte-short.receipt");
    let short_limit = (expected.len() - 1).to_string();
    let refused = frame_command(&root, "read-decoded", &id)
        .arg("--output")
        .arg(&short_path)
        .arg("--receipt-out")
        .arg(&short_receipt)
        .args([
            "--output-format",
            "gray-mkv",
            "--output-rate",
            "30000/1001",
            "--max-output-bytes",
            &short_limit,
        ])
        .args(window)
        .output()?;
    assert!(!refused.status.success());
    assert_eq!(field(&refused, "gray_mkv_export_complete")?, "false");
    assert!(!short_path.exists());
    assert!(!short_receipt.exists());
    let stdout = String::from_utf8(refused.stdout)?;
    for complete in [
        "gray_mkv_sha256=",
        "gray_mkv_frame_receipts_sha256=",
        "gray_mkv_export_complete=true",
        "output_window_complete=true",
        "decode_complete=true",
    ] {
        assert!(!stdout.contains(complete), "{complete}");
    }
    let retained = frame_command(&root, "read-decoded", &id).output()?;
    success(&retained);
    assert_eq!(field(&retained, "decode_root")?, field(&decoded, "decode_root")?);
    assert_eq!(field(&retained, "privacy_mask_binding_digest")?, field(&decoded, "privacy_mask_binding_digest")?);
    Ok(())
}

#[test]
fn motion_scan_retains_each_frame_and_distinguishes_baseline_from_zero_change() -> TestResult {
    let (directory, root, id) = imported("motion")?;
    let report_path = directory.0.join("motion.json");
    let result = motion_command(&root, &id, &report_path, "100000000").output()?;
    success(&result);
    assert_eq!(field(&result, "motion_complete")?, "true");
    assert_eq!(field(&result, "motion_observations")?, "2");
    let report = fs::read_to_string(&report_path)?;
    assert!(report.contains("\"complete\":true"));
    assert!(report.contains("\"no_predecessor\""));
    assert!(report.contains("\"comparison\":null"));
    assert!(report.contains("\"changed_pixels\":0"));
    assert!(report.contains("\"candidate\":false"));
    assert!(report.contains("\"absence_certifiable\":false"));
    assert_eq!(
        ContentDigest::sha256(report.as_bytes()).to_text(),
        field(&result, "motion_report_sha256")?
    );
    success(&frame_command(&root, "read-decoded", &id).output()?);
    Ok(())
}

#[test]
fn comparison_pressure_produces_explicit_partial_report_and_replayable_frames() -> TestResult {
    let (directory, root, id) = imported("pressure")?;
    let partial_path = directory.0.join("partial.json");
    let partial = motion_command(&root, &id, &partial_path, "0").output()?;
    assert!(!partial.status.success());
    assert_eq!(field(&partial, "motion_complete")?, "false");
    assert_eq!(field(&partial, "motion_next_segment")?, "1");
    let report = fs::read_to_string(&partial_path)?;
    assert!(report.contains("\"complete\":false"));
    assert!(report.contains("\"resume_start_segment\":0"));
    // Decoding the second frame completed before the comparison was refused.
    success(&frame_command(&root, "read-decoded", &id).output()?);
    let completed_path = directory.0.join("completed.json");
    success(&motion_command(&root, &id, &completed_path, "100000000").output()?);
    assert!(fs::read_to_string(completed_path)?.contains("\"complete\":true"));
    Ok(())
}

#[test]
fn decode_refusals_do_not_overwrite_exports_or_invent_completed_pixels() -> TestResult {
    let (directory, root, id) = imported("refusal")?;
    let absent = frame_command(&root, "read-decoded", &id).output()?;
    assert!(!absent.status.success());
    let refused = frame_command(&root, "decode", &id)
        .args(["--work-units", "0"])
        .output()?;
    assert!(!refused.status.success());
    assert!(
        !frame_command(&root, "read-decoded", &id)
            .output()?
            .status
            .success()
    );
    success(&frame_command(&root, "decode", &id).output()?);
    let existing = directory.0.join("existing.pgm");
    fs::write(&existing, b"operator-owned")?;
    assert!(
        !frame_command(&root, "read-decoded", &id)
            .arg("--output")
            .arg(&existing)
            .output()?
            .status
            .success()
    );
    assert_eq!(fs::read(existing)?, b"operator-owned");
    let inside = root.join("not-a-derived-object.pgm");
    assert!(
        !frame_command(&root, "read-decoded", &id)
            .arg("--output")
            .arg(&inside)
            .output()?
            .status
            .success()
    );
    assert!(!inside.exists());
    Ok(())
}
