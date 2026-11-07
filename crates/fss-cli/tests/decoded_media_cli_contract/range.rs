#![forbid(unsafe_code)]
//! Complete retained JPEG range processes: custody, current masks, budgets and file completion.

use super::*;
use fss_codec_jpeg_encode::{EncodeBudget, EncodeConfig, EncodeLimits, PixelFormat, encode_jpeg};
use fss_codec_mjpeg::{
    ComponentInterpretation, DecodeBudget, DecodeLimits, DecodedLuma, decode_luma,
};
use fss_container::matroska_gray::{GrayMatroskaConfig, PlaybackRate};
use std::io;

fn frames(dimensions: &[[u32; 2]]) -> TestResult<Vec<Vec<u8>>> {
    dimensions
        .iter()
        .enumerate()
        .map(|(index, [width, height])| {
            let pixels = vec![40 + index as u8 * 60; (*width * *height) as usize];
            Ok(encode_jpeg(
                *width,
                *height,
                &pixels,
                ContentDigest::sha256(&pixels).bytes(),
                EncodeConfig {
                    quality: 85,
                    format: PixelFormat::Grayscale,
                },
                &EncodeLimits::default(),
                &mut EncodeBudget::new(100_000_000),
            )?
            .bytes()
            .to_vec())
        })
        .collect()
}

fn import_frames(name: &str, frames: &[Vec<u8>]) -> TestResult<(OwnedDirectory, PathBuf, String)> {
    let directory = OwnedDirectory::new(name)?;
    let root = directory.0.join("deployment");
    let input = directory.0.join("source.mjpeg");
    fs::write(&input, frames.concat())?;
    let output = command(&root, "import")
        .arg("--input")
        .arg(&input)
        .args([
            "--media-format",
            "mjpeg",
            "--sensor",
            "sensor:media-cli",
            "--stream",
            "stream:media-cli",
            "--receive-time-ns",
            "1000000000",
            "--capture-start-ns",
            "100000000",
            "--capture-uncertainty-ns",
            "1000",
            "--assumed-fps",
            "10",
        ])
        .output()?;
    success(&output);
    let identity = field(&output, "import_identity")?;
    fs::remove_file(input)?;
    Ok((directory, root, identity))
}

fn range_command(root: &Path, action: &str, identity: &str, first: usize, count: usize) -> Command {
    let mut result = command(root, action);
    result.args([
        "--import-id",
        identity,
        "--segment",
        &first.to_string(),
        "--segment-count",
        &count.to_string(),
        "--interpretation",
        "gray",
    ]);
    result
}

fn export(
    root: &Path,
    action: &str,
    identity: &str,
    format: &str,
    path: &Path,
    maximum: usize,
) -> Command {
    let mut result = range_command(root, action, identity, 0, 3);
    result.arg("--output").arg(path).args([
        "--output-format",
        format,
        "--max-output-bytes",
        &maximum.to_string(),
    ]);
    if format == "gray-mkv" {
        result.args(["--output-rate", "30000/1001"]);
    }
    result
}

fn values(output: &Output, name: &str) -> TestResult<Vec<String>> {
    let prefix = format!("{name}=");
    Ok(String::from_utf8(output.stdout.clone())?
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix).map(str::to_owned))
        .collect())
}

fn journals(root: &Path) -> TestResult<(Vec<u8>, Vec<u8>)> {
    Ok((
        fs::read(root.join("authority.fssb"))?,
        fs::read(root.join("roots.fssr"))?,
    ))
}

fn decoded(frames: &[Vec<u8>]) -> TestResult<Vec<DecodedLuma>> {
    let mut budget = DecodeBudget::new(100_000_000);
    frames
        .iter()
        .map(|bytes| {
            Ok(decode_luma(
                bytes,
                ContentDigest::sha256(bytes).bytes(),
                ComponentInterpretation::Grayscale,
                DecodeLimits::default(),
                &mut budget,
            )?)
        })
        .collect()
}

fn expected(format: &str, images: &[DecodedLuma]) -> TestResult<Vec<u8>> {
    let mut result = Vec::new();
    let mut budget = EncodeBudget::new(100_000_000);
    for (ordinal, image) in images.iter().enumerate() {
        let [width, height] = image.dimensions();
        match format {
            "pgm" => {
                result.extend_from_slice(format!("P5\n{width} {height}\n255\n").as_bytes());
                result.extend_from_slice(image.pixels());
            }
            "mjpeg" => result.extend_from_slice(
                encode_jpeg(
                    width,
                    height,
                    image.pixels(),
                    image.receipt().luma_sha256,
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
                    GrayMatroskaConfig::new([width, height], PlaybackRate::new(30_000, 1001)?)?;
                if ordinal == 0 {
                    result.extend_from_slice(config.initialization()?.bytes());
                }
                result.extend_from_slice(config.frame(ordinal as u64)?.prefix());
                result.extend_from_slice(image.pixels());
            }
            _ => return Err(io::Error::other("unknown test output format").into()),
        }
    }
    Ok(result)
}

fn incomplete(output: &Output) -> TestResult {
    assert!(!output.status.success());
    assert_eq!(field(output, "decode_complete")?, "false");
    let text = String::from_utf8(output.stdout.clone())?;
    for completed in [
        "pgm_sha256=",
        "mjpeg_sha256=",
        "gray_mkv_sha256=",
        "mjpeg_frame_receipts_sha256=",
        "gray_mkv_frame_receipts_sha256=",
        "mjpeg_export_complete=true",
        "gray_mkv_export_complete=true",
        "output_window_complete=true",
        "output_window_selection_digest=",
        "decode_complete=true",
    ] {
        assert!(!text.contains(completed), "{completed}");
    }
    Ok(())
}

#[test]
fn retained_jpeg_ranges_round_trip_every_output_format_and_reopen_without_authority_changes()
-> TestResult {
    let frames = frames(&[[8, 8]; 3])?;
    let images = decoded(&frames)?;
    let (directory, root, identity) = import_frames("range-formats", &frames)?;
    let mut roots = None;
    let mut receipts = None;
    for format in ["pgm", "mjpeg", "gray-mkv"] {
        let bytes = expected(format, &images)?;
        let mut lineage = None;
        for action in ["decode", "read-decoded", "verify-decoded"] {
            let before = journals(&root)?;
            let path = directory.0.join(format!("{format}-{action}"));
            let output = export(&root, action, &identity, format, &path, bytes.len()).output()?;
            success(&output);
            assert_eq!(fs::read(&path)?, bytes);
            assert_eq!(field(&output, "jpeg_frames_processed")?, "3");
            assert_eq!(field(&output, "jpeg_frames_selected")?, "3");
            assert_eq!(values(&output, "frame_output_index")?, ["0", "1", "2"]);
            assert_eq!(values(&output, "frame_segment")?, ["0", "1", "2"]);
            let current_roots = values(&output, "frame_decode_root")?;
            let current_receipts = values(&output, "frame_receipt_digest")?;
            if let Some(previous) = &roots {
                assert_eq!(previous, &current_roots);
            }
            if let Some(previous) = &receipts {
                assert_eq!(previous, &current_receipts);
            }
            roots = Some(current_roots);
            receipts = Some(current_receipts);
            let prefix = if format == "gray-mkv" {
                "gray_mkv"
            } else {
                format
            };
            assert_eq!(
                field(&output, &format!("{prefix}_sha256"))?,
                ContentDigest::sha256(&bytes).to_text()
            );
            assert_eq!(field(&output, &format!("{prefix}_frames"))?, "3");
            if format != "pgm" {
                let current = field(&output, &format!("{prefix}_frame_receipts_sha256"))?;
                if let Some(previous) = &lineage {
                    assert_eq!(previous, &current);
                }
                lineage = Some(current);
                assert_eq!(
                    field(&output, &format!("{prefix}_export_complete"))?,
                    "true"
                );
            }
            if action != "decode" {
                assert_eq!(journals(&root)?, before);
            }
            if action == "read-decoded" {
                assert_eq!(field(&output, "this_request_decode_work_units")?, "0");
            }
            assert_eq!(
                field(&output, "replay_verified")?,
                (action == "verify-decoded").to_string()
            );
        }
    }
    Ok(())
}

#[test]
fn decode_replay_and_encode_allowances_are_cumulative_and_never_complete_a_prefix() -> TestResult {
    let frames = frames(&[[8, 8]; 3])?;
    let images = decoded(&frames)?;
    let (directory, root, identity) = import_frames("range-budget", &frames)?;
    let complete = range_command(&root, "decode", &identity, 0, 3).output()?;
    success(&complete);
    let work = field(&complete, "this_request_decode_work_units")?.parse::<u64>()?;
    let per_frame = values(&complete, "frame_recorded_decode_work_units")?
        .into_iter()
        .map(|v| v.parse::<u64>())
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(per_frame.iter().sum::<u64>(), work);
    let before = journals(&root)?;
    for (index, limit) in [per_frame[0], work - 1, work].into_iter().enumerate() {
        let path = directory.0.join(format!("replay-{index}.mkv"));
        let result = export(
            &root,
            "verify-decoded",
            &identity,
            "gray-mkv",
            &path,
            1024 * 1024,
        )
        .args(["--work-units", &limit.to_string()])
        .output()?;
        if limit == work {
            success(&result);
        } else {
            incomplete(&result)?;
            if limit == per_frame[0] {
                assert_eq!(fs::read(path)?, expected("gray-mkv", &images[..1])?);
            }
        }
        assert!(field(&result, "this_request_decode_work_units")?.parse::<u64>()? <= limit);
        assert_eq!(journals(&root)?, before);
    }
    let encoded = export(
        &root,
        "read-decoded",
        &identity,
        "mjpeg",
        &directory.0.join("full.mjpeg"),
        1024 * 1024,
    )
    .output()?;
    success(&encoded);
    let encode_work = field(&encoded, "encode_work_units")?.parse::<u64>()?;
    let short = export(
        &root,
        "read-decoded",
        &identity,
        "mjpeg",
        &directory.0.join("short.mjpeg"),
        1024 * 1024,
    )
    .args(["--encode-work-units", &(encode_work - 1).to_string()])
    .output()?;
    incomplete(&short)?;
    assert_eq!(journals(&root)?, before);

    let (directory, root, identity) = import_frames("range-first-budget", &frames)?;
    let path = directory.0.join("prefix.pgm");
    let result = export(&root, "decode", &identity, "pgm", &path, 1024 * 1024)
        .args(["--work-units", &per_frame[0].to_string()])
        .output()?;
    incomplete(&result)?;
    assert_eq!(fs::read(path)?, expected("pgm", &images[..1])?);
    success(&range_command(&root, "read-decoded", &identity, 0, 1).output()?);
    assert!(
        !range_command(&root, "read-decoded", &identity, 1, 1)
            .output()?
            .status
            .success()
    );
    Ok(())
}

#[test]
fn source_windows_select_across_all_jpegs_and_refuse_empty_or_late_uncertain_boundaries()
-> TestResult {
    let frames = frames(&[[8, 8]; 3])?;
    let images = decoded(&frames)?;
    let (directory, root, identity) = import_frames("range-window", &frames)?;
    let mut selection = None;
    for action in ["decode", "read-decoded", "verify-decoded"] {
        let path = directory.0.join(format!("selected-{action}.mkv"));
        let result = export(&root, action, &identity, "gray-mkv", &path, 1024 * 1024)
            .args([
                "--output-window-ns",
                "150000000:250000000",
                "--output-clock-basis",
                "estimated",
            ])
            .output()?;
        success(&result);
        assert_eq!(fs::read(path)?, expected("gray-mkv", &images[1..2])?);
        assert_eq!(values(&result, "frame_output_index")?, ["1"]);
        assert_eq!(values(&result, "source_segment")?, ["1"]);
        assert_eq!(field(&result, "output_window_observed_frames")?, "3");
        assert_eq!(field(&result, "output_window_selected_frames")?, "1");
        assert_eq!(field(&result, "output_window_skipped_frames")?, "2");
        assert_eq!(field(&result, "gray_mkv_duration_ns")?, "33366666");
        let current = field(&result, "output_window_selection_digest")?;
        if let Some(previous) = &selection {
            assert_eq!(previous, &current);
        }
        selection = Some(current);
    }
    let before = journals(&root)?;
    for (name, interval, prefix) in [
        ("empty", "400000000:450000000", false),
        ("straddle", "0:200000000", true),
    ] {
        let path = directory.0.join(format!("{name}.mkv"));
        let result = export(
            &root,
            "read-decoded",
            &identity,
            "gray-mkv",
            &path,
            1024 * 1024,
        )
        .args([
            "--output-window-ns",
            interval,
            "--output-clock-basis",
            "estimated",
        ])
        .output()?;
        incomplete(&result)?;
        if prefix {
            assert_eq!(fs::read(path)?, expected("gray-mkv", &images[..1])?);
        } else {
            assert!(!path.exists());
        }
        assert_eq!(journals(&root)?, before);
    }
    Ok(())
}

#[test]
fn late_unsupported_source_or_unavailable_retained_decode_never_finishes_a_range() -> TestResult {
    let mut frames = frames(&[[8, 8]; 3])?;
    let images = decoded(&frames[..1])?;
    let marker = frames[1]
        .windows(2)
        .position(|pair| pair == [0xff, 0xc0])
        .ok_or_else(|| io::Error::other("fixture baseline marker missing"))?;
    frames[1][marker + 1] = 0xc1; // Splitter retains SOF1; the native decoder refuses it.
    let (directory, root, identity) = import_frames("range-unsupported", &frames)?;
    for action in ["decode", "read-decoded", "verify-decoded"] {
        let before = journals(&root)?;
        let path = directory.0.join(format!("{action}.mkv"));
        let result = export(&root, action, &identity, "gray-mkv", &path, 1024 * 1024).output()?;
        incomplete(&result)?;
        assert_eq!(fs::read(path)?, expected("gray-mkv", &images)?);
        if action != "decode" {
            assert_eq!(journals(&root)?, before);
        }
    }
    success(&range_command(&root, "read-decoded", &identity, 0, 1).output()?);
    assert!(
        !range_command(&root, "read-decoded", &identity, 1, 1)
            .output()?
            .status
            .success()
    );
    Ok(())
}

#[test]
fn byte_quota_and_dimension_drift_never_certify_a_shorter_gray_video() -> TestResult {
    let frames = frames(&[[8, 8], [9, 7], [8, 8]])?;
    let images = decoded(&frames)?;
    let (directory, root, identity) = import_frames("range-shape", &frames)?;
    success(&range_command(&root, "decode", &identity, 0, 3).output()?);
    let before = journals(&root)?;
    let first = expected("gray-mkv", &images[..1])?;
    for (name, maximum) in [
        ("zero", first.len() - 1),
        ("first", first.len()),
        ("shape", 1024 * 1024),
    ] {
        let path = directory.0.join(format!("{name}.mkv"));
        let result =
            export(&root, "read-decoded", &identity, "gray-mkv", &path, maximum).output()?;
        incomplete(&result)?;
        if maximum < first.len() {
            assert!(!path.exists());
        } else {
            assert_eq!(fs::read(path)?, first);
        }
        assert_eq!(journals(&root)?, before);
    }
    for format in ["pgm", "mjpeg"] {
        let bytes = expected(format, &images)?;
        let path = directory.0.join(format!("variable.{format}"));
        let result =
            export(&root, "read-decoded", &identity, format, &path, bytes.len()).output()?;
        success(&result);
        assert_eq!(fs::read(path)?, bytes);
    }
    Ok(())
}

#[test]
fn range_admission_and_ambiguous_receipt_requests_cannot_publish_or_overwrite() -> TestResult {
    let frames = frames(&[[8, 8]; 3])?;
    let (directory, root, identity) = import_frames("range-preflight", &frames)?;
    let before = journals(&root)?;
    for (first, count) in [(0, 4), (2, 2), (3, 2)] {
        let path = directory.0.join(format!("outside-{first}-{count}.pgm"));
        let result = range_command(&root, "decode", &identity, first, count)
            .arg("--output")
            .arg(&path)
            .output()?;
        incomplete(&result)?;
        assert!(!path.exists());
        assert_eq!(journals(&root)?, before);
    }
    for action in ["decode", "read-decoded", "verify-decoded"] {
        let path = directory.0.join(format!("ambiguous-{action}.receipt"));
        let result = range_command(&root, action, &identity, 0, 3)
            .arg("--receipt-out")
            .arg(&path)
            .output()?;
        assert!(!result.status.success());
        assert!(!path.exists());
        assert_eq!(journals(&root)?, before);
    }
    let path = directory.0.join("operator.pgm");
    fs::write(&path, b"operator-owned")?;
    incomplete(&export(&root, "decode", &identity, "pgm", &path, 1024 * 1024).output()?)?;
    assert_eq!(fs::read(path)?, b"operator-owned");
    assert_eq!(journals(&root)?, before);
    let path = root.join("forbidden.pgm");
    incomplete(&export(&root, "decode", &identity, "pgm", &path, 1024 * 1024).output()?)?;
    assert!(!path.exists());
    assert_eq!(journals(&root)?, before);
    Ok(())
}

fn declare_full_mask(root: &Path) -> TestResult<ContentDigest> {
    use fss_core::{BudgetVector, ContextAuthority, OperationId, RootAuthoritySpec, SensorId};
    use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:jpeg-range-mask".into(),
        operation_id: OperationId::parse("operation:jpeg-range-mask")?,
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
        anchor_universe: ContentDigest::sha256(b"site:media-cli"),
        generation: 1,
    })?;
    let cx = fss_reference::ReplayCx::from_context_authority(&authority, root)?;
    let mut deployment = fss_reference::ReferenceDeployment::open(root, "site:media-cli", &cx)?;
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:media-cli")?,
        [8, 8],
        &[[0, 0, 8, 8]],
    )?;
    let approval = preview_mask(&deployment, &policy)?.approval;
    let digest = declare_mask(&mut deployment, &policy, approval, &cx)?.policy_digest;
    drop(deployment);
    cx.drain_and_finalize();
    Ok(digest)
}

#[test]
fn current_masks_apply_to_every_frame_and_a_late_stale_decode_refuses_the_clip() -> TestResult {
    let frames = frames(&[[8, 8]; 3])?;
    let (directory, root, identity) = import_frames("range-mask", &frames)?;
    success(&range_command(&root, "decode", &identity, 0, 3).output()?);
    let policy = declare_full_mask(&root)?;
    success(&range_command(&root, "decode", &identity, 0, 1).output()?);
    let before = journals(&root)?;
    for action in ["read-decoded", "verify-decoded"] {
        let result = export(
            &root,
            action,
            &identity,
            "gray-mkv",
            &directory.0.join(format!("stale-{action}.mkv")),
            1024 * 1024,
        )
        .output()?;
        incomplete(&result)?;
        assert_eq!(values(&result, "frame_segment")?, ["0"]);
        assert_eq!(journals(&root)?, before);
    }
    let config = GrayMatroskaConfig::new([8, 8], PlaybackRate::new(30_000, 1001)?)?;
    let mut expected = config.initialization()?.bytes().to_vec();
    for ordinal in 0..3 {
        expected.extend_from_slice(config.frame(ordinal)?.prefix());
        expected.extend_from_slice(&[16; 64]);
    }
    for action in ["decode", "read-decoded", "verify-decoded"] {
        let path = directory.0.join(format!("masked-{action}.mkv"));
        let result =
            export(&root, action, &identity, "gray-mkv", &path, expected.len()).output()?;
        success(&result);
        assert_eq!(fs::read(path)?, expected);
        assert_eq!(
            values(&result, "privacy_mask_policy")?,
            vec![policy.to_text(); 3]
        );
    }
    Ok(())
}
