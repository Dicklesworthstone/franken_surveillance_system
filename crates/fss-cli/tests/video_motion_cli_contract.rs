#![forbid(unsafe_code)]
//! Native recorded-video motion through real CLI processes. All video is a committed codec
//! fixture, and the original input is removed after custody import. No foreign codec runs.

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type Test<T = ()> = Result<T, Box<dyn Error>>;
const AVC: &[u8] =
    include_bytes!("../../fss-codec-h264/tests/fixtures/decode/p_qcif_ref3_p4x4.h264");
const HEVC: &[u8] =
    include_bytes!("../../fss-codec-h265/tests/fixtures/decode/f_qcif_default.h265");
const CRA: &[u8] = include_bytes!("../../fss-codec-h265/tests/fixtures/decode/b_qcif_opengop.h265");

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-video-motion-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Imported {
    directory: Directory,
    root: PathBuf,
    identity: String,
    format: String,
}

fn command(root: &Path, action: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-file"));
    command
        .arg(action)
        .arg("--root")
        .arg(root)
        .args(["--site", "site:video-motion"]);
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

fn lines(output: &Output, name: &str) -> Test<Vec<String>> {
    let prefix = format!("{name}=");
    Ok(std::str::from_utf8(&output.stdout)?
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix).map(str::to_owned))
        .collect())
}

fn output_field(output: &Output, name: &str) -> Test<String> {
    lines(output, name)?
        .into_iter()
        .next()
        .ok_or_else(|| format!("missing output field {name}").into())
}

fn import(label: &str, bytes: &[u8], format: Option<&str>) -> Test<Imported> {
    let directory = Directory::new(label)?;
    let root = directory.0.join("deployment");
    let input = directory.0.join("recording");
    fs::write(&input, bytes)?;
    let mut cmd = command(&root, "import");
    cmd.arg("--input").arg(&input).args([
        "--sensor",
        "sensor:video-motion",
        "--stream",
        "stream:video-motion",
        "--receive-time-ns",
        "1000000000",
    ]);
    if let Some(format) = format {
        cmd.args(["--media-format", format]);
    }
    let output = cmd.output()?;
    success(&output);
    fs::remove_file(input)?;
    Ok(Imported {
        directory,
        root,
        identity: output_field(&output, "import_identity")?,
        format: output_field(&output, "media_format")?,
    })
}

fn motion(imported: &Imported, first: usize, count: usize, report: &Path) -> Command {
    let mut command = command(&imported.root, "motion");
    command
        .args([
            "--import-id",
            &imported.identity,
            "--start-segment",
            &first.to_string(),
            "--frame-count",
            &count.to_string(),
            "--interpretation",
            "ycbcr",
            "--pixel-delta",
            "16",
            "--minimum-changed-pixels",
            "1",
        ])
        .arg("--report-out")
        .arg(report);
    command
}

fn field<'a>(value: &'a Value, name: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|fields| fields.get(name))
        .ok_or_else(|| format!("missing {name}").into())
}
fn number(value: &Value, name: &str) -> Test<i128> {
    field(value, name)?
        .integer()
        .ok_or("expected integer".into())
}
fn text<'a>(value: &'a Value, name: &str) -> Test<&'a str> {
    field(value, name)?.text().ok_or("expected text".into())
}
fn items<'a>(value: &'a Value, name: &str) -> Test<&'a [Value]> {
    field(value, name)?.array().ok_or("expected array".into())
}
fn integers(value: &Value, name: &str) -> Test<Vec<i128>> {
    items(value, name)?
        .iter()
        .map(|value| value.integer().ok_or("expected integer".into()))
        .collect()
}
fn report(path: &Path, output: &Output) -> Test<Value> {
    let bytes = fs::read_to_string(path)?;
    assert_eq!(
        ContentDigest::sha256(bytes.as_bytes()).to_text(),
        output_field(output, "motion_report_sha256")?
    );
    parse(&bytes).map_err(Into::into)
}

fn verify_receipts(value: &Value) -> Test {
    for observation in items(value, "observations")? {
        let encoded = text(observation, "frame_receipt")?;
        assert_eq!(encoded.len() % 2, 0);
        let bytes = (0..encoded.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&encoded[index..index + 2], 16))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            ContentDigest::sha256(&bytes).to_text(),
            text(observation, "frame_receipt_digest")?
        );
        assert_eq!(field(observation, "decode_published")?, &Value::Bool(false));
        assert!(
            observation
                .object()
                .is_some_and(|fields| !fields.contains_key("frame_root")
                    && !fields.contains_key("predecessor_root"))
        );
        assert_eq!(
            text(observation, "source_import_root")?,
            text(value, "source_import_root")?
        );
        assert_eq!(number(observation, "capture_earliest_ns")?, 0);
        assert_eq!(number(observation, "capture_latest_ns")?, 1_000_000_000);
    }
    Ok(())
}

/// Independently calculate sample-pair statistics from the existing decoded PGM export, so
/// routing one repeated/stale frame or comparing coding-order neighbors cannot pass.
fn compare_with_decode(
    imported: &Imported,
    first: usize,
    count: usize,
    width: usize,
    height: usize,
    value: &Value,
) -> Test {
    let path = imported.directory.0.join("oracle.pgm");
    let decoded = command(&imported.root, "decode")
        .args([
            "--import-id",
            &imported.identity,
            "--segment",
            &first.to_string(),
            "--segment-count",
            &count.to_string(),
            "--interpretation",
            "ycbcr",
        ])
        .arg("--output")
        .arg(&path)
        .output()?;
    success(&decoded);
    let observations = items(value, "observations")?;
    let segments = lines(&decoded, "frame_segment")?;
    let receipts = lines(&decoded, "frame_receipt_digest")?;
    assert_eq!(observations.len(), segments.len());
    let header = format!("P5\n{width} {height}\n255\n");
    let bytes = fs::read(path)?;
    let stride = header.len() + width * height;
    assert_eq!(bytes.len(), stride * observations.len());
    let frames = bytes
        .chunks_exact(stride)
        .map(|frame| {
            assert!(frame.starts_with(header.as_bytes()));
            &frame[header.len()..]
        })
        .collect::<Vec<_>>();
    for (index, observation) in observations.iter().enumerate() {
        assert_eq!(
            number(observation, "segment")?,
            segments[index].parse::<i128>()?
        );
        assert_eq!(number(observation, "display_index")?, index as i128);
        assert_eq!(text(observation, "frame_receipt_digest")?, receipts[index]);
        assert_eq!(
            text(observation, "luma_sha256")?,
            ContentDigest::sha256(frames[index]).to_text()
        );
        if index == 0 {
            assert_eq!(field(observation, "comparison")?, &Value::Null);
            continue;
        }
        assert_eq!(
            text(observation, "predecessor_receipt_digest")?,
            receipts[index - 1]
        );
        assert!(items(observation, "reset_reasons")?.is_empty());
        let differences = frames[index - 1]
            .iter()
            .zip(frames[index])
            .map(|(left, right)| left.abs_diff(*right))
            .collect::<Vec<_>>();
        let compared = field(observation, "comparison")?;
        assert_eq!(
            number(compared, "compared_pixels")?,
            (width * height) as i128
        );
        assert_eq!(
            number(compared, "changed_pixels")?,
            differences
                .iter()
                .filter(|difference| **difference >= 16)
                .count() as i128
        );
        assert_eq!(
            number(compared, "absolute_difference_sum")?,
            differences
                .iter()
                .map(|value| i128::from(*value))
                .sum::<i128>()
        );
        assert_eq!(
            number(compared, "maximum_difference")?,
            i128::from(*differences.iter().max().ok_or("empty image")?)
        );
    }
    Ok(())
}

#[test]
fn annexb_avc_and_hevc_motion_matches_display_order_pixels_and_exact_retained_receipts() -> Test {
    for (name, bytes, format, count) in [("avc", AVC, "annexb", 12), ("hevc", HEVC, "hevc", 8)] {
        let imported = import(name, bytes, Some(format))?;
        let path = imported.directory.0.join("motion.json");
        let output = motion(&imported, 0, count, &path).output()?;
        success(&output);
        let value = report(&path, &output)?;
        assert_eq!(
            text(&value, "format")?,
            "fss.recorded_pixel_change_report.v2"
        );
        assert_eq!(field(&value, "complete")?, &Value::Bool(true));
        assert_eq!(
            field(&value, "all_requested_segments_observed")?,
            &Value::Bool(true)
        );
        assert_eq!(field(&value, "absence_certifiable")?, &Value::Bool(false));
        assert_eq!(number(&value, "next_segment")?, count as i128);
        assert_eq!(number(&value, "resume_start_segment")?, 0);
        assert_eq!(number(&value, "resume_segment_count")?, count as i128);
        verify_receipts(&value)?;
        compare_with_decode(&imported, 0, count, 176, 144, &value)?;
        if format == "hevc" {
            let order = items(&value, "observations")?
                .iter()
                .map(|value| number(value, "segment"))
                .collect::<Test<Vec<_>>>()?;
            assert_ne!(order, (0..count as i128).collect::<Vec<_>>());
        }
        let again = imported.directory.0.join("again.json");
        let output = motion(&imported, 0, count, &again).output()?;
        success(&output);
        assert_eq!(fs::read(path)?, fs::read(again)?);
    }
    Ok(())
}

#[test]
fn mp4_quicktime_matroska_and_fragmented_recordings_reach_the_same_motion_pipeline() -> Test {
    let fixtures: &[(&str, &[u8], &str)] = &[
        (
            "mp4-avc",
            include_bytes!("../../fss-container/tests/fixtures/interleaved_av.mp4"),
            "mp4avc",
        ),
        (
            "mov-avc",
            include_bytes!("../../fss-container/tests/fixtures/qt_av.mov"),
            "mp4avc",
        ),
        (
            "mkv-avc",
            include_bytes!("../../fss-container/tests/fixtures/avc_av.mkv"),
            "mkvavc",
        ),
        (
            "fragment-avc",
            include_bytes!("../../fss-container/tests/fixtures/fragmented_av.mp4"),
            "mp4avc",
        ),
        (
            "mp4-hevc",
            include_bytes!("../../fss-container/tests/fixtures/hevc_av.mp4"),
            "mp4hevc",
        ),
        (
            "mov-hevc",
            include_bytes!("../../fss-container/tests/fixtures/qt_hevc.mov"),
            "mp4hevc",
        ),
        (
            "mkv-hevc",
            include_bytes!("../../fss-container/tests/fixtures/hevc_av.mkv"),
            "mkvhevc",
        ),
        (
            "fragment-hevc",
            include_bytes!("../../fss-container/tests/fixtures/hevc_fragmented_av.mp4"),
            "mp4hevc",
        ),
    ];
    for &(name, bytes, format) in fixtures {
        let imported = import(name, bytes, None)?;
        assert_eq!(imported.format, format);
        let path = imported.directory.0.join("motion.json");
        let output = motion(&imported, 0, 10, &path).output()?;
        success(&output);
        let value = report(&path, &output)?;
        assert_eq!(field(&value, "complete")?, &Value::Bool(true));
        assert_eq!(items(&value, "observations")?.len(), 10);
        verify_receipts(&value)?;
        compare_with_decode(&imported, 0, 10, 64, 48, &value)?;
    }
    Ok(())
}

#[test]
fn partial_comparisons_keep_a_valid_prefix_and_replay_the_original_random_access_range() -> Test {
    let imported = import("comparison-pressure", HEVC, Some("hevc"))?;
    let path = imported.directory.0.join("partial.json");
    let output = motion(&imported, 0, 8, &path)
        .args(["--max-comparisons", &(176 * 144).to_string()])
        .output()?;
    assert!(!output.status.success());
    let value = report(&path, &output)?;
    assert_eq!(items(&value, "observations")?.len(), 2);
    assert_eq!(field(&value, "complete")?, &Value::Bool(false));
    assert_eq!(
        text(field(&value, "error")?, "kind")?,
        "comparison_budget_exceeded"
    );
    assert_eq!(
        text(&value, "resume_strategy")?,
        "replay_original_random_access_range"
    );
    assert_eq!(number(&value, "resume_start_segment")?, 0);
    assert_eq!(number(&value, "resume_segment_count")?, 8);
    let completed = imported.directory.0.join("completed.json");
    let full = motion(&imported, 0, 8, &completed).output()?;
    success(&full);
    let full = report(&completed, &full)?;
    assert_eq!(
        items(&value, "observations")?,
        &items(&full, "observations")?[..2]
    );
    let observed = items(&value, "observations")?
        .iter()
        .map(|value| number(value, "segment"))
        .collect::<Test<Vec<_>>>()?;
    let expected = (0..8)
        .filter(|segment| !observed.contains(segment))
        .collect::<Vec<_>>();
    assert_eq!(integers(&value, "unobserved_segments")?, expected);
    assert_eq!(number(&value, "next_segment")?, expected[0]);
    verify_receipts(&value)?;
    Ok(())
}

#[test]
fn cumulative_video_work_is_reserved_before_decode_and_refusals_preserve_observations() -> Test {
    let imported = import("decode-pressure", AVC, Some("annexb"))?;
    for (label, allowance) in [
        ("zero", 0_u64),
        ("partial", 5 * 4_194_304 + AVC.len() as u64),
    ] {
        let path = imported.directory.0.join(format!("{label}.json"));
        let output = motion(&imported, 0, 12, &path)
            .args(["--work-units", &allowance.to_string()])
            .output()?;
        assert!(!output.status.success());
        let value = report(&path, &output)?;
        assert_eq!(field(&value, "complete")?, &Value::Bool(false));
        assert_eq!(
            text(field(&value, "error")?, "refusal_id")?,
            "ERR-DECODE-BOUNDS-001"
        );
        assert_eq!(
            text(&value, "decode_work_unit_model")?,
            "encoded_bytes_plus_coded_luma_capacity.v1"
        );
        assert!(number(&value, "decode_work_units")? <= i128::from(allowance));
        if allowance == 0 {
            assert!(items(&value, "observations")?.is_empty());
            assert_eq!(number(&value, "frames_decoded")?, 0);
            assert_eq!(number(&value, "decode_work_units")?, 0);
        } else {
            assert!(!items(&value, "observations")?.is_empty());
            assert!(items(&value, "observations")?.len() < 12);
            assert!(number(&value, "decode_work_units")? >= 5 * 4_194_304);
            assert_eq!(number(&value, "failure_segment")?, 5);
            verify_receipts(&value)?;
        }
    }
    Ok(())
}

#[test]
fn predicted_starts_gray_and_widened_pixel_ceilings_are_typed_refusals() -> Test {
    for (label, bytes, format, refusal) in [
        (
            "avc-refusal",
            AVC,
            "annexb",
            "ERR-DECODE-H264-RANGE-NOT-IDR-001",
        ),
        (
            "hevc-refusal",
            HEVC,
            "hevc",
            "ERR-DECODE-H265-RANGE-NOT-IRAP-001",
        ),
    ] {
        let imported = import(label, bytes, Some(format))?;
        let path = imported.directory.0.join("non-random-access.json");
        let output = motion(&imported, 1, 2, &path).output()?;
        assert!(!output.status.success());
        let value = report(&path, &output)?;
        assert_eq!(text(field(&value, "error")?, "refusal_id")?, refusal);
        assert!(items(&value, "observations")?.is_empty());
        assert_eq!(number(&value, "failure_segment")?, 1);
        // A positive user pixel ceiling below one minimum coded block is never rounded up.
        let path = imported.directory.0.join("ceiling.json");
        let output = motion(&imported, 0, 2, &path)
            .args(["--max-pixels", "1"])
            .output()?;
        assert!(!output.status.success());
        let value = report(&path, &output)?;
        assert_eq!(
            text(field(&value, "error")?, "refusal_id")?,
            "ERR-DECODE-BOUNDS-001"
        );
        assert!(items(&value, "observations")?.is_empty());
        let path = imported.directory.0.join("gray.json");
        let output = command(&imported.root, "motion")
            .args([
                "--import-id",
                &imported.identity,
                "--start-segment",
                "0",
                "--frame-count",
                "2",
                "--interpretation",
                "gray",
                "--pixel-delta",
                "16",
                "--minimum-changed-pixels",
                "1",
            ])
            .arg("--report-out")
            .arg(&path)
            .output()?;
        assert!(!output.status.success());
        let value = report(&path, &output)?;
        assert_eq!(
            text(field(&value, "error")?, "refusal_id")?,
            "ERR-DECODE-INTERPRETATION-001"
        );
    }
    Ok(())
}

#[test]
fn cra_leading_rasl_is_explicitly_unobserved_and_never_a_zero_motion_frame() -> Test {
    let imported = import("cra", CRA, Some("hevc"))?;
    let path = imported.directory.0.join("motion.json");
    let output = motion(&imported, 5, 7, &path).output()?;
    success(&output);
    let value = report(&path, &output)?;
    assert_eq!(field(&value, "complete")?, &Value::Bool(true));
    assert_eq!(items(&value, "observations")?.len(), 6);
    assert_eq!(integers(&value, "skipped_rasl_segments")?, [6]);
    assert_eq!(integers(&value, "unobserved_segments")?, [6]);
    assert_eq!(
        field(&value, "all_requested_segments_observed")?,
        &Value::Bool(false)
    );
    assert_eq!(number(&value, "next_segment")?, 12);
    assert_eq!(number(&value, "resume_start_segment")?, 5);
    verify_receipts(&value)?;
    compare_with_decode(&imported, 5, 7, 176, 144, &value)?;
    Ok(())
}

#[test]
fn corrupt_final_picture_preserves_previous_measurements_and_existing_exports() -> Test {
    let last = AVC
        .windows(3)
        .rposition(|bytes| bytes == [0, 0, 1])
        .ok_or("no start code")?;
    let truncated = &AVC[..last + (AVC.len() - last) / 2];
    let imported = import("corrupt", truncated, Some("annexb"))?;
    let path = imported.directory.0.join("partial.json");
    let output = motion(&imported, 0, 12, &path).output()?;
    assert!(!output.status.success());
    let value = report(&path, &output)?;
    assert_eq!(field(&value, "complete")?, &Value::Bool(false));
    assert_eq!(items(&value, "observations")?.len(), 11);
    assert_eq!(number(&value, "next_segment")?, 11);
    assert_eq!(integers(&value, "unobserved_segments")?, [11]);
    verify_receipts(&value)?;
    let before = fs::read(&path)?;
    assert!(!motion(&imported, 0, 12, &path).output()?.status.success());
    assert_eq!(fs::read(path)?, before);
    let forbidden = imported.root.join("refused-export.json");
    assert!(
        !motion(&imported, 0, 12, &forbidden)
            .output()?
            .status
            .success()
    );
    assert!(!forbidden.exists());
    Ok(())
}
