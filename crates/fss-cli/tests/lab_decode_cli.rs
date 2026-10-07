#![forbid(unsafe_code)]
//! `fss-lab decode` process contract on the checked-in media fixtures (fss-2h5zq.43 /
//! fss-2h5zq.44): golden source digests, tensor digests equal to an independent decode of the
//! exact fixture bytes, receipted refusals, the truncated-last omission, byte-identical reports
//! across two fresh roots, no pixel bytes in the report, and typed refusals for a non-empty root
//! and a missing interpretation. Every committed MJPEG fixture is covered: clean, truncated-last,
//! garbage-between-frames (every frame decoded, the import's omission spans reported),
//! dimension-change and zero-length (refused, nothing reported). A 1920x1080 MJPEG from the
//! in-repo encoder decodes under the per-frame budget derived from the decode limits. Each case
//! prints one CAPLOG record.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits, decode_luma};
use fss_core::ContentDigest;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// `frames[].frame_sha256` and spans of `mjpeg_clean_3frames.mjpeg`
/// (tests/fixtures/media/mjpeg/fixture_manifest.json).
const CLEAN: [(usize, usize, &str); 3] = [
    (
        0,
        907,
        "3b92d4ad9cbcb3621b43105760025eb5d771a0944967ebd431712687245d36bd",
    ),
    (
        907,
        942,
        "e1ebbdd9ef55c057215ba0ba1b233419cd30f420084758cef8e2a38a4776de25",
    ),
    (
        1849,
        661,
        "cc8e0d2b7d3be5bf40e952e41ab5fb1d2cf903f05b3cc626df1c01b188fa3905",
    ),
];

#[path = "../../fss-reference/tests/caplog_support/mod.rs"]
mod caplog_support;
use caplog_support::Record;

fn fixture(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/media")
        .join(relative)
}

struct Scratch(PathBuf);
impl Scratch {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-lab-decode-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory capacity".into())
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn lab_decode(input: &Path, root: &Path, interpretation: &str, json: bool) -> TestResult<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-lab"));
    command
        .arg("decode")
        .arg("--input")
        .arg(input)
        .arg("--root")
        .arg(root)
        .args(["--interpretation", interpretation]);
    if json {
        command.arg("--json");
    }
    Ok(command.output()?)
}

fn stdout(output: &Output) -> TestResult<String> {
    assert!(
        output.status.success(),
        "status={:?} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout.clone())?)
}

fn count(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

fn luma_digest(bytes: &[u8]) -> TestResult<ContentDigest> {
    let mut budget = DecodeBudget::new(100_000_000);
    let image = decode_luma(
        bytes,
        ContentDigest::sha256(bytes).bytes(),
        ComponentInterpretation::YCbCr,
        DecodeLimits::default(),
        &mut budget,
    )?;
    Ok(ContentDigest::sha256(image.pixels()))
}

/// Clean fixture: every frame decoded with golden source digests and independently reproduced
/// tensor digests; the report is byte-identical across two fresh roots and carries no pixels.
#[test]
fn clean_mjpeg_report_matches_goldens_and_is_identical_across_roots() -> TestResult {
    let scratch = Scratch::new("clean")?;
    let input = fixture("mjpeg/mjpeg_clean_3frames.mjpeg");
    let file = fs::read(&input)?;
    let first = stdout(&lab_decode(&input, &scratch.0.join("a"), "ycbcr", true)?)?;
    let second = stdout(&lab_decode(&input, &scratch.0.join("b"), "ycbcr", true)?)?;
    let identical = first == second;
    Record::new("clean_determinism_across_roots")
        .check(
            "report_digest",
            ContentDigest::sha256(first.as_bytes()).to_string(),
            ContentDigest::sha256(second.as_bytes()).to_string(),
        )
        .emit_checked(0, identical);
    assert!(identical, "reports differ across roots:\n{first}\n{second}");
    assert!(first.starts_with("{\"schema\":\"fss.lab.decode_report.v1\""));
    assert_eq!(count(&first, "\"outcome\":\"decoded\""), 3);
    assert_eq!(count(&first, "\"outcome\":\"refused\""), 0);
    assert!(first.contains("\"omissions\":[]"));
    assert!(first.contains(
        "\"totals\":{\"capsules\":3,\"decoded\":3,\"refused\":0,\"not_decoded\":0,\"omitted\":0}"
    ));
    assert!(first.contains("\"degraded\":false"));
    assert!(first.contains("\"absence_certifiable\":false"));
    assert!(first.contains("\"derived_not_evidence\":true"));
    assert!(
        !first.contains(&scratch.0.display().to_string()),
        "root path leaked"
    );
    for (index, (offset, len, golden)) in CLEAN.iter().enumerate() {
        let tensor = luma_digest(&file[*offset..offset + len])?;
        let row = format!("{{\"segment\":{index},\"capsule_id\":\"",);
        let pass = first.contains(&row)
            && first.contains(&format!("\"source_digest\":\"sha256:{golden}\""))
            && first.contains(&format!(
                "\"source_offset\":{offset},\"source_bytes\":{len}"
            ))
            && first.contains(&format!("\"tensor_digest\":\"{tensor}\""));
        // Each compared value is whether the report carries that exact row field.
        Record::new(&format!("clean_frame_{index}"))
            .check("segment_row", true, first.contains(&row))
            .check(
                "source_digest_sha256",
                true,
                first.contains(&format!("\"source_digest\":\"sha256:{golden}\"")),
            )
            .check(
                "source_span",
                true,
                first.contains(&format!(
                    "\"source_offset\":{offset},\"source_bytes\":{len}"
                )),
            )
            .check(
                "tensor_digest",
                true,
                first.contains(&format!("\"tensor_digest\":\"{tensor}\"")),
            )
            .emit_checked(0, pass);
        assert!(pass, "frame {index} lineage missing from report:\n{first}");
    }
    assert_eq!(
        count(&first, "\"tensor_shape\":[48,64,1],\"tensor_dtype\":\"u8\""),
        3
    );
    // The mask binding is read from each receipt (a fresh lab root has no retained policy).
    assert_eq!(count(&first, "\"mask_policy\":\"none\""), 3);
    // Bounded report: digests and counters only; far smaller than the 3 * 3072 luma bytes.
    assert!(first.len() < 8 * 1024, "report is {} bytes", first.len());
    Ok(())
}

/// Truncated last frame: two decoded frames plus one omission; exit 0 and degraded.
#[test]
fn truncated_last_is_degraded_with_one_omission() -> TestResult {
    let scratch = Scratch::new("truncated")?;
    let input = fixture("mjpeg/mjpeg_truncated_last.mjpeg");
    let report = stdout(&lab_decode(&input, &scratch.0.join("root"), "ycbcr", true)?)?;
    let pass = count(&report, "\"outcome\":\"decoded\"") == 2
        && count(&report, "\"outcome\":\"omitted\"") == 1
        // The dropped 633-byte truncated frame (fixture_manifest.json frames[2]) is accounted.
        && report.contains(
            "{\"outcome\":\"omitted\",\"source_offset\":1849,\"source_bytes\":633,\
             \"reason\":\"not_segmented\"}",
        )
        && report.contains("\"truncated_frame_omitted\"")
        && report.contains("\"degraded\":true")
        && report.contains(&format!("\"source_digest\":\"sha256:{}\"", CLEAN[1].2));
    Record::new("truncated_last")
        .check(
            "decoded",
            2_usize,
            count(&report, "\"outcome\":\"decoded\""),
        )
        .check(
            "omitted",
            1_usize,
            count(&report, "\"outcome\":\"omitted\""),
        )
        .check(
            "omission_row_1849_633_not_segmented",
            true,
            report.contains(
                "{\"outcome\":\"omitted\",\"source_offset\":1849,\"source_bytes\":633,\
                 \"reason\":\"not_segmented\"}",
            ),
        )
        .check(
            "truncated_frame_omitted",
            true,
            report.contains("\"truncated_frame_omitted\""),
        )
        .check("degraded", true, report.contains("\"degraded\":true"))
        .check(
            "frame_1_source_digest",
            true,
            report.contains(&format!("\"source_digest\":\"sha256:{}\"", CLEAN[1].2)),
        )
        .emit_checked(0, pass);
    assert!(pass, "{report}");
    Ok(())
}

/// A wrong declared interpretation refuses every frame with a retained receipt per frame.
#[test]
fn wrong_interpretation_rows_are_receipted_refusals() -> TestResult {
    let scratch = Scratch::new("gray")?;
    let input = fixture("mjpeg/mjpeg_clean_3frames.mjpeg");
    let report = stdout(&lab_decode(&input, &scratch.0.join("root"), "gray", true)?)?;
    let pass = count(
        &report,
        "\"outcome\":\"refused\",\"refusal\":\"unsupported\",\"error_id\":\"ERR-DECODE-001\"",
    ) == 3
        && count(
            &report,
            "\"receipt_domain\":\"fss.recorded_decode_refusal.v1\"",
        ) == 3
        && report.contains("\"degraded\":true")
        && !report.contains("\"tensor_digest\"");
    Record::new("gray_refusals")
        .check(
            "unsupported_refusals",
            3_usize,
            count(
                &report,
                "\"outcome\":\"refused\",\"refusal\":\"unsupported\",\"error_id\":\"ERR-DECODE-001\"",
            ),
        )
        .check(
            "refusal_receipts",
            3_usize,
            count(
                &report,
                "\"receipt_domain\":\"fss.recorded_decode_refusal.v1\"",
            ),
        )
        .check("degraded", true, report.contains("\"degraded\":true"))
        .check(
            "tensor_digest_present",
            false,
            report.contains("\"tensor_digest\""),
        )
        .emit_checked(0, pass);
    assert!(pass, "{report}");
    Ok(())
}

/// A single JPEG file is one decoded capsule; the human summary names it without pixels.
#[test]
fn single_jpeg_human_summary() -> TestResult {
    let scratch = Scratch::new("jpeg")?;
    let input = fixture("jpeg/rgb_64x48_colorbars_420.jpg");
    let text = stdout(&lab_decode(
        &input,
        &scratch.0.join("root"),
        "ycbcr",
        false,
    )?)?;
    let file = fs::read(&input)?;
    let segment_line = format!("segment 0 decoded 64x48 tensor {}", luma_digest(&file)?);
    let totals_line = "decoded=1 refused=0 not_decoded=0 omitted=0 degraded=false";
    let pass = text.contains(&segment_line) && text.contains(totals_line);
    Record::new("single_jpeg_text")
        .check("segment_line_present", true, text.contains(&segment_line))
        .check("totals_line_present", true, text.contains(totals_line))
        .emit_checked(0, pass);
    assert!(pass, "{text}");
    Ok(())
}

/// A non-empty root and a missing interpretation are refused before anything is written.
#[test]
fn non_empty_root_and_missing_interpretation_are_refused() -> TestResult {
    let scratch = Scratch::new("refuse")?;
    let input = fixture("mjpeg/mjpeg_clean_3frames.mjpeg");
    let root = scratch.0.join("root");
    fs::create_dir(&root)?;
    fs::write(root.join("occupied"), b"x")?;
    let occupied = lab_decode(&input, &root, "ycbcr", true)?;
    let stderr = String::from_utf8_lossy(&occupied.stderr).into_owned();
    let pass_root =
        occupied.status.code() == Some(1) && stderr.contains("ERR-LAB-ROOT-NOT-EMPTY-001");
    Record::new("non_empty_root")
        .check("exit", Some(1), occupied.status.code())
        .check(
            "stderr_error_id",
            true,
            stderr.contains("ERR-LAB-ROOT-NOT-EMPTY-001"),
        )
        .emit_checked(0, pass_root);
    assert!(pass_root, "{stderr}");
    let entries = fs::read_dir(&root)?.count();
    assert_eq!(entries, 1, "nothing written into an occupied root");

    let missing = Command::new(env!("CARGO_BIN_EXE_fss-lab"))
        .arg("decode")
        .arg("--input")
        .arg(&input)
        .arg("--root")
        .arg(scratch.0.join("fresh"))
        .output()?;
    let pass_missing = !missing.status.success() && !scratch.0.join("fresh").exists();
    Record::new("missing_interpretation")
        .check("exit_success", false, missing.status.success())
        .check("root_created", false, scratch.0.join("fresh").exists())
        .emit_checked(0, pass_missing);
    assert!(pass_missing);
    Ok(())
}

/// Garbage between frames (fss-dazsb, fss-2h5zq.44 D3): all three intact frames decode with the
/// manifest's golden spans and digests, and the two garbage spans the import omitted are reported
/// verbatim as omissions with the import's reason (mutant C3 drops them).
#[test]
fn garbage_between_frames_decodes_every_frame_and_reports_import_omissions() -> TestResult {
    let scratch = Scratch::new("garbage")?;
    let input = fixture("mjpeg/mjpeg_garbage_between_frames.mjpeg");
    let file = fs::read(&input)?;
    let report = stdout(&lab_decode(&input, &scratch.0.join("root"), "ycbcr", true)?)?;
    // fixture_manifest.json: frames at 0/907, 940/942 and 1902/661 with the clean frames' bytes.
    let spans = [(0_usize, 907_usize), (940, 942), (1902, 661)];
    let mut pass = count(&report, "\"outcome\":\"decoded\"") == 3
        && count(&report, "\"outcome\":\"refused\"") == 0
        && report.contains(
            "\"omissions\":[{\"outcome\":\"omitted\",\"source_offset\":907,\"source_bytes\":33,\
             \"reason\":\"GarbageBetweenFrames\"},{\"outcome\":\"omitted\",\"source_offset\":1882,\
             \"source_bytes\":20,\"reason\":\"GarbageBetweenFrames\"}]",
        )
        && report.contains(
            "\"totals\":{\"capsules\":3,\"decoded\":3,\"refused\":0,\"not_decoded\":0,\"omitted\":2}",
        )
        && report.contains("\"source_bytes_omitted\"")
        && report.contains("\"degraded\":true");
    let mut frames_present = Vec::new();
    for (index, (offset, len)) in spans.iter().enumerate() {
        let tensor = luma_digest(&file[*offset..offset + len])?;
        let present = report.contains(&format!("\"segment\":{index},\"capsule_id\":\""))
            && report.contains(&format!(
                "\"source_offset\":{offset},\"source_bytes\":{len},\"source_digest\":\"sha256:{}\"",
                CLEAN[index].2
            ))
            && report.contains(&format!("\"tensor_digest\":\"{tensor}\""));
        pass &= present;
        frames_present.push(present);
    }
    Record::new("garbage_between_frames")
        .check("decoded", 3_usize, count(&report, "\"outcome\":\"decoded\""))
        .check("refused", 0_usize, count(&report, "\"outcome\":\"refused\""))
        .check(
            "import_omissions_907_33_and_1882_20",
            true,
            report.contains(
                "\"omissions\":[{\"outcome\":\"omitted\",\"source_offset\":907,\"source_bytes\":33,\
                 \"reason\":\"GarbageBetweenFrames\"},{\"outcome\":\"omitted\",\"source_offset\":1882,\
                 \"source_bytes\":20,\"reason\":\"GarbageBetweenFrames\"}]",
            ),
        )
        .check(
            "totals",
            true,
            report.contains(
                "\"totals\":{\"capsules\":3,\"decoded\":3,\"refused\":0,\"not_decoded\":0,\"omitted\":2}",
            ),
        )
        .check(
            "source_bytes_omitted",
            true,
            report.contains("\"source_bytes_omitted\""),
        )
        .check("degraded", true, report.contains("\"degraded\":true"))
        .check("frames_at_manifest_spans", [true; 3], frames_present)
        .emit_checked(0, pass);
    assert!(pass, "{report}");
    Ok(())
}

/// Dimension change: a 16x16 frame then a 64x48 frame, each decoded at its own coded size with
/// its manifest digest; nothing omitted, not degraded.
#[test]
fn dimension_change_decodes_each_frame_at_its_own_size() -> TestResult {
    let scratch = Scratch::new("dimension")?;
    let input = fixture("mjpeg/mjpeg_dimension_change.mjpeg");
    let file = fs::read(&input)?;
    let report = stdout(&lab_decode(&input, &scratch.0.join("root"), "ycbcr", true)?)?;
    let small = luma_digest(&file[0..621])?;
    let large = luma_digest(&file[621..1528])?;
    let small_source = "\"source_offset\":0,\"source_bytes\":621,\"source_digest\":\"sha256:\
                        92b510feca8c4f0c29955a3c00ee54a8ae207c242cf6889666a8cfa4e9ff077a\"";
    let large_source = format!(
        "\"source_offset\":621,\"source_bytes\":907,\"source_digest\":\"sha256:{}\"",
        CLEAN[0].2
    );
    let small_frame = format!(
        "\"outcome\":\"decoded\",\"width\":16,\"height\":16,\"tensor_shape\":[16,16,1],\
         \"tensor_dtype\":\"u8\",\"tensor_layout\":\"hwc_luma\",\"tensor_digest\":\"{small}\""
    );
    let large_frame = format!(
        "\"outcome\":\"decoded\",\"width\":64,\"height\":48,\"tensor_shape\":[48,64,1],\
         \"tensor_dtype\":\"u8\",\"tensor_layout\":\"hwc_luma\",\"tensor_digest\":\"{large}\""
    );
    let pass = count(&report, "\"outcome\":\"decoded\"") == 2
        && report.contains(small_source)
        && report.contains(&large_source)
        && report.contains(&small_frame)
        && report.contains(&large_frame)
        && report.contains("\"omissions\":[]")
        && report.contains("\"degraded\":false");
    Record::new("dimension_change")
        .check(
            "decoded",
            2_usize,
            count(&report, "\"outcome\":\"decoded\""),
        )
        .check(
            "source_16x16_span_digest",
            true,
            report.contains(small_source),
        )
        .check(
            "source_64x48_span_digest",
            true,
            report.contains(&large_source),
        )
        .check("frame_16x16_tensor", true, report.contains(&small_frame))
        .check("frame_64x48_tensor", true, report.contains(&large_frame))
        .check("no_omissions", true, report.contains("\"omissions\":[]"))
        .check("not_degraded", true, report.contains("\"degraded\":false"))
        .emit_checked(0, pass);
    assert!(pass, "{report}");
    Ok(())
}

/// A zero-length file is refused at import: exit 1, no report on stdout, nothing decoded.
#[test]
fn zero_length_file_is_refused_with_no_report() -> TestResult {
    let scratch = Scratch::new("zero")?;
    let input = fixture("mjpeg/mjpeg_zero_length.mjpeg");
    let output = lab_decode(&input, &scratch.0.join("root"), "ycbcr", true)?;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let pass = output.status.code() == Some(1)
        && output.stdout.is_empty()
        && stderr.contains("lab decode import: input file is empty");
    Record::new("zero_length")
        .check("exit", Some(1), output.status.code())
        .check("stdout_bytes", 0_usize, output.stdout.len())
        .check(
            "stderr_input_file_is_empty",
            true,
            stderr.contains("lab decode import: input file is empty"),
        )
        .emit_checked(0, pass);
    assert!(pass, "status={:?} stderr={stderr}", output.status.code());
    Ok(())
}

/// fss-2h5zq.43 D1: 1920x1080 frames (4:2:0 and the worst-case 4:4:4 layout) from the in-repo
/// encoder decode under the per-frame budget derived from the decode limits; the fixed 100M
/// budget refused both (a 4:2:0 1080p frame needs about 205M work units).
#[test]
fn full_hd_frames_decode_under_the_limit_derived_budget() -> TestResult {
    use fss_reference::media_fixture::jpeg::{
        JpegConfig, Subsampling, encode_jpeg, encode_mjpeg, generate_gradient_rgb,
    };
    let scratch = Scratch::new("fullhd")?;
    let pixels = generate_gradient_rgb(1920, 1080);
    let yuv420 = encode_jpeg(1920, 1080, &pixels, &JpegConfig::default())?;
    let yuv444 = encode_jpeg(
        1920,
        1080,
        &pixels,
        &JpegConfig {
            subsampling: Subsampling::Yuv444,
            ..JpegConfig::default()
        },
    )?;
    let input = scratch.0.join("fullhd.mjpeg");
    fs::write(
        &input,
        encode_mjpeg(&[yuv420.as_slice(), yuv444.as_slice()]),
    )?;
    let report = stdout(&lab_decode(&input, &scratch.0.join("root"), "ycbcr", true)?)?;
    let bound = DecodeLimits::default().luma_work_bound();
    let mut pass = count(&report, "\"outcome\":\"decoded\"") == 2
        && count(&report, "\"tensor_shape\":[1080,1920,1]") == 2
        && report.contains("\"degraded\":false");
    let mut record = Record::new("full_hd_decode")
        .check(
            "decoded",
            2_usize,
            count(&report, "\"outcome\":\"decoded\""),
        )
        .check(
            "tensor_shape_1080x1920",
            2_usize,
            count(&report, "\"tensor_shape\":[1080,1920,1]"),
        )
        .check("not_degraded", true, report.contains("\"degraded\":false"));
    for (name, frame) in [("yuv420", &yuv420), ("yuv444", &yuv444)] {
        let mut budget = DecodeBudget::new(bound);
        let image = decode_luma(
            frame,
            ContentDigest::sha256(frame).bytes(),
            ComponentInterpretation::YCbCr,
            DecodeLimits::default(),
            &mut budget,
        )?;
        let tensor_row = format!(
            "\"tensor_digest\":\"{}\"",
            ContentDigest::sha256(image.pixels())
        );
        let work_row = format!("\"work_units\":{}}}", budget.used());
        pass &= budget.used() > 100_000_000
            && report.contains(&tensor_row)
            && report.contains(&work_row);
        record = record
            .check(
                &format!("{name}_work_units_above_100m"),
                true,
                budget.used() > 100_000_000,
            )
            .check(
                &format!("{name}_tensor_digest"),
                true,
                report.contains(&tensor_row),
            )
            .check(
                &format!("{name}_work_units"),
                true,
                report.contains(&work_row),
            );
    }
    record.emit_checked(0, pass);
    assert!(pass, "{report}");
    Ok(())
}
