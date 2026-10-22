#![forbid(unsafe_code)]
//! `fss-file import` process contract on the checked-in media fixtures (fss-2h5zq.18).
//!
//! The original bead text targeted `fss-lab ingest`, which was closed as superseded by the
//! product command `fss-file import` (fss-2h5zq.17); these tests pin the same contract
//! against the real binary. Clean H.264 Annex-B, MJPEG and JPEG fixtures import with a
//! key=value report matching the fixture manifests (segment counts, input bytes, input
//! sha256); degraded fixtures give typed findings; an oversize input is refused before any
//! allocation; rtpplay routes through the recorded-RTP import and is never guessed; the
//! report is byte-identical across two fresh roots; a re-run into the same root is
//! idempotent; multi-chunk import keeps the segment spans but changes the import identity;
//! out-of-range chunk bytes are a parse error; reopening + verifying the import re-derives
//! the same source digest; and the acquisition history uses the real state-kind names.
//! Each case prints one CAPLOG record.

use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::ContentDigest;

type TestResult = Result<(), Box<dyn Error>>;

/// Committed rtpdump fixtures (tests/fixtures/media/rtp), SSRC 0x11223344, payload type 96.
const SSRC: &str = "287454020";

/// `clean.264` manifest (tests/fixtures/media/h264/fixture_manifest.json).
const H264_SHA256: &str =
    "8c306a4717970585256481714c96b1e868206c83f7cfa964602878276a09eff8";
const H264_BYTES: u64 = 3558;
const H264_AU: &str = "5";

/// `mjpeg_clean_3frames.mjpeg` manifest (tests/fixtures/media/mjpeg/fixture_manifest.json).
const MJPEG_CLEAN_SHA256: &str =
    "5d0ad1de84dd83b354310d873ec1f1f8d02557b33b4420f3838673679d7591e7";
const MJPEG_CLEAN_BYTES: u64 = 2510;

/// `gray_16x16_flat.jpg` manifest (tests/fixtures/media/jpeg/fixture_manifest.json).
const JPEG_SHA256: &str =
    "bb89bdbebe3b4aa81a6bb3a0d3a548d4d8b4e0d633a511de75b0fd6c41062577";
const JPEG_BYTES: u64 = 329;

#[path = "../../fss-reference/tests/caplog_support/mod.rs"]
mod caplog_support;
use caplog_support::Record;

fn fixture(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/media")
        .join(relative)
}

/// A scratch directory removed on drop (the deployment root lives inside it).
struct Scratch(PathBuf);
impl Scratch {
    fn new(name: &str) -> Result<Self, Box<dyn Error>> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-lab-ingest-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
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

/// Run `fss-file import` on `source` into `root` with the extra options (e.g. `--media-format`).
fn import(root: &Path, source: &Path, extra: &[&str]) -> io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import")
        .arg("--root")
        .arg(root)
        .args(["--site", "site:lab-ingest-cli"])
        .arg("--input")
        .arg(source)
        .args([
            "--sensor",
            "sensor:lab-ingest-cli",
            "--stream",
            "stream:lab-ingest-cli",
            "--receive-time-ns",
            "2000000000",
        ])
        .args(extra)
        .output()
}

/// Run another `fss-file` action (`inspect`, `verify`) against an existing root.
fn action(root: &Path, argv: &[&str]) -> io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .args(argv)
        .arg("--root")
        .arg(root)
        .args(["--site", "site:lab-ingest-cli"])
        .output()
}

/// The owner's stream binding for the committed rtpdump fixtures (never sniffed).
const RTP_BINDING: [&str; 10] = [
    "--media-format",
    "rtpplay",
    "--rtp-generation",
    "1",
    "--rtp-ssrc",
    SSRC,
    "--rtp-payload-type",
    "96",
    "--rtp-mode",
    "non-interleaved",
];

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "exit {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn field(output: &Output, name: &str) -> Result<String, Box<dyn Error>> {
    let text = std::str::from_utf8(&output.stdout)?;
    let prefix = format!("{name}=");
    text.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other(format!("missing output field {name}")).into())
}

fn sha256_text(bytes: &[u8]) -> String {
    ContentDigest::sha256(bytes).to_text()
}

/// The media report for a clean fixture: counts, spans, digests, format, and the file-session
/// absence gate (a file import never certifies absence).
fn assert_clean_media_report(output: &Output, seg_count: &str) -> TestResult {
    success(output);
    assert_eq!(field(output, "operation")?, "new");
    assert_eq!(field(output, "segment_count")?, seg_count);
    assert_eq!(field(output, "absence_certifiable")?, "false");
    // A file session ends at end-of-source with the terminal `cancelled` kind (no live
    // continuity); the history carries the real state-kind names.
    assert_eq!(field(output, "acquisition_terminal")?, "cancelled");
    assert_eq!(field(output, "acquisition_ending")?, "end_of_file_source");
    let history = field(output, "acquisition_history")?;
    for kind in [
        "requested",
        "authenticated",
        "adapter_accepted",
        "first_frame_observed",
        "cancelled",
    ] {
        assert!(
            history.split(',').any(|k| k == kind),
            "history {history:?} missing kind {kind:?}"
        );
    }
    Ok(())
}

/// Clean H.264 Annex-B: the whole stream is one import; the report matches the manifest.
#[test]
fn clean_h264_import_matches_manifest() -> TestResult {
    let scratch = Scratch::new("h264")?;
    let input = fixture("h264/clean.264");
    let output = import(
        &scratch.0.join("root"),
        &input,
        &["--media-format", "annexb"],
    )?;
    let expected = sha256_text(&fs::read(&input)?);
    let pass = expected == H264_SHA256;
    let record = Record::new("clean_h264_import")
        .check("input_sha256", format!("sha256:{H264_SHA256}"), field(&output, "input_sha256")?)
        .check(
            "input_bytes",
            H264_BYTES.to_string(),
            field(&output, "input_bytes")?,
        )
        .check("segment_count", H264_AU.to_string(), field(&output, "segment_count")?)
        .check(
            "media_format",
            "annexb".to_string(),
            field(&output, "media_format")?,
        );
    record.emit_checked(0, pass && record.passed());
    assert_clean_media_report(&output, H264_AU)?;
    assert_eq!(field(&output, "omission_count")?, "0");
    Ok(())
}

/// Clean MJPEG: every frame is a segment; the report matches the manifest.
#[test]
fn clean_mjpeg_import_matches_manifest() -> TestResult {
    let scratch = Scratch::new("mjpeg")?;
    let input = fixture("mjpeg/mjpeg_clean_3frames.mjpeg");
    let output = import(
        &scratch.0.join("root"),
        &input,
        &["--media-format", "mjpeg"],
    )?;
    let expected = sha256_text(&fs::read(&input)?);
    let record = Record::new("clean_mjpeg_import")
        .check(
            "input_sha256",
            format!("sha256:{MJPEG_CLEAN_SHA256}"),
            field(&output, "input_sha256")?,
        )
        .check(
            "input_bytes",
            MJPEG_CLEAN_BYTES.to_string(),
            field(&output, "input_bytes")?,
        )
        .check("segment_count", "3".to_string(), field(&output, "segment_count")?)
        .check(
            "media_format",
            "mjpeg".to_string(),
            field(&output, "media_format")?,
        );
    record.emit_checked(0, expected == MJPEG_CLEAN_SHA256 && record.passed());
    assert_clean_media_report(&output, "3")?;
    assert_eq!(field(&output, "omission_count")?, "0");
    Ok(())
}

/// Clean single-frame JPEG: auto-detection imports one segment; the report matches the manifest.
#[test]
fn clean_jpeg_import_matches_manifest() -> TestResult {
    let scratch = Scratch::new("jpeg")?;
    let input = fixture("jpeg/gray_16x16_flat.jpg");
    let output = import(&scratch.0.join("root"), &input, &[])?;
    let expected = sha256_text(&fs::read(&input)?);
    let record = Record::new("clean_jpeg_import")
        .check(
            "input_sha256",
            format!("sha256:{JPEG_SHA256}"),
            field(&output, "input_sha256")?,
        )
        .check(
            "input_bytes",
            JPEG_BYTES.to_string(),
            field(&output, "input_bytes")?,
        )
        .check("segment_count", "1".to_string(), field(&output, "segment_count")?);
    record.emit_checked(0, expected == JPEG_SHA256 && record.passed());
    assert_clean_media_report(&output, "1")?;
    Ok(())
}

/// Determinism: the same clean fixture into two fresh roots produces byte-identical reports.
#[test]
fn clean_import_is_deterministic_across_roots() -> TestResult {
    let scratch = Scratch::new("determinism")?;
    let input = fixture("mjpeg/mjpeg_clean_3frames.mjpeg");
    let first = import(&scratch.0.join("a"), &input, &["--media-format", "mjpeg"])?;
    let second = import(&scratch.0.join("b"), &input, &["--media-format", "mjpeg"])?;
    let a = String::from_utf8_lossy(&first.stdout).to_string();
    let b = String::from_utf8_lossy(&second.stdout).to_string();
    let pass = a == b;
    Record::new("clean_determinism_across_roots")
        .check(
            "report_digest",
            sha256_text(a.as_bytes()),
            sha256_text(b.as_bytes()),
        )
        .emit_checked(0, pass);
    assert!(pass, "reports differ across roots:\n{a}\n{b}");
    Ok(())
}

/// Idempotent re-run: a second import into the same root reports `idempotent_existing`
/// and re-derives the same identity and authority anchor.
#[test]
fn repeated_import_is_idempotent() -> TestResult {
    let scratch = Scratch::new("idempotent")?;
    let root = scratch.0.join("root");
    let input = fixture("mjpeg/mjpeg_clean_3frames.mjpeg");
    let first = import(&root, &input, &["--media-format", "mjpeg"])?;
    let second = import(&root, &input, &["--media-format", "mjpeg"])?;
    let pass = field(&second, "operation")? == "idempotent_existing";
    Record::new("repeated_import_idempotent")
        .check(
            "operation",
            "idempotent_existing".to_string(),
            field(&second, "operation")?,
        )
        .check(
            "identity_stable",
            field(&first, "import_identity")?,
            field(&second, "import_identity")?,
        )
        .emit_checked(0, pass);
    assert!(pass);
    Ok(())
}

/// Truncated last frame: two intact segments plus one omission; still exit 0.
#[test]
fn truncated_last_is_degraded_with_omission() -> TestResult {
    let scratch = Scratch::new("truncated")?;
    let input = fixture("mjpeg/mjpeg_truncated_last.mjpeg");
    let output = import(&scratch.0.join("root"), &input, &["--media-format", "mjpeg"])?;
    let omitted = field(&output, "omission_count")?;
    let pass = field(&output, "segment_count")? == "2" && omitted != "0";
    Record::new("truncated_last_degraded")
        .check("segment_count", "2".to_string(), field(&output, "segment_count")?)
        .check("omission_count_positive", true, omitted != "0")
        .emit_checked(0, pass);
    success(&output);
    assert!(pass);
    Ok(())
}

/// Garbage between frames: all three intact frames decode to segments; the two garbage spans
/// are reported as omissions, not lost frames.
#[test]
fn garbage_between_frames_reports_omissions() -> TestResult {
    let scratch = Scratch::new("garbage")?;
    let input = fixture("mjpeg/mjpeg_garbage_between_frames.mjpeg");
    let output = import(&scratch.0.join("root"), &input, &["--media-format", "mjpeg"])?;
    let omitted = field(&output, "omission_count")?;
    let pass = field(&output, "segment_count")? == "3"
        && omitted.parse::<u64>().unwrap_or(0) >= 2;
    Record::new("garbage_between_frames_omissions")
        .check("segment_count", "3".to_string(), field(&output, "segment_count")?)
        .check(
            "omission_count_at_least_2",
            true,
            omitted.parse::<u64>().unwrap_or(0) >= 2,
        )
        .emit_checked(0, pass);
    success(&output);
    assert!(pass);
    Ok(())
}

/// A zero-length file is refused at import: exit 1, no report on stdout.
#[test]
fn zero_length_file_is_refused() -> TestResult {
    let scratch = Scratch::new("zero")?;
    let input = fixture("mjpeg/mjpeg_zero_length.mjpeg");
    let output = import(&scratch.0.join("root"), &input, &["--media-format", "mjpeg"])?;
    let pass = !output.status.success() && output.stdout.is_empty();
    Record::new("zero_length_refused")
        .check("exit_nonzero", true, !output.status.success())
        .check("stdout_empty", true, output.stdout.is_empty())
        .emit_checked(0, pass);
    assert!(pass);
    Ok(())
}

/// An oversize input is refused from metadata before any read/allocation: a typed limit error,
/// exit 1, and no import report.
#[test]
fn oversize_input_refused_before_allocation() -> TestResult {
    let scratch = Scratch::new("oversize")?;
    let input = scratch.0.join("big.mjpeg");
    let mut bytes = Vec::with_capacity(64 * 1024);
    // Copy the clean MJPEG so the bytes are plausible, then pad well past the limit.
    bytes.extend_from_slice(&fs::read(fixture("mjpeg/mjpeg_clean_3frames.mjpeg"))?);
    while (bytes.len() as u64) < 64 * 1024 {
        bytes.push(0x00);
    }
    fs::write(&input, &bytes)?;
    let output = import(
        &scratch.0.join("root"),
        &input,
        &["--media-format", "mjpeg", "--max-source-bytes", "1024"],
    )?;
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let pass = !output.status.success()
        && stderr.contains("ERR-CLI-RUNTIME-FAILURE-001")
        && stderr.contains("exceeds limit");
    Record::new("oversize_refused_before_allocation")
        .check("exit_nonzero", true, !output.status.success())
        .check("typed_limit_error", true, stderr.contains("exceeds limit"))
        .emit_checked(0, pass);
    assert!(pass, "stderr: {stderr}");
    Ok(())
}

/// Out-of-range source bounds are parse errors (exit 2), refused before the file is opened.
#[test]
fn out_of_range_source_bounds_are_usage_errors() -> TestResult {
    let scratch = Scratch::new("bounds")?;
    let input = fixture("mjpeg/mjpeg_clean_3frames.mjpeg");
    let zero = import(
        &scratch.0.join("root"),
        &input,
        &["--media-format", "mjpeg", "--chunk-bytes", "0"],
    )?;
    let pass = zero.status.code() == Some(2)
        && String::from_utf8_lossy(&zero.stderr).contains("ERR-CLI-MALFORMED-VALUE-001");
    Record::new("out_of_range_chunk_zero")
        .check("exit_2", true, zero.status.code() == Some(2))
        .check(
            "malformed_value",
            true,
            String::from_utf8_lossy(&zero.stderr).contains("ERR-CLI-MALFORMED-VALUE-001"),
        )
        .emit_checked(0, pass);
    assert!(pass);
    Ok(())
}

/// Multi-chunk: `--chunk-bytes 4096` keeps the same segment count and input digest but yields a
/// different import identity than the default chunk size.
#[test]
fn multi_chunk_keeps_spans_changes_identity() -> TestResult {
    let scratch = Scratch::new("multichunk")?;
    let input = fixture("mjpeg/mjpeg_clean_3frames.mjpeg");
    let default = import(&scratch.0.join("a"), &input, &["--media-format", "mjpeg"])?;
    let chunked = import(
        &scratch.0.join("b"),
        &input,
        &["--media-format", "mjpeg", "--chunk-bytes", "4096"],
    )?;
    let same_segments = field(&default, "segment_count")? == field(&chunked, "segment_count")?;
    let same_digest = field(&default, "input_sha256")? == field(&chunked, "input_sha256")?;
    let different_identity =
        field(&default, "import_identity")? != field(&chunked, "import_identity")?;
    let pass = same_segments && same_digest && different_identity;
    Record::new("multi_chunk_same_spans_new_identity")
        .check("segment_count_stable", true, same_segments)
        .check("input_digest_stable", true, same_digest)
        .check("identity_changes", true, different_identity)
        .emit_checked(0, pass);
    assert!(pass);
    Ok(())
}

/// rtpplay routes a recorded RTP session through the recorded-RTP import; the binding is the
/// owner's and is never guessed.
#[test]
fn rtpplay_imports_and_auto_is_refused() -> TestResult {
    let scratch = Scratch::new("rtp")?;
    let source = fixture("rtp/clean.rtp");
    let imported = import(&scratch.0.join("a"), &source, &RTP_BINDING)?;
    let auto = import(&scratch.0.join("b"), &source, &["--media-format", "auto"])?;
    let auto_refused = !auto.status.success()
        && String::from_utf8_lossy(&auto.stderr).contains("rtp_binding_required");
    let pass = field(&imported, "media_format")? == "rtpplay"
        && field(&imported, "access_unit_count")? == "5"
        && field(&imported, "capsule_count")? == "5"
        && auto_refused;
    Record::new("rtpplay_import_and_auto_refused")
        .check("media_format", "rtpplay".to_string(), field(&imported, "media_format")?)
        .check(
            "access_unit_count",
            "5".to_string(),
            field(&imported, "access_unit_count")?,
        )
        .check("capsule_count", "5".to_string(), field(&imported, "capsule_count")?)
        .check("auto_refused", true, auto_refused)
        .emit_checked(0, pass);
    success(&imported);
    assert!(pass);
    Ok(())
}

/// Reopen + verify: a separate process reopens the retained import and re-derives the source
/// digest, cross-checking the ledger/publication state against the original report.
#[test]
fn reopen_verify_rederives_source_digest() -> TestResult {
    let scratch = Scratch::new("reopen")?;
    let root = scratch.0.join("root");
    let input = fixture("mjpeg/mjpeg_clean_3frames.mjpeg");
    let imported = import(&root, &input, &["--media-format", "mjpeg"])?;
    let identity = field(&imported, "import_identity")?;
    let verify = action(
        &root,
        &["verify", "--import-id", &identity],
    )?;
    let pass = field(&verify, "verified_source_sha256")?
        == field(&imported, "input_sha256")?
        && field(&verify, "authority_sequence")? == field(&imported, "authority_sequence")?;
    Record::new("reopen_verify_rederives_source")
        .check(
            "verified_source_sha256",
            field(&imported, "input_sha256")?,
            field(&verify, "verified_source_sha256")?,
        )
        .check(
            "authority_sequence_stable",
            field(&imported, "authority_sequence")?,
            field(&verify, "authority_sequence")?,
        )
        .emit_checked(0, pass);
    success(&verify);
    assert!(pass);
    Ok(())
}
