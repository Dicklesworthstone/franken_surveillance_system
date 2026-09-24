#![forbid(unsafe_code)]
//! Cross-process retained H.264 decode: import an Annex-B recording, then decode an IDR-led
//! range through the canonical pure-Rust codec and compare every picture with the sealed
//! FFmpeg oracle digests committed beside the codec fixtures.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::ContentDigest;

/// 176x144, twelve pictures, one IDR then P pictures with three reference frames.
const STREAM: &[u8] =
    include_bytes!("../../fss-codec-h264/tests/fixtures/decode/p_qcif_ref3_p4x4.h264");
/// FFmpeg `yuv420p` framehash of `STREAM` (offline sealed oracle; FFmpeg never runs here).
const ORACLE: &str =
    include_str!("../../fss-codec-h264/tests/fixtures/decode/p_qcif_ref3_p4x4.sha256");

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-h264-cli-{name}-{}-{attempt}",
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
        .args(["--site", "site:h264-cli"]);
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

fn values(output: &Output, name: &str) -> TestResult<Vec<String>> {
    let prefix = format!("{name}=");
    Ok(String::from_utf8(output.stdout.clone())?
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix).map(str::to_owned))
        .collect())
}

fn field(output: &Output, name: &str) -> TestResult<String> {
    values(output, name)?
        .into_iter()
        .next()
        .ok_or_else(|| std::io::Error::other(format!("missing field {name}")).into())
}

fn imported(name: &str, bytes: &[u8]) -> TestResult<(OwnedDirectory, PathBuf, String)> {
    let directory = OwnedDirectory::new(name)?;
    let root = directory.0.join("deployment");
    let input = directory.0.join("camera.h264");
    fs::write(&input, bytes)?;
    let output = command(&root, "import")
        .arg("--input")
        .arg(&input)
        .args([
            "--sensor",
            "sensor:h264-cli",
            "--stream",
            "stream:h264-cli",
            "--receive-time-ns",
            "1000000000",
            "--media-format",
            "annexb",
        ])
        .output()?;
    success(&output);
    assert_eq!(field(&output, "media_format")?, "annexb");
    let id = field(&output, "import_identity")?;
    // Decode must use retained custody, not the original input file.
    fs::remove_file(input)?;
    Ok((directory, root, id))
}

fn decode(root: &Path, id: &str, first: &str, count: &str) -> Command {
    let mut command = command(root, "decode");
    command.args([
        "--import-id",
        id,
        "--segment",
        first,
        "--segment-count",
        count,
        "--interpretation",
        "ycbcr",
    ]);
    command
}

fn refusal(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .find_map(|line| line.strip_prefix("refusal_id=").map(str::to_owned))
        .unwrap_or_default()
}

#[test]
fn annexb_range_decode_matches_ffmpeg_oracle_and_exports_every_luma_frame() -> TestResult {
    let (directory, root, id) = imported("oracle", STREAM)?;
    let expected: Vec<String> = ORACLE
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .filter_map(|line| line.split_whitespace().nth(2))
        .map(|digest| format!("sha256:{digest}"))
        .collect();
    assert_eq!(expected.len(), 12);
    let pgm_path = directory.0.join("frames.pgm");
    let decoded = decode(&root, &id, "0", "12")
        .arg("--output")
        .arg(&pgm_path)
        .output()?;
    success(&decoded);
    assert_eq!(values(&decoded, "frame_i420_sha256")?, expected);
    assert_eq!(field(&decoded, "h264_frames_decoded")?, "12");
    assert_eq!(field(&decoded, "decode_complete")?, "true");
    assert_eq!(field(&decoded, "decode_published")?, "false");
    assert_eq!(field(&decoded, "absence_certifiable")?, "false");
    let idr = values(&decoded, "frame_idr")?;
    assert_eq!(idr.first().map(String::as_str), Some("true"));
    assert!(idr[1..].iter().all(|value| value == "false"));
    // One binary PGM per frame, in decode order; each luma digest is the plane in the file.
    let pgm = fs::read(&pgm_path)?;
    assert_eq!(
        ContentDigest::sha256(&pgm).to_text(),
        field(&decoded, "pgm_sha256")?
    );
    let header = b"P5\n176 144\n255\n";
    let frame_bytes = header.len() + 176 * 144;
    assert_eq!(pgm.len(), 12 * frame_bytes);
    let luma = values(&decoded, "frame_luma_sha256")?;
    for (index, image) in pgm.chunks(frame_bytes).enumerate() {
        assert!(image.starts_with(header));
        assert_eq!(
            ContentDigest::sha256(&image[header.len()..]).to_text(),
            luma[index]
        );
    }
    // The same range decodes identically in a new process (deterministic, nothing published).
    let again = decode(&root, &id, "0", "12").output()?;
    success(&again);
    assert_eq!(
        values(&again, "frame_receipt_digest")?,
        values(&decoded, "frame_receipt_digest")?
    );
    Ok(())
}

#[test]
fn predicted_range_start_gray_and_jpeg_only_reads_are_typed_refusals() -> TestResult {
    let (_directory, root, id) = imported("refusals", STREAM)?;
    let predicted = decode(&root, &id, "1", "2").output()?;
    assert!(!predicted.status.success());
    assert_eq!(refusal(&predicted), "ERR-DECODE-H264-RANGE-NOT-IDR-001");
    let beyond = decode(&root, &id, "0", "13").output()?;
    assert!(!beyond.status.success());
    let mut gray = command(&root, "decode");
    gray.args([
        "--import-id",
        &id,
        "--segment",
        "0",
        "--interpretation",
        "gray",
    ]);
    let gray = gray.output()?;
    assert!(!gray.status.success());
    assert_eq!(refusal(&gray), "ERR-DECODE-INTERPRETATION-001");
    let mut reopen = command(&root, "read-decoded");
    reopen.args([
        "--import-id",
        &id,
        "--segment",
        "0",
        "--interpretation",
        "ycbcr",
    ]);
    let reopen = reopen.output()?;
    assert!(!reopen.status.success());
    assert_eq!(refusal(&reopen), "ERR-DECODE-UNSUPPORTED-MEDIA-001");
    Ok(())
}

#[test]
fn corrupt_stream_and_unknown_import_fail_closed() -> TestResult {
    // Truncate the last predicted picture: custody accepts the recorded bytes, the codec must
    // refuse the damaged picture instead of concealing it.
    let last_nal = STREAM
        .windows(3)
        .rposition(|w| w == [0, 0, 1])
        .ok_or("fixture has no start code")?;
    let truncated = &STREAM[..last_nal + (STREAM.len() - last_nal) / 2];
    let (_directory, root, id) = imported("corrupt", truncated)?;
    let output = decode(&root, &id, "0", "12").output()?;
    assert!(!output.status.success());
    assert_eq!(values(&output, "frame_segment")?.len(), 11);
    assert!(
        refusal(&output).starts_with("ERR-DECODE-"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let unknown = ContentDigest::sha256(b"never imported").to_text();
    let missing = decode(&root, &unknown, "0", "1").output()?;
    assert!(!missing.status.success());
    Ok(())
}
