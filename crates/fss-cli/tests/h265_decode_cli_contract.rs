#![forbid(unsafe_code)]
//! Cross-process retained H.265 decode: `fss-file import` detects and retains an HEVC Annex-B
//! recording, then `fss-file decode` decodes an IRAP-led range through the canonical pure-Rust
//! codec. Every picture is compared with the sealed FFmpeg oracle digests committed beside the
//! fixtures; FFmpeg never runs here.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::ContentDigest;

/// 176x144, eight pictures, libx265 defaults (B pyramid: display order differs from decode order).
const STREAM: &[u8] =
    include_bytes!("../../fss-codec-h265/tests/fixtures/decode/f_qcif_default.h265");
/// FFmpeg `yuv420p` framehash of `STREAM` in output order.
const ORACLE: &str =
    include_str!("../../fss-codec-h265/tests/fixtures/decode/f_qcif_default.sha256");
/// IDR, four trailing pictures, a CRA (segment 5) with one RASL picture (segment 6), five more.
const OPEN_GOP: &[u8] =
    include_bytes!("../../fss-codec-h265/tests/fixtures/decode/b_qcif_opengop.h265");
/// FFmpeg framehash of `OPEN_GOP` decoded from its CRA access unit onwards.
const OPEN_GOP_FROM_CRA: &str =
    include_str!("../../fss-reference/tests/fixtures/hevc_ingest/b_qcif_opengop_from_cra.sha256");

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-h265-cli-{name}-{}-{attempt}",
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
        .args(["--site", "site:h265-cli"]);
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

fn refusal(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .find_map(|line| line.strip_prefix("refusal_id=").map(str::to_owned))
        .unwrap_or_default()
}

fn oracle(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .filter_map(|line| line.split_whitespace().nth(2))
        .map(|digest| format!("sha256:{digest}"))
        .collect()
}

fn import(directory: &OwnedDirectory, bytes: &[u8], format: Option<&str>) -> TestResult<Output> {
    let root = directory.0.join("deployment");
    let input = directory.0.join("camera.h265");
    fs::write(&input, bytes)?;
    let mut import = command(&root, "import");
    import.arg("--input").arg(&input).args([
        "--sensor",
        "sensor:h265-cli",
        "--stream",
        "stream:h265-cli",
        "--receive-time-ns",
        "1000000000",
    ]);
    if let Some(format) = format {
        import.args(["--media-format", format]);
    }
    let output = import.output()?;
    // Decode must use retained custody, not the original input file.
    fs::remove_file(input)?;
    Ok(output)
}

fn imported(name: &str, bytes: &[u8]) -> TestResult<(OwnedDirectory, PathBuf, String)> {
    let directory = OwnedDirectory::new(name)?;
    let output = import(&directory, bytes, None)?;
    success(&output);
    assert_eq!(field(&output, "media_format")?, "hevc");
    let id = field(&output, "import_identity")?;
    let root = directory.0.join("deployment");
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

#[test]
fn hevc_import_decodes_to_the_ffmpeg_oracle_and_exports_every_luma_frame() -> TestResult {
    let (directory, root, id) = imported("oracle", STREAM)?;
    let expected = oracle(ORACLE);
    assert_eq!(expected.len(), 8);
    let pgm_path = directory.0.join("frames.pgm");
    let decoded = decode(&root, &id, "0", "8")
        .arg("--output")
        .arg(&pgm_path)
        .output()?;
    success(&decoded);
    assert_eq!(values(&decoded, "frame_i420_sha256")?, expected);
    assert_eq!(field(&decoded, "h265_frames_decoded")?, "8");
    assert_eq!(field(&decoded, "h265_rasl_skipped")?, "0");
    assert_eq!(field(&decoded, "decode_complete")?, "true");
    assert_eq!(field(&decoded, "decode_published")?, "false");
    assert_eq!(field(&decoded, "absence_certifiable")?, "false");
    let idr = values(&decoded, "frame_idr")?;
    assert_eq!(idr.first().map(String::as_str), Some("true"));
    // Display order: the coding segments are reordered by the B pyramid.
    let segments = values(&decoded, "frame_segment")?;
    let mut sorted: Vec<usize> = segments
        .iter()
        .map(|s| s.parse())
        .collect::<Result<_, _>>()?;
    let in_order = sorted.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, (0..8).collect::<Vec<_>>());
    assert_ne!(in_order, sorted);
    let pgm = fs::read(&pgm_path)?;
    assert_eq!(
        ContentDigest::sha256(&pgm).to_text(),
        field(&decoded, "pgm_sha256")?
    );
    let header = b"P5\n176 144\n255\n";
    let frame_bytes = header.len() + 176 * 144;
    assert_eq!(pgm.len(), 8 * frame_bytes);
    let luma = values(&decoded, "frame_luma_sha256")?;
    for (index, image) in pgm.chunks(frame_bytes).enumerate() {
        assert!(image.starts_with(header));
        assert_eq!(
            ContentDigest::sha256(&image[header.len()..]).to_text(),
            luma[index]
        );
    }
    let again = decode(&root, &id, "0", "8").output()?;
    success(&again);
    assert_eq!(
        values(&again, "frame_receipt_digest")?,
        values(&decoded, "frame_receipt_digest")?
    );
    Ok(())
}

#[test]
fn cra_led_range_lists_its_skipped_rasl_segment_and_matches_the_cra_oracle() -> TestResult {
    let (_directory, root, id) = imported("cra", OPEN_GOP)?;
    let decoded = decode(&root, &id, "5", "7").output()?;
    success(&decoded);
    assert_eq!(
        values(&decoded, "frame_i420_sha256")?,
        oracle(OPEN_GOP_FROM_CRA)
    );
    assert_eq!(values(&decoded, "skipped_rasl_segment")?, ["6"]);
    assert_eq!(field(&decoded, "h265_frames_decoded")?, "6");
    assert_eq!(field(&decoded, "frame_nal_unit_type")?, "21");
    assert_eq!(field(&decoded, "frame_irap")?, "true");
    assert_eq!(field(&decoded, "frame_idr")?, "false");
    Ok(())
}

#[test]
fn non_irap_start_gray_ambiguous_and_conflicting_inputs_are_typed_refusals() -> TestResult {
    let (_directory, root, id) = imported("refusals", OPEN_GOP)?;
    let trailing = decode(&root, &id, "1", "2").output()?;
    assert!(!trailing.status.success());
    assert_eq!(refusal(&trailing), "ERR-DECODE-H265-RANGE-NOT-IRAP-001");
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

    // `28 01` is both an H.265 IDR_N_LP header and an H.264 PPS header: never guessed.
    let ambiguous = [0, 0, 0, 1, 0x28, 0x01, 0xaf, 0x0b, 0xe0, 0x14, 0x80];
    let guessed = import(&OwnedDirectory::new("ambiguous")?, &ambiguous, None)?;
    assert!(!guessed.status.success());
    assert_eq!(refusal(&guessed), "ERR-INGEST-FORMAT-AMBIGUOUS-001");
    assert!(String::from_utf8_lossy(&guessed.stderr).contains("hevc"));
    let declared = import(&OwnedDirectory::new("declared")?, &ambiguous, Some("hevc"))?;
    success(&declared);
    assert_eq!(field(&declared, "media_format")?, "hevc");

    // An H.265 recording declared as H.264 is a conflict, not a misparse.
    let conflict = import(&OwnedDirectory::new("conflict")?, STREAM, Some("annexb"))?;
    assert!(!conflict.status.success());
    assert_eq!(refusal(&conflict), "ERR-INGEST-FORMAT-CONFLICT-001");
    Ok(())
}
