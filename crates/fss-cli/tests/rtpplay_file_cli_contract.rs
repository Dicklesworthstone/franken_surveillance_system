#![forbid(unsafe_code)]
//! `fss-file import --media-format rtpplay` routes a recorded RTP session (rtpdump) through the
//! generic file adapter into the recorded-RTP import, end to end in the real binary, on the
//! committed FIXH264 rtpdump fixtures (fss-2h5zq.27). Directories are allocated under the cargo
//! target tmpdir and never removed.

use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::ContentDigest;

type TestResult = Result<(), Box<dyn Error>>;

/// Committed rtpdump fixtures (tests/fixtures/media/rtp), SSRC 0x11223344, payload type 96.
const SSRC: &str = "287454020";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/fixtures/media/rtp/{name}"))
}

fn directory(label: &str) -> io::Result<PathBuf> {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(base)?;
    for attempt in 0..1000_u32 {
        let path = base.join(format!(
            "rtpplay-cli-{label}-{}-{attempt}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("test directory capacity"))
}

fn import(root: &Path, source: &Path, extra: &[&str]) -> io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import")
        .arg("--root")
        .arg(root)
        .args(["--site", "site:rtpplay-cli-test"])
        .arg("--input")
        .arg(source)
        .args([
            "--sensor",
            "sensor:rtpplay-cli",
            "--stream",
            "stream:rtpplay-cli",
            "--receive-time-ns",
            "2000000000",
        ])
        .args(extra)
        .output()
}

const BINDING: [&str; 10] = [
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
        "stdout: {}\nstderr: {}",
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

fn unit_lines(output: &Output) -> Result<Vec<String>, Box<dyn Error>> {
    Ok(std::str::from_utf8(&output.stdout)?
        .lines()
        .filter(|l| l.starts_with("access_unit="))
        .map(str::to_owned)
        .collect())
}

/// The clean recording imports through the real binary: the whole file is retained and
/// re-verified, 15 records give 14 NALs in 5 access-unit capsules (only the file entry fenced),
/// and an identical rerun is idempotent (same root, no failure).
///
/// Planted negatives: (a) the pre-fix CLI refusal of `--media-format rtpplay` (parse error);
/// (b) the generic adapter's pre-fix `UnsupportedFormat` for a sniffed rtpplay file; (c)
/// per-NAL capsules (capsule_count 14).
#[test]
fn rtpplay_import_routes_through_the_cli_end_to_end() -> TestResult {
    let dir = directory("clean")?;
    let root = dir.join("deployment");
    let source = fixture("clean.rtp");
    let bytes = fs::read(&source)?;
    let report_path = dir.join("import.report");
    let mut args = BINDING.to_vec();
    let report_text = report_path.to_str().ok_or("utf-8 path")?;
    args.extend(["--manifest-out", report_text]);
    let imported = import(&root, &source, &args)?;
    success(&imported);
    assert_eq!(field(&imported, "media_format")?, "rtpplay");
    assert_eq!(
        field(&imported, "input_sha256")?,
        ContentDigest::sha256(&bytes).to_text()
    );
    assert_eq!(
        field(&imported, "verified_source_sha256")?,
        ContentDigest::sha256(&bytes).to_text()
    );
    assert_eq!(field(&imported, "input_bytes")?, bytes.len().to_string());
    assert_eq!(field(&imported, "record_count")?, "15");
    assert_eq!(field(&imported, "nal_count")?, "14");
    assert_eq!(field(&imported, "access_unit_count")?, "5");
    assert_eq!(field(&imported, "capsule_count")?, "5");
    assert_eq!(field(&imported, "gap_before_capsules")?, "1");
    assert_eq!(field(&imported, "stream_generations")?, "1");
    assert_eq!(field(&imported, "container_end")?, "ended");
    assert_eq!(field(&imported, "clock_basis")?, "estimated");
    assert_eq!(field(&imported, "capture_time_class")?, "unknown");
    assert_eq!(field(&imported, "decoded_frames")?, "0");
    assert_eq!(field(&imported, "absence_certifiable")?, "false");
    let units = unit_lines(&imported)?;
    assert_eq!(units.len(), 5);
    assert!(units.iter().all(|u| u.contains(" end=marker ")));
    assert!(units[0].contains(" nals=6 ") && units[0].contains(" gap_before=true "));
    let report = fs::read(&report_path)?;
    assert!(!report.is_empty());
    let root_digest = field(&imported, "import_root")?;
    assert!(
        field(&imported, "import_slot")?.starts_with("rtp-"),
        "content-derived rtp slot"
    );

    let again = import(&root, &source, &BINDING)?;
    success(&again);
    assert_eq!(field(&again, "import_root")?, root_digest);
    assert_eq!(
        field(&again, "authority_sequence")?,
        field(&imported, "authority_sequence")?
    );
    Ok(())
}

/// The loss variant's missing packet fences two capsules (file entry and the post-loss IDR
/// unit) and is counted, not hidden.
///
/// Planted negative: capsules that ignore the sequence gap (gap_before_capsules 1).
#[test]
fn rtpplay_loss_is_fenced_and_counted_through_the_cli() -> TestResult {
    let dir = directory("loss")?;
    let imported = import(&dir.join("deployment"), &fixture("loss.rtp"), &BINDING)?;
    success(&imported);
    assert_eq!(field(&imported, "access_unit_count")?, "6");
    assert_eq!(field(&imported, "gap_before_capsules")?, "2");
    assert_eq!(field(&imported, "sequence_missing")?, "1");
    let units = unit_lines(&imported)?;
    assert!(units[0].contains(" end=fence "));
    Ok(())
}

/// The stream binding is the owner's and is never guessed: `auto` on an rtpplay file is refused
/// before anything is published; partial or out-of-range bindings are parse errors; binding
/// options without rtpplay are refused; a recording under another SSRC retains the file but
/// yields no capsule.
///
/// Planted negatives: (a) adopting the capture's SSRC when none is given; (b) accepting a
/// binding fragment.
#[test]
fn rtpplay_binding_is_required_and_never_guessed() -> TestResult {
    let dir = directory("binding")?;
    let root = dir.join("deployment");
    let source = fixture("clean.rtp");

    let auto = import(&root, &source, &["--media-format", "auto"])?;
    assert!(!auto.status.success());
    let stderr = String::from_utf8_lossy(&auto.stderr);
    assert!(stderr.contains("refusal=rtp_binding_required"), "{stderr}");

    let partial = import(&root, &source, &BINDING[..6])?;
    assert!(!partial.status.success());
    assert!(String::from_utf8_lossy(&partial.stderr).contains("ERR-CLI-"));

    let mut bad_pt = BINDING;
    bad_pt[7] = "200";
    assert!(!import(&root, &source, &bad_pt)?.status.success());

    let stray = import(&root, &source, &["--rtp-generation", "1"])?;
    assert!(!stray.status.success());

    let mut other = BINDING;
    other[5] = "9";
    let refused = import(&dir.join("other"), &source, &other)?;
    success(&refused);
    assert_eq!(field(&refused, "record_count")?, "15");
    assert_eq!(field(&refused, "nal_count")?, "0");
    assert_eq!(field(&refused, "capsule_count")?, "0");
    assert_eq!(
        field(&refused, "verified_source_sha256")?,
        ContentDigest::sha256(&fs::read(&source)?).to_text()
    );
    Ok(())
}

/// `fss capabilities` reports rtpplay file custody as implemented only now that the CLI route
/// works end to end, and no longer as a refused partial.
///
/// Planted negative: the pre-fix partial entry `file_import_custody_rtpplay:...`.
#[test]
fn capabilities_report_rtpplay_file_import_as_implemented() -> TestResult {
    let output = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(["capabilities", "--json"])
        .output()?;
    success(&output);
    let text = String::from_utf8(output.stdout)?;
    let implemented = text
        .split("\"implemented\":[")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .ok_or("implemented list")?;
    assert!(implemented.contains("\"file_import_custody:annexb,hevc,mjpeg,rtpplay\""));
    assert!(!text.contains("file_import_custody_rtpplay"));
    Ok(())
}
