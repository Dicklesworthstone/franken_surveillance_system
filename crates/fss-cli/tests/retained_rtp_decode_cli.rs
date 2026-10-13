#![forbid(unsafe_code)]
//! Real process import -> cold native decode -> current-mask PGM export.
#[path = "../../fss-reference/tests/rtpdump_support/mod.rs"]
mod rtpdump_support;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use fss_core::{ContentDigest, SensorId};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ReferenceDeployment;
use rtpdump_support::{Error, TestResult, cx, real_dump};

fn directory(label: &str) -> Result<PathBuf, Error> {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(base)?;
    for attempt in 0..1000 {
        let path = base.join(format!("rtp-decode-cli-{label}-{}-{attempt}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err("temporary directory bound".into())
}
fn text(output: &Output) -> String { String::from_utf8_lossy(&output.stdout).into_owned() }
fn success(output: Output) -> Result<String, Error> {
    if !output.status.success() {
        return Err(format!("child refused: {}\n{}", text(&output), String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(text(&output))
}
fn field<'a>(text: &'a str, key: &str) -> Result<&'a str, Error> {
    text.lines().find_map(|line| line.strip_prefix(key).and_then(|s| s.strip_prefix('=')))
        .ok_or_else(|| format!("missing report field {key}").into())
}
fn import(base: &Path, damaged: bool) -> Result<(PathBuf, String), Error> {
    let source = base.join("original.rtpdump");
    let mut bytes = real_dump(true);
    if damaged { bytes.extend_from_slice(&[0, 10, 0]); }
    std::fs::write(&source, bytes)?;
    let root = base.join("deployment");
    let report = success(Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import").arg("--root").arg(&root).arg("--site").arg("site:rtp-cli")
        .arg("--input").arg(&source)
        .args(["--sensor", "sensor:rtp-cli", "--stream", "stream:rtp-cli",
            "--receive-time-ns", "1000000000", "--media-format", "rtpplay",
            "--rtp-generation", "1", "--rtp-ssrc", "7", "--rtp-payload-type", "96",
            "--rtp-mode", "non-interleaved"])
        .output()?)?;
    let imported = field(&report, "import_root")?.to_owned();
    std::fs::remove_file(source)?;
    Ok((root, imported))
}
fn command(mode: &str, root: &Path, imported: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-decode-rtp"));
    command.arg(mode).arg("--root").arg(root)
        .args(["--site", "site:rtp-cli", "--source-root", imported]);
    command
}
fn read_pgm(bytes: &[u8]) -> Result<Vec<([u32; 2], Vec<u8>)>, Error> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if bytes.get(at..at + 3) != Some(b"P5\n") { return Err("PGM magic".into()); }
        at += 3;
        let end = bytes[at..].iter().position(|b| *b == b'\n').ok_or("PGM dimensions")? + at;
        let dimensions: Vec<u32> = std::str::from_utf8(&bytes[at..end])?
            .split_whitespace().map(str::parse).collect::<Result<_, _>>()?;
        let [width, height] = dimensions.as_slice() else { return Err("PGM dimensions count".into()); };
        at = end + 1;
        if bytes.get(at..at + 4) != Some(b"255\n") { return Err("PGM depth".into()); }
        at += 4;
        let end = at + *width as usize * *height as usize;
        let pixels = bytes.get(at..end).ok_or("truncated PGM")?.to_vec();
        out.push(([*width, *height], pixels));
        at = end;
    }
    Ok(out)
}

#[test]
fn original_file_removed_cold_native_export_matches_report_and_exact_parameter_retry() -> TestResult {
    let base = directory("cold")?;
    let (root, imported) = import(&base, false)?;
    let inspection = success(command("inspect", &root, &imported).output()?)?;
    assert_eq!(field(&inspection, "import_complete")?, "true");
    let sps = field(&inspection, "sps_candidate")?;
    let pps = field(&inspection, "pps_candidate")?;
    let output = base.join("frames.pgm");
    let report = success(command("decode", &root, &imported).arg("--output").arg(&output).output()?)?;
    assert_eq!(field(&report, "decode_complete")?, "true");
    assert_eq!(field(&report, "frames_decoded")?, "4");
    assert_eq!(field(&report, "export_complete")?, "true");
    assert_eq!(field(&report, "absence_certifiable")?, "false");
    let bytes = std::fs::read(&output)?;
    assert_eq!(field(&report, "export_sha256")?, ContentDigest::sha256(&bytes).to_string());
    let frames = read_pgm(&bytes)?;
    assert_eq!(frames.len(), 4);
    let reported: Vec<_> = report.lines().filter_map(|line| line.strip_prefix("frame_luma_sha256=")).collect();
    assert_eq!(reported.len(), frames.len());
    for ((_, pixels), digest) in frames.iter().zip(reported) {
        assert_eq!(ContentDigest::sha256(pixels).to_string(), digest);
    }
    let retry = base.join("retry.pgm");
    success(command("decode", &root, &imported).args(["--sps", sps, "--pps", pps])
        .arg("--output").arg(&retry).output()?)?;
    assert_eq!(std::fs::read(retry)?, bytes);
    let refused = command("decode", &root, &imported).arg("--output").arg(&output).output()?;
    assert!(!refused.status.success());
    assert_eq!(std::fs::read(output)?, bytes);
    Ok(())
}

#[test]
fn current_privacy_policy_masks_all_exported_luma_after_a_real_restart() -> TestResult {
    let base = directory("mask")?;
    let (root, imported) = import(&base, false)?;
    let unmasked = base.join("before.pgm");
    success(command("decode", &root, &imported).arg("--output").arg(&unmasked).output()?)?;
    let original = read_pgm(&std::fs::read(&unmasked)?)?;
    let [width, height] = original[0].0;
    assert!(original.iter().any(|(_, p)| p.iter().any(|v| *v != 16)));
    let cx = cx()?;
    let mut dep = ReferenceDeployment::reopen(&root, "site:rtp-cli", &cx)?;
    let policy = PrivacyMaskPolicy::new(SensorId::parse("sensor:rtp-cli")?, [width, height], &[[0, 0, width, height]])?;
    let approval = preview_mask(&dep, &policy)?.approval;
    declare_mask(&mut dep, &policy, approval, &cx)?;
    drop(dep);
    let masked = base.join("after.pgm");
    let report = success(command("decode", &root, &imported).arg("--output").arg(&masked).output()?)?;
    assert_eq!(field(&report, "privacy_mask_policy")?, policy.digest().to_string());
    let frames = read_pgm(&std::fs::read(masked)?)?;
    assert_eq!(frames.len(), 4);
    assert!(frames.iter().all(|(_, p)| p.iter().all(|v| *v == 16)));
    assert_eq!(field(&report, "decode_complete")?, "true");
    Ok(())
}

#[test]
fn partial_recordings_and_work_limits_never_publish_a_successful_export_receipt() -> TestResult {
    for damaged in [false, true] {
        let base = directory(if damaged { "tail" } else { "budget" })?;
        let (root, imported) = import(&base, damaged)?;
        let output = base.join("output.pgm");
        let mut child = command("decode", &root, &imported);
        child.arg("--output").arg(&output);
        if !damaged { child.args(["--max-output-bytes", "1"]); }
        let result = child.output()?;
        assert!(!result.status.success());
        let report = text(&result);
        assert_eq!(field(&report, "decode_complete")?, "false");
        assert_eq!(field(&report, "export_complete")?, "false");
        assert!(!report.contains("export_sha256="));
        if !damaged { assert!(!output.exists()); }
        let stopped = command("decode", &root, &imported).args(["--max-steps", "1"]).output()?;
        assert!(!stopped.status.success());
        assert_eq!(field(&text(&stopped), "decode_complete")?, "false");
    }
    Ok(())
}

#[test]
fn bad_admission_creates_no_destination_or_missing_deployment() -> TestResult {
    let base = directory("refuse")?;
    let missing = base.join("missing");
    let digest = ContentDigest::sha256(b"missing").to_string();
    assert!(!command("inspect", &missing, &digest).output()?.status.success());
    assert!(!missing.exists());
    let (root, imported) = import(&base, false)?;
    for tail in [vec!["--sps", &digest], vec!["--max-frames", "0"], vec!["--max-frames", "2048"],
        vec!["--max-pixels", "1"], vec!["--unknown", "x"], vec!["--max-steps", "1", "--max-steps", "2"]] {
        let result = command("decode", &root, &imported).args(tail).output()?;
        assert!(!result.status.success());
        assert!(!text(&result).contains("frames_decoded="));
    }
    let forbidden = root.join("forbidden.pgm");
    assert!(!command("decode", &root, &imported).arg("--output").arg(&forbidden).output()?.status.success());
    assert!(!forbidden.exists());
    assert!(!command("inspect", &root, &imported).args(["--sps", &digest, "--pps", &digest]).output()?.status.success());
    let output = base.join("wrong-parameters.pgm");
    let result = command("decode", &root, &imported).args(["--sps", &digest, "--pps", &digest])
        .arg("--output").arg(&output).output()?;
    assert!(!result.status.success());
    assert!(!output.exists());
    Ok(())
}
