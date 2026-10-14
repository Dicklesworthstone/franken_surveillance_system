#![forbid(unsafe_code)]
//! Real retained-root motion command: cold reproduction, shared kernel, privacy and partials.
#[path = "../../fss-reference/tests/rtpdump_support/mod.rs"]
mod rtpdump_support;

use fss_cli::json_input::{Value, parse};
use fss_core::{ContentDigest, SensorId, StreamId, TimestampNs};
use fss_reference::ReferenceDeployment;
use fss_reference::ingest::pixel_change::PixelChangeConfig;
use fss_reference::ingest::pixel_change::rtp::{
    RtpMotionAnalyzer, RtpMotionRequest, RtpMotionStep,
};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::rtpdump::import::{
    RtpImportLimits, RtpImportScope, prepare_rtp_import, publish_rtp_import,
};
use fss_reference::ingest::rtpdump::recovery::decode::RetainedRtpDecodeRequest;
use fss_reference::ingest::rtpdump::recovery::{RtpRecoveryPolicy, inspect_rtp_import};
use rtpdump_support::*;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SITE: &str = "site:motion-cli";
fn directory(label: &str) -> Result<PathBuf, Error> {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(base)?;
    for i in 0..1000 {
        let p = base.join(format!("rtp-motion-cli-{label}-{}-{i}", std::process::id()));
        match std::fs::create_dir(&p) {
            Ok(()) => return Ok(p),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err("fixture directory bound".into())
}
fn setup(label: &str, bytes: &[u8]) -> Result<(PathBuf, PathBuf, ContentDigest), Error> {
    let dir = directory(label)?;
    let root = dir.join("deployment");
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&root, SITE, &cx)?;
    let plan = prepare_rtp_import(
        bytes,
        RtpImportScope {
            sensor: SensorId::parse("sensor:motion-cli")?,
            stream: StreamId::parse("stream:motion-cli")?,
            receive_time: TimestampNs(1_000_000_000),
        },
        config_for(7),
        RtpImportLimits::default(),
        &cx,
    )?;
    let source = publish_rtp_import(plan, &cx, &mut dep)?.root();
    Ok((dir, root, source))
}
fn command(root: &Path, source: ContentDigest, report: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_fss-decode-rtp"));
    c.args(["motion", "--root"])
        .arg(root)
        .args(["--site", SITE, "--source-root"])
        .arg(source.to_string())
        .args([
            "--custody",
            "current",
            "--pixel-delta",
            "20",
            "--minimum-changed-pixels",
            "2",
            "--minimum-changed-ppm",
            "500",
            "--report-out",
        ])
        .arg(report);
    c
}
fn success(output: Output) -> Result<String, Error> {
    if !output.status.success() {
        return Err(format!(
            "child failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}
fn field<'a>(s: &'a str, key: &str) -> Result<&'a str, Error> {
    s.lines()
        .find_map(|l| l.strip_prefix(key))
        .ok_or_else(|| format!("missing {key}").into())
}
fn rows(path: &Path) -> Result<Vec<Value>, Error> {
    std::fs::read_to_string(path)?
        .lines()
        .map(|s| parse(s).map_err(Error::from))
        .collect()
}
fn value<'a>(v: &'a Value, key: &str) -> Result<&'a Value, Error> {
    v.object()
        .and_then(|o| o.get(key))
        .ok_or_else(|| format!("missing JSON field {key}").into())
}
fn observations(v: &[Value]) -> Vec<&Value> {
    v.iter()
        .filter(|v| {
            v.object().and_then(|o| o.get("type")).and_then(Value::text) == Some("observation")
        })
        .collect()
}
fn incomplete(output: Output) -> Result<String, Error> {
    assert!(!output.status.success());
    let s = String::from_utf8(output.stdout)?;
    assert!(s.contains("motion_complete=false") && !s.contains("motion_complete=true"));
    assert!(!s.contains("motion_report_sha256="));
    Ok(s)
}

#[test]
fn cold_command_reproduces_library_observations_private_report_and_unchanged_authority()
-> TestResult {
    let (dir, root, source) = setup("cold", &real_dump(true))?;
    let path = dir.join("motion.jsonl");
    let cx = cx()?;
    let dep = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    let anchor = dep.current_anchor().clone();
    let retained = inspect_rtp_import(source, 999, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let mut decode = RetainedRtpDecodeRequest::new(
        retained
            .h264_parameters(&cx)?
            .unique_pair()
            .ok_or("parameters")?,
    );
    // Match explicit native defaults of the CLI; their resource policy is receipt-bound.
    decode.decode.codec.max_width = 2048;
    decode.decode.codec.max_height = 2048;
    decode.decode.codec.max_macroblocks = 4_194_304 / 256;
    decode.decode.codec.max_pictures = 1024;
    let r = RtpMotionRequest::new(
        decode,
        PixelChangeConfig {
            minimum_delta: 20,
            minimum_changed_pixels: 2,
            minimum_changed_fraction_ppm: 500,
        },
        64_000_000,
    );
    let mut a = RtpMotionAnalyzer::open(&retained, r, &dep, &cx)?;
    let mut expected = Vec::new();
    for _ in 0..20_000 {
        match a.step(&dep, &cx)? {
            RtpMotionStep::Observation(o) => expected.push(o),
            RtpMotionStep::Ended(_) => break,
            _ => {}
        }
    }
    assert!(a.stats().complete());
    drop(a);
    drop(retained);
    drop(dep);
    let stdout = success(command(&root, source, &path).output()?)?;
    assert_eq!(field(&stdout, "motion_observations=")?, "4");
    assert_eq!(field(&stdout, "motion_measured_pairs=")?, "3");
    assert_eq!(
        field(&stdout, "motion_report_sha256=")?,
        ContentDigest::sha256(&std::fs::read(&path)?).to_string()
    );
    let v = rows(&path)?;
    let actual = observations(&v);
    assert_eq!(actual.len(), expected.len());
    for (actual, expected) in actual.iter().zip(expected) {
        assert_eq!(
            value(actual, "observation_sha256")?.text(),
            Some(expected.digest().to_string().as_str())
        );
        assert_eq!(
            value(actual, "frame_receipt")?.text(),
            Some(expected.frame_receipt.to_string().as_str())
        );
        assert_eq!(
            value(actual, "output_index")?.integer(),
            Some(i128::from(expected.output_index))
        );
        match expected.statistics {
            None => assert_eq!(value(actual, "comparison")?, &Value::Null),
            Some(s) => {
                let c = value(actual, "comparison")?;
                assert_eq!(
                    value(c, "changed_pixels")?.integer(),
                    Some(i128::from(s.changed_pixels))
                );
                assert_eq!(value(c, "candidate")?.boolean(), Some(s.candidate));
            }
        }
    }
    assert_eq!(
        value(v.last().ok_or("summary")?, "complete")?.boolean(),
        Some(true)
    );
    let again = dir.join("again.jsonl");
    success(command(&root, source, &again).output()?)?;
    assert_eq!(std::fs::read(&path)?, std::fs::read(&again)?);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600
        );
    }
    let dep = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    assert_eq!(dep.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn fully_masked_source_measures_zero_changes_without_claiming_absence() -> TestResult {
    let (dir, root, source) = setup("mask", &real_dump(false))?;
    let before = dir.join("before.jsonl");
    success(command(&root, source, &before).output()?)?;
    let v = rows(&before)?;
    let first = observations(&v)[0];
    let d = value(first, "dimensions")?.array().ok_or("dimensions")?;
    let (w, h) = (
        d[0].integer().ok_or("width")? as u32,
        d[1].integer().ok_or("height")? as u32,
    );
    let cx = cx()?;
    let mut dep = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    let p = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:motion-cli")?,
        [w, h],
        &[[0, 0, w, h]],
    )?;
    let approval = preview_mask(&dep, &p)?.approval;
    declare_mask(&mut dep, &p, approval, &cx)?;
    drop(dep);
    let after = dir.join("after.jsonl");
    let out = success(command(&root, source, &after).output()?)?;
    assert_eq!(field(&out, "motion_candidate_pairs=")?, "0");
    assert_eq!(field(&out, "absence_certifiable=")?, "false");
    let v = rows(&after)?;
    for o in &observations(&v)[1..] {
        let c = value(o, "comparison")?;
        assert_eq!(value(c, "changed_pixels")?.integer(), Some(0));
        assert_eq!(value(c, "absolute_difference_sum")?.integer(), Some(0));
    }
    assert_ne!(std::fs::read(before)?, std::fs::read(after)?);
    Ok(())
}

#[test]
fn lost_packets_produce_gap_resets_and_incomplete_reports_even_after_native_recovery() -> TestResult
{
    let mut p = packetize(3, 10000, 100, 7, 0, 0);
    let at = p
        .iter()
        .enumerate()
        .filter(|(_, p)| p.vcl)
        .nth(5)
        .ok_or("VCL")?
        .0;
    p.remove(at);
    let (dir, root, source) = setup("gap", &dump_planned(&p))?;
    let path = dir.join("gap.jsonl");
    incomplete(command(&root, source, &path).output()?)?;
    let v = rows(&path)?;
    let obs = observations(&v);
    let recovered = obs
        .iter()
        .find(|o| {
            value(o, "decoder_epoch")
                .ok()
                .and_then(Value::integer)
                .is_some_and(|e| e > 0)
        })
        .ok_or("recovered baseline")?;
    assert_eq!(value(recovered, "comparison")?, &Value::Null);
    assert_eq!(value(recovered, "predecessor_receipt")?, &Value::Null);
    assert!(
        value(recovered, "reset_reasons")?
            .array()
            .ok_or("resets")?
            .contains(&Value::Text("source_gap".into()))
    );
    assert_eq!(
        value(v.last().ok_or("summary")?, "complete")?.boolean(),
        Some(false)
    );
    Ok(())
}

#[test]
fn comparison_and_report_limits_are_not_successful_shorter_scans() -> TestResult {
    let (dir, root, source) = setup("limits", &real_dump(false))?;
    for (name, args) in [
        ("compare", vec!["--max-comparisons", "0"]),
        ("header", vec!["--max-report-bytes", "1"]),
        ("report", vec!["--max-report-bytes", "2200"]),
        ("steps", vec!["--max-steps", "1"]),
        ("decode", vec!["--max-output-bytes", "1"]),
    ] {
        let path = dir.join(format!("{name}.jsonl"));
        let text = incomplete(command(&root, source, &path).args(args).output()?)?;
        if name == "header" {
            assert!(!path.exists());
        }
        if name == "compare" {
            assert_eq!(field(&text, "motion_observations=")?, "1");
            assert_eq!(field(&text, "motion_pixel_comparisons=")?, "0");
        }
        if path.exists() {
            assert!(rows(&path)?.iter().all(|v| v.object().and_then(|v| v.get("complete")) != Some(&Value::Bool(true))));
        }
    }
    Ok(())
}

#[test]
fn report_paths_cannot_overwrite_enter_deployment_or_create_parents() -> TestResult {
    let (dir, root, source) = setup("paths", &real_dump(false))?;
    let path = dir.join("existing.jsonl");
    std::fs::write(&path, b"keep")?;
    incomplete(command(&root, source, &path).output()?)?;
    assert_eq!(std::fs::read(&path)?, b"keep");
    let inside = root.join("forbidden.jsonl");
    incomplete(command(&root, source, &inside).output()?)?;
    assert!(!inside.exists());
    let missing = dir.join("absent").join("report.jsonl");
    incomplete(command(&root, source, &missing).output()?)?;
    assert!(!dir.join("absent").exists());
    #[cfg(unix)]
    {
        let link = dir.join("symlink.jsonl");
        std::os::unix::fs::symlink(&path, &link)?;
        incomplete(command(&root, source, &link).output()?)?;
        assert_eq!(std::fs::read(&path)?, b"keep");
    }
    Ok(())
}

#[test]
fn malformed_requests_create_no_deployment_or_report() -> TestResult {
    let dir = directory("args")?;
    let root = dir.join("absent");
    let path = dir.join("report.jsonl");
    let source = ContentDigest::sha256(b"unknown");
    for extra in [
        vec!["--pixel-delta", "1"],
        vec!["--output", "no.pgm"],
        vec!["--max-report-bytes", "67108865"],
        vec!["--report-out"],
        vec!["--bad", "x"],
    ] {
        let result = command(&root, source, &path).args(extra).output()?;
        assert_eq!(result.status.code(), Some(2));
        assert!(!root.exists() && !path.exists());
    }
    incomplete(command(&root, source, &path).output()?)?;
    assert!(!root.exists() && !path.exists());
    Ok(())
}

#[test]
fn malformed_recording_tail_retains_partial_analysis_not_quietness() -> TestResult {
    let mut bytes = real_dump(false);
    bytes.extend_from_slice(&[0, 10, 0]);
    let (dir, root, source) = setup("tail", &bytes)?;
    let path = dir.join("tail.jsonl");
    let stdout = incomplete(command(&root, source, &path).output()?)?;
    assert!(field(&stdout, "refused_steps=")?.parse::<usize>()? > 0);
    assert_eq!(
        value(rows(&path)?.last().ok_or("summary")?, "native_complete")?.boolean(),
        Some(false)
    );
    Ok(())
}
