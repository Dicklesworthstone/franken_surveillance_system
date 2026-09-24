#![forbid(unsafe_code)]
//! Detector cascade and package-report consumption through the real binaries (fss-704tz).
//!
//! `fss-file import` retains a synthetic person-silhouette recording (the YOLOX conformance
//! generator). `fss-event watch --detector-package ...` runs the verified YOLOX-Nano package only
//! on the frame the cheap gate selected and attaches uncalibrated person evidence while the
//! candidate stays unclassified and single-sensor. `fss-infer package-detect --retain yes` feeds
//! `fss-event report --package-report`, `prepare` and `publish`. Each heavy test runs exactly one
//! inference; the refusal test runs none. Wiring, not detection quality.

#[path = "../../fss-reference/tests/yolox_support/person.rs"]
mod person;

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::ContentDigest;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:cascade-cli";
const PACKAGE_SHA256: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";
const FRAMES: usize = 12;

struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-cascade-cli-{name}-{}-{attempt}",
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
    fn root(&self) -> PathBuf {
        self.0.join("deployment")
    }
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn package_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models/yolox-nano/yolox_nano.fmpk")
}

fn jpeg(foot: Option<i64>) -> TestResult<Vec<u8>> {
    let [width, height] = person::PERSON_SCENE_DIMENSIONS;
    Ok(encode_jpeg(
        width,
        height,
        &person::person_scene(foot),
        &JpegConfig {
            quality: 90,
            subsampling: Subsampling::Yuv420,
            restart_interval: 0,
            custom_markers: Vec::new(),
        },
    )?)
}

/// Two empty frames, then the silhouette walks right 24 px per frame from foot x = 60.
fn walking() -> TestResult<Vec<u8>> {
    let mut stream = Vec::new();
    for index in 0..FRAMES {
        stream.extend(jpeg((index >= 2).then(|| 60 + 24 * (index as i64 - 2)))?);
    }
    Ok(stream)
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn refusal(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .find_map(|line| line.strip_prefix("refusal_id=").map(str::to_owned))
        .unwrap_or_default()
}

fn line(text: &[u8], key: &str) -> TestResult<String> {
    let prefix = format!("{key}=");
    Ok(String::from_utf8(text.to_vec())?
        .lines()
        .find_map(|l| l.strip_prefix(&prefix).map(str::to_owned))
        .ok_or_else(|| format!("{key} missing"))?)
}

fn import(directory: &OwnedDirectory, bytes: &[u8], format: &str) -> TestResult<String> {
    let input = directory.0.join("recording.bin");
    fs::write(&input, bytes)?;
    let output = Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import")
        .arg("--root")
        .arg(directory.root())
        .args(["--site", SITE, "--input"])
        .arg(&input)
        .args([
            "--sensor",
            "sensor:cascade-cli",
            "--stream",
            "stream:cascade-cli",
            "--receive-time-ns",
            "1000000000",
            "--media-format",
            format,
        ])
        .output()?;
    success(&output);
    fs::remove_file(input)?;
    line(&output.stdout, "import_identity")
}

fn event(root: &Path, command: &str, args: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .arg(command)
        .arg("--root")
        .arg(root)
        .args(["--site", SITE])
        .args(args)
        .output()?)
}

fn watch(root: &Path, id: &str, extra: &[&str]) -> TestResult<Output> {
    let mut args = vec![
        "--import-id",
        id,
        "--interpretation",
        "ycbcr",
        "--zone",
        "door:200,0,160,640",
        "--min-region-pixels",
        "1500",
        "--work-units",
        "2000000000",
    ];
    args.extend_from_slice(extra);
    event(root, "watch", &args)
}

/// Value of the first `"key":` in a JSON report: a bare token or the quoted string body.
fn json_field(output: &Output, key: &str) -> TestResult<String> {
    let text = String::from_utf8(output.stdout.clone())?;
    let pattern = format!("\"{key}\":");
    let start = text
        .find(&pattern)
        .ok_or_else(|| format!("missing {key} in {text}"))?
        + pattern.len();
    let rest = &text[start..];
    Ok(match rest.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next().unwrap_or_default().to_owned(),
        None if rest.starts_with('[') => rest[..=rest.find(']').unwrap_or(0)].to_owned(),
        None => rest
            .split([',', '}', ']'])
            .next()
            .unwrap_or_default()
            .to_owned(),
    })
}

#[test]
fn watch_cascade_runs_the_package_once_and_attaches_uncalibrated_person_evidence() -> TestResult {
    let directory = OwnedDirectory::new("watch")?;
    let root = directory.root();
    let id = import(&directory, &walking()?, "mjpeg")?;
    let package = package_path();
    let package = package.to_str().ok_or("package path is not UTF-8")?;
    let plain = watch(&root, &id, &[])?;
    success(&plain);
    assert_eq!(json_field(&plain, "candidate_count")?, "1");
    let plain_text = String::from_utf8(plain.stdout.clone())?;
    assert!(!plain_text.contains("detector_cascade"));
    assert!(!plain_text.contains("class_evidence"));

    let cascaded = watch(
        &root,
        &id,
        &[
            "--detector-package",
            package,
            "--detector-digest",
            PACKAGE_SHA256,
            "--detector-max-inferences",
            "2",
            "--detector-min-iou-ppm",
            "200000",
        ],
    )?;
    success(&cascaded);
    assert_eq!(json_field(&cascaded, "candidate_count")?, "1");
    let entry = json_field(&cascaded, "entry_segment")?;
    // One selected frame (the zone entry), one inference, eleven frames skipped by the cascade.
    assert_eq!(
        json_field(&cascaded, "selected_segments")?,
        format!("[{entry}]")
    );
    assert_eq!(
        json_field(&cascaded, "inferred_segments")?,
        format!("[{entry}]")
    );
    assert_eq!(json_field(&cascaded, "inference_count")?, "1");
    assert_eq!(json_field(&cascaded, "budget_skipped_segments")?, "[]");
    assert_eq!(json_field(&cascaded, "budget_exhausted")?, "false");
    let skipped = json_field(&cascaded, "cascade_skipped_segments")?;
    assert_eq!(skipped.split(',').count(), FRAMES - 1, "{skipped}");
    assert_eq!(json_field(&cascaded, "outcome")?, "associated");
    assert_eq!(json_field(&cascaded, "selection")?, "zone_entry");
    assert_eq!(json_field(&cascaded, "score_calibrated")?, "false");
    assert_eq!(json_field(&cascaded, "package_digest")?, PACKAGE_SHA256);
    assert_eq!(json_field(&cascaded, "scores")?, "uncalibrated");
    let text = String::from_utf8(cascaded.stdout.clone())?;
    assert!(text.contains("\"label\":\"person\""), "{text}");
    // The candidate stays unclassified, indeterminate and single-sensor.
    assert_eq!(json_field(&cascaded, "event_kind")?, "unclassified");
    assert_eq!(json_field(&cascaded, "event_state")?, "indeterminate");
    assert_eq!(json_field(&cascaded, "corroborated")?, "false");
    assert_eq!(json_field(&cascaded, "alert_authorized")?, "false");
    assert_ne!(
        json_field(&cascaded, "candidate_id")?,
        json_field(&plain, "candidate_id")?
    );
    Ok(())
}

#[test]
fn wrong_package_digest_and_incomplete_cascade_options_are_refused_before_analysis() -> TestResult {
    let directory = OwnedDirectory::new("refusal")?;
    let root = directory.root();
    let id = import(&directory, &jpeg(Some(180))?, "mjpeg")?;
    let package = package_path();
    let package = package.to_str().ok_or("package path is not UTF-8")?;
    let wrong = ContentDigest::sha256(b"not the package").to_text();
    let refused = watch(
        &root,
        &id,
        &[
            "--detector-package",
            package,
            "--detector-digest",
            &wrong,
            "--detector-max-inferences",
            "1",
        ],
    )?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert_eq!(refusal(&refused), "ERR-MODEL-PACKAGE-DIGEST-001");
    // An explicit inference budget is mandatory, and bounded.
    for extra in [
        &[
            "--detector-package",
            package,
            "--detector-digest",
            PACKAGE_SHA256,
        ][..],
        &[
            "--detector-package",
            package,
            "--detector-digest",
            PACKAGE_SHA256,
            "--detector-max-inferences",
            "65",
        ][..],
        &["--detector-max-inferences", "1"][..],
    ] {
        let malformed = watch(&root, &id, extra)?;
        assert!(!malformed.status.success(), "{extra:?}");
        assert!(malformed.stdout.is_empty());
        assert!(String::from_utf8(malformed.stderr)?.starts_with("ERR-CLI-MALFORMED-VALUE"));
    }
    // The same options on corroborate are parsed by the same owner.
    let camera = format!("a:{id}");
    let other = format!("b:{wrong}");
    let malformed = event(
        &root,
        "corroborate",
        &[
            "--camera",
            &camera,
            "--camera",
            &other,
            "--ground",
            "a:1,0,0,0,1,0,0,0,1",
            "--ground",
            "b:1,0,0,0,1,0,0,0,1",
            "--zone",
            "door:0,0,10,10",
            "--interpretation",
            "ycbcr",
            "--time-gate-ns",
            "1000",
            "--distance-gate",
            "1",
            "--detector-digest",
            PACKAGE_SHA256,
        ],
    )?;
    assert!(!malformed.status.success());
    assert!(String::from_utf8(malformed.stderr)?.contains("--detector-package"));
    // A report digest the deployment never retained is a typed refusal.
    let unknown = event(
        &root,
        "report",
        &[
            "--package-report",
            &wrong,
            "--label",
            "person",
            "--report-out",
            directory
                .0
                .join("never.bin")
                .to_str()
                .ok_or("path is not UTF-8")?,
        ],
    )?;
    assert!(!unknown.status.success());
    assert_eq!(refusal(&unknown), "ERR-PACKAGE-EVENT-UNAVAILABLE-001");
    Ok(())
}

#[test]
fn retained_package_detection_flows_through_report_prepare_and_publish() -> TestResult {
    let directory = OwnedDirectory::new("report")?;
    let root = directory.root();
    let id = import(&directory, &jpeg(Some(180))?, "mjpeg")?;
    let detect = Command::new(env!("CARGO_BIN_EXE_fss-infer"))
        .arg("package-detect")
        .arg("--root")
        .arg(&root)
        .args([
            "--site",
            SITE,
            "--import-id",
            &id,
            "--first-segment",
            "0",
            "--frames",
            "1",
            "--interpretation",
            "ycbcr",
            "--package-digest",
            PACKAGE_SHA256,
            "--retain",
            "yes",
        ])
        .arg("--package")
        .arg(package_path())
        .output()?;
    success(&detect);
    let report_digest = ContentDigest::sha256(&detect.stdout).to_text();
    assert_eq!(
        line(&detect.stderr, "package_detection_retained")?,
        report_digest
    );
    assert_eq!(line(&detect.stderr, "status")?, "retained");
    let json = String::from_utf8(detect.stdout.clone())?;
    assert!(json.contains("\"label\":\"person\""), "{json}");

    let analysis_path = directory.0.join("package-analysis.bin");
    let analysis_arg = analysis_path.to_str().ok_or("path is not UTF-8")?;
    let report = event(
        &root,
        "report",
        &[
            "--package-report",
            &report_digest,
            "--label",
            "person",
            "--confirmation-hits",
            "1",
            "--report-out",
            analysis_arg,
        ],
    )?;
    success(&report);
    assert_eq!(
        line(&report.stdout, "operation")?,
        "package_report_verified"
    );
    assert_eq!(line(&report.stdout, "package_report")?, report_digest);
    assert_eq!(line(&report.stdout, "track_count")?, "1");
    assert_eq!(line(&report.stdout, "scores")?, "uncalibrated");
    let analysis_digest = line(&report.stdout, "report_digest")?;
    assert_eq!(
        ContentDigest::sha256(&fs::read(&analysis_path)?).to_text(),
        analysis_digest
    );
    let track = line(&report.stdout, "track")?;
    let selection = [
        "--report",
        analysis_arg,
        "--report-digest",
        &analysis_digest,
        "--track",
        &track,
    ];
    let prepared = event(&root, "prepare", &selection)?;
    success(&prepared);
    assert_eq!(line(&prepared.stdout, "operation")?, "prepared");
    assert_eq!(line(&prepared.stdout, "event_kind")?, "unclassified");
    assert_eq!(line(&prepared.stdout, "event_state")?, "indeterminate");
    assert_eq!(line(&prepared.stdout, "supporting_detector_evidence")?, "1");
    assert_eq!(line(&prepared.stdout, "failure_domains")?, "1");
    assert_eq!(line(&prepared.stdout, "corroborated")?, "false");
    let proposal = line(&prepared.stdout, "proposal_digest")?;

    let stale = ContentDigest::sha256(b"not the proposal").to_text();
    let mut refused_args = selection.to_vec();
    refused_args.extend(["--proposal-digest", &stale]);
    let refused = event(&root, "publish", &refused_args)?;
    assert!(!refused.status.success());
    assert_eq!(refusal(&refused), "ERR-PACKAGE-EVENT-APPROVAL-STALE-001");

    let mut publish_args = selection.to_vec();
    publish_args.extend(["--proposal-digest", &proposal]);
    let published = event(&root, "publish", &publish_args)?;
    success(&published);
    assert_eq!(line(&published.stdout, "operation")?, "published");
    assert_eq!(line(&published.stdout, "event_kind")?, "unclassified");
    let event_id = line(&published.stdout, "event_id")?;
    let sequence: u64 = line(&published.stdout, "authority_sequence")?.parse()?;
    // An exact rerun recognises the event and never republishes it.
    let again = event(&root, "publish", &publish_args)?;
    success(&again);
    assert_eq!(line(&again.stdout, "operation")?, "already_published");
    assert_eq!(line(&again.stdout, "event_id")?, event_id);
    assert_eq!(
        line(&again.stdout, "authority_sequence")?.parse::<u64>()?,
        sequence
    );
    Ok(())
}
