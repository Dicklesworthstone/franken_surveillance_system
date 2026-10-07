#![forbid(unsafe_code)]
//! Actual watch CLI: opt-in health diagnostics, refusal and source-closed cold publication.

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::{CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:watch-health-cli";
const FRAMES: usize = 300;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-watch-health-cli-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy)]
enum Scene {
    Changing,
    Frozen,
    Dark,
    Bright,
    Contrast,
    DecodeGap,
}
struct Fixture {
    root: PathBuf,
    identity: ContentDigest,
    directory: Directory,
}
impl Fixture {
    fn new(label: &str, scene: Scene) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment with spaces");
        let input = directory.0.join("source.mjpeg");
        let config = JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        };
        let mut bytes = Vec::new();
        for index in 0..FRAMES {
            let background = if matches!(scene, Scene::Frozen) {
                40
            } else {
                40 + (index % 2) as u8 * 8
            };
            let mut pixels = vec![background; 48 * 32];
            if index >= 3 {
                for y in 8..24 {
                    for x in 8..24 {
                        pixels[y * 48 + x] = 220;
                    }
                }
            }
            if index >= 15 {
                match scene {
                    Scene::Dark => pixels.fill(0),
                    Scene::Bright => pixels.fill(255),
                    Scene::Contrast => pixels.fill(100),
                    _ => {}
                }
            }
            let mut frame = encode_jpeg(48, 32, &pixels, &config)?;
            if matches!(scene, Scene::DecodeGap) && index == 150 {
                let sof = frame
                    .windows(2)
                    .position(|w| w == [0xff, 0xc0])
                    .ok_or("SOF0 missing")?;
                frame[sof + 1] = 0xc2;
            }
            bytes.extend(frame);
        }
        fs::write(&input, bytes)?;
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:watch-health-cli".into(),
            operation_id: OperationId::parse("operation:watch-health-cli")?,
            principal: "principal:fixture".into(),
            capabilities: vec!["ADP-REPLAY-001".into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(128 * 1024 * 1024)
                .storage_operations(65_536)
                .build()?,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut limits = FileIngestLimits::standard();
        limits.max_segments = FRAMES + 1;
        limits.chunk_bytes = 4096;
        let identity = FileIngestAdapter::ingest(
            FileIngestRequest::new(
                &input,
                SensorId::parse("sensor:watch-health")?,
                StreamId::parse("stream:watch-health")?,
            )
            .with_limits(limits)
            .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?)
            .with_receive_time(TimestampNs(1_000_000_000_000)),
            &cx,
            &mut deployment,
        )?
        .import_identity;
        drop(deployment);
        cx.drain_and_finalize();
        fs::remove_file(input)?;
        Ok(Self {
            root,
            identity,
            directory,
        })
    }
    fn args(&self, screened: bool) -> Vec<OsString> {
        let mut args = base(&self.root, self.identity);
        args.extend(
            [
                "--stream-dwell",
                "--dwell-for-ns",
                "20000000000",
                "--dwell-max-gap-ns",
                "100000000",
                "--segment-count",
                "300",
            ]
            .map(OsString::from),
        );
        if screened {
            args.extend(["--sensor-health", "conservative-v1"].map(OsString::from));
        }
        args
    }
    fn snapshot(&self) -> Test<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(self.root.join("ledger/journal.fssj"))?,
            fs::read(self.root.join("effects/journal.fssj"))?,
        ))
    }
}
fn base(root: &Path, identity: ContentDigest) -> Vec<OsString> {
    vec![
        "watch".into(),
        "--root".into(),
        root.as_os_str().to_owned(),
        "--site".into(),
        SITE.into(),
        "--import-id".into(),
        identity.to_text().into(),
        "--interpretation".into(),
        "gray".into(),
        "--zone".into(),
        "porch:0,0,32,32".into(),
    ]
}
fn run(args: &[OsString]) -> Test<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(args)
        .output()?)
}
fn good(output: Output) -> Test<String> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout)?;
    assert!(text.starts_with('{') && text.ends_with("}\n"));
    Ok(text)
}
fn refuses(output: Output, reason: &str) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(reason),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn digest_field(text: &str, key: &str) -> Test<String> {
    // Only synthetic digest-valued fields; not a general-purpose JSON parser.
    let marker = format!("\"{key}\":\"");
    let rest = text.split_once(&marker).ok_or("field absent")?.1;
    let value = rest.split_once('"').ok_or("unterminated digest")?.0;
    ContentDigest::parse(value)?;
    Ok(value.into())
}

#[test]
fn frozen_footage_returns_diagnostics_and_refuses_exact_approved_publication() -> Test {
    let f = Fixture::new("freeze", Scene::Frozen)?;
    let before = f.snapshot()?;
    let mut args = f.args(true);
    let preview = good(run(&args)?)?;
    assert!(preview.contains("\"frames_screened\":300"));
    assert!(preview.contains("\"status\":\"suspected_degradation\""));
    assert!(preview.contains("\"candidate_count\":1"));
    assert!(preview.contains("exact_frame_repetition"));
    assert!(preview.contains("\"publication_blocked\":true"));
    assert!(preview.contains("\"publish_command\":null"));
    assert_eq!(f.snapshot()?, before);
    args.extend([
        "--approve".into(),
        digest_field(&preview, "proposal_digest")?.into(),
    ]);
    refuses(
        run(&args)?,
        "sensor-health findings or incomplete screening",
    );
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn no_findings_can_publish_once_and_export_a_complete_cold_retry_report() -> Test {
    let f = Fixture::new("clear", Scene::Changing)?;
    let before = f.snapshot()?;
    let mut args = f.args(true);
    let preview = good(run(&args)?)?;
    assert!(preview.contains("\"status\":\"no_findings\""));
    assert!(preview.contains("\"healthy_proved\":false"));
    assert!(preview.contains("--sensor-health conservative-v1"));
    assert_eq!(f.snapshot()?, before);
    args.extend([
        "--approve".into(),
        digest_field(&preview, "proposal_digest")?.into(),
    ]);
    let published = good(run(&args)?)?;
    assert!(published.contains("\"status\":\"published\""));
    let after = f.snapshot()?;
    assert_ne!(after.0, before.0);
    assert_eq!(after.1, before.1);
    let output = f.directory.0.join("screened-report.json");
    args.extend(["--report-out".into(), output.as_os_str().to_owned()]);
    let retry = good(run(&args)?)?;
    assert!(retry.contains("\"status\":\"already_published\""));
    assert_eq!(
        digest_field(&retry, "analysis_digest")?,
        digest_field(&preview, "analysis_digest")?
    );
    assert_eq!(fs::read_to_string(output)?, retry);
    assert_eq!(f.snapshot()?, after);
    Ok(())
}

#[test]
fn clipping_and_contrast_loss_are_reported_as_suspected_not_proven_tamper() -> Test {
    for (label, scene, finding) in [
        ("dark", Scene::Dark, "persistent_dark_field"),
        ("bright", Scene::Bright, "persistent_bright_field"),
        ("contrast", Scene::Contrast, "contrast_collapse"),
    ] {
        let f = Fixture::new(label, scene)?;
        let before = f.snapshot()?;
        let report = good(run(&f.args(true))?)?;
        assert!(report.contains(finding));
        assert!(report.contains("\"publication_blocked\":true"));
        assert!(report.contains("\"tamper_proved\":false"));
        assert!(report.contains("\"absence_certifiable\":false"));
        assert_eq!(f.snapshot()?, before);
    }
    Ok(())
}

#[test]
fn changing_or_dropping_screening_cannot_reuse_an_approval() -> Test {
    let f = Fixture::new("approval", Scene::Changing)?;
    let before = f.snapshot()?;
    let plain = good(run(&f.args(false))?)?;
    let screened = good(run(&f.args(true))?)?;
    assert!(!plain.contains("\"sensor_health\":"));
    assert_ne!(
        digest_field(&plain, "proposal_digest")?,
        digest_field(&screened, "proposal_digest")?
    );
    for (enable, wrong) in [(true, &plain), (false, &screened)] {
        let mut args = f.args(enable);
        args.extend([
            "--approve".into(),
            digest_field(wrong, "proposal_digest")?.into(),
        ]);
        refuses(run(&args)?, "ERR-WATCH-APPROVAL-STALE-001");
    }
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn invalid_health_policy_and_orphan_modes_fail_before_deployment_io() -> Test {
    let directory = Directory::new("parse")?;
    let root = directory.0.join("must-not-exist");
    let prefix = base(&root, ContentDigest::sha256(b"not-an-import"));
    for (extra, reason) in [
        (
            vec![
                "--dwell-for-ns",
                "20000000000",
                "--dwell-max-gap-ns",
                "100000000",
                "--sensor-health",
                "conservative-v1",
            ],
            "short dwell screening is unsupported",
        ),
        (
            vec!["--stream-dwell", "--sensor-health", "latest"],
            "requires policy conservative-v1",
        ),
        (vec!["--stream-dwell", "--sensor-health"], "missing value"),
        (
            vec![
                "--stream-dwell",
                "--sensor-health",
                "conservative-v1",
                "--sensor-health",
                "conservative-v1",
            ],
            "duplicate --sensor-health",
        ),
        (
            vec!["--stream-dwell", "--sensor-health", "conservative-v1"],
            "requires the explicit dwell",
        ),
    ] {
        let mut args = prefix.clone();
        args.extend(extra.into_iter().map(OsString::from));
        refuses(run(&args)?, reason);
        assert!(!root.exists());
    }
    Ok(())
}

#[test]
fn tolerated_decode_refusal_remains_incomplete_even_without_a_visual_finding() -> Test {
    let f = Fixture::new("gap", Scene::DecodeGap)?;
    let before = f.snapshot()?;
    let mut args = f.args(true);
    args.push("--tolerate-decode-refusals".into());
    let report = good(run(&args)?)?;
    assert!(report.contains("\"frames_screened\":299"));
    assert!(report.contains("\"complete\":false"));
    assert!(report.contains("\"publication_blocked\":true"));
    assert!(report.contains("\"first_segment\":150"));
    assert!(report.contains("\"absence_certifiable\":false"));
    assert_eq!(f.snapshot()?, before);
    Ok(())
}
