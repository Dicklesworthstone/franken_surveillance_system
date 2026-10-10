#![forbid(unsafe_code)]
//! Whole-recording entry analysis through the real CLI, including approval/restart boundaries.
//! Synthetic footage proves workflow and provenance, not real camera detection quality.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::{CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:stream-entry-cli";
const FRAMES: usize = 300;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-stream-entry-cli-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("temporary directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    root: PathBuf,
    identity: ContentDigest,
    directory: Directory,
}
impl Fixture {
    fn mjpeg(label: &str, appearance: Option<usize>, known_time: bool) -> Test<Self> {
        let config = JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        };
        let mut bytes = Vec::new();
        for frame in 0..FRAMES {
            let mut pixels = vec![40_u8; 48 * 32];
            if appearance.is_some_and(|first| frame >= first) {
                for y in 8..24 {
                    for x in 8..24 {
                        pixels[y * 48 + x] = 220;
                    }
                }
            }
            bytes.extend(encode_jpeg(48, 32, &pixels, &config)?);
        }
        Self::import(label, &bytes, "mjpeg", known_time)
    }

    fn import(label: &str, bytes: &[u8], extension: &str, known_time: bool) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment with spaces");
        let input = directory.0.join(format!("source.{extension}"));
        fs::write(&input, bytes)?;
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:stream-entry-cli".into(),
            operation_id: OperationId::parse("operation:stream-entry-cli")?,
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
        authority.validate()?;
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut limits = FileIngestLimits::standard();
        limits.max_segments = FRAMES + 1;
        limits.chunk_bytes = 4096;
        let mut request = FileIngestRequest::new(
            &input,
            SensorId::parse("sensor:stream-entry")?,
            StreamId::parse("stream:stream-entry")?,
        )
        .with_limits(limits)
        .with_receive_time(TimestampNs(1_000_000_000_000));
        if known_time {
            request = request.with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?);
        }
        let identity = FileIngestAdapter::ingest(request, &cx, &mut deployment)?.import_identity;
        drop(deployment);
        cx.drain_and_finalize();
        // Every preview, publication and retry below must recover from retained custody alone.
        fs::remove_file(input)?;
        Ok(Self {
            root,
            identity,
            directory,
        })
    }

    fn args(&self) -> Vec<OsString> {
        let mut args = base(&self.root, self.identity);
        args.push("--stream-watch".into());
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
        "porch:0,0,48,32".into(),
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
    Ok(String::from_utf8(output.stdout)?)
}
fn refuses(output: Output, reason: &str) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "refusal emitted a JSON prefix");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(reason),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn digest_field(text: &str, key: &str) -> Test<String> {
    // Synthetic digest-valued fields only; this is not a general JSON parser.
    let marker = format!("\"{key}\":\"");
    let rest = text.split_once(&marker).ok_or("missing digest field")?.1;
    let value = rest.split_once('"').ok_or("unterminated digest")?.0;
    ContentDigest::parse(value)?;
    Ok(value.to_owned())
}
fn unsigned_field(text: &str, key: &str) -> Test<u64> {
    let marker = format!("\"{key}\":");
    let rest = text.split_once(&marker).ok_or("missing numeric field")?.1;
    let value: String = rest.chars().take_while(char::is_ascii_digit).collect();
    Ok(value.parse()?)
}
fn set(args: &mut [OsString], key: &str, value: &str) -> Test {
    let position = args.iter().position(|v| v == key).ok_or("missing option")?;
    *args.get_mut(position + 1).ok_or("missing option value")? = value.into();
    Ok(())
}

#[test]
fn entry_beyond_old_window_publishes_once_and_survives_cold_retry() -> Test {
    let f = Fixture::mjpeg("late-entry", Some(180), true)?;
    let before = f.snapshot()?;
    let mut args = f.args();
    let preview = good(run(&args)?)?;
    assert!(preview.contains("\"format\":\"fss.long_watch_report.v1\""));
    assert_eq!(unsigned_field(&preview, "frames_decoded")?, FRAMES as u64);
    assert_eq!(unsigned_field(&preview, "candidate_count")?, 1);
    assert!(unsigned_field(&preview, "entry_position")? >= 180);
    assert!(preview.contains("--stream-watch"));
    assert!(
        preview.contains("'"),
        "rerun must quote the deployment path"
    );
    for expected in [
        "\"event_kind\":\"unclassified\"",
        "\"event_state\":\"indeterminate\"",
        "\"policy_action\":\"hold\"",
        "\"absence_certifiable\":false",
        "\"alert_authorized\":false",
        "\"model_invoked\":false",
    ] {
        assert!(preview.contains(expected), "missing {expected}");
    }
    assert_eq!(f.snapshot()?, before);
    let approval = digest_field(&preview, "proposal_digest")?;
    args.extend(["--approve".into(), approval.into()]);
    let published = good(run(&args)?)?;
    assert!(published.contains("\"status\":\"published\""));
    let after = f.snapshot()?;
    assert_ne!(after.0, before.0);
    assert_eq!(
        after.1, before.1,
        "entry analysis must never dispatch an effect"
    );
    let output = f.directory.0.join("entry report.json");
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
fn aggregate_budgets_refuse_before_report_export_or_event_append() -> Test {
    let f = Fixture::mjpeg("budgets", Some(180), true)?;
    let before = f.snapshot()?;
    for (index, key) in [
        "--stream-read-bytes",
        "--stream-pixel-budget",
        "--stream-assignment-work",
        "--stream-trace-bytes",
    ]
    .into_iter()
    .enumerate()
    {
        let output = f.directory.0.join(format!("refused-{index}.json"));
        let mut args = f.args();
        args.extend([
            key.into(),
            "1".into(),
            "--report-out".into(),
            output.as_os_str().to_owned(),
        ]);
        refuses(run(&args)?, "ERR-WATCH-LIMIT-001");
        assert!(!output.exists());
        assert_eq!(f.snapshot()?, before);
    }
    Ok(())
}

#[test]
fn inapplicable_modes_and_budget_names_fail_before_deployment_io() -> Test {
    let directory = Directory::new("parse")?;
    let root = directory.0.join("must-not-exist");
    let prefix = base(&root, ContentDigest::sha256(b"not-an-import"));
    for (extra, reason) in [
        (
            vec!["--stream-watch", "--stream-watch"],
            "duplicate --stream-watch",
        ),
        (
            vec!["--stream-watch", "--stream-dwell"],
            "cannot be combined",
        ),
        (
            vec!["--stream-watch", "--dwell-for-ns", "1"],
            "cannot be combined",
        ),
        (
            vec!["--stream-watch", "--dwell-read-bytes", "100"],
            "cannot be combined",
        ),
        (
            vec!["--stream-watch", "--detector-package", "/unused/model"],
            "--detector-digest",
        ),
        (
            vec![
                "--stream-watch",
                "--retain-coverage",
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            ],
            "refuses --retain-coverage",
        ),
        (
            vec!["--stream-watch", "--segment-count", "65537"],
            "segment count",
        ),
        (
            vec!["--stream-watch", "--stream-trace-bytes", "0"],
            "limits out of bounds",
        ),
        (
            vec!["--stream-pixel-budget", "100"],
            "require --stream-watch",
        ),
        (
            vec!["--stream-watch", "--sensor-health", "latest"],
            "requires policy conservative-v1",
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
fn changed_analysis_and_other_modes_cannot_reuse_approval() -> Test {
    let f = Fixture::mjpeg("approval", Some(3), true)?;
    let mut long = f.args();
    let preview = good(run(&long)?)?;
    let approval = digest_field(&preview, "proposal_digest")?;
    let before = f.snapshot()?;
    set(&mut long, "--zone", "renamed:0,0,48,32")?;
    long.extend(["--approve".into(), approval.clone().into()]);
    refuses(run(&long)?, "ERR-WATCH-APPROVAL-STALE-001");

    // The complete admitted budget is part of the new mode's reviewable computation recipe.
    let mut changed_budget = f.args();
    changed_budget.extend([
        "--stream-pixel-budget".into(),
        "2147483648".into(),
        "--approve".into(),
        approval.into(),
    ]);
    refuses(run(&changed_budget)?, "ERR-WATCH-APPROVAL-STALE-001");

    let mut short = base(&f.root, f.identity);
    short.extend(["--segment-count", "128"].map(OsString::from));
    let short_report = good(run(&short)?)?;
    let mut dwell = f.args();
    let flag = dwell
        .iter()
        .position(|a| a == "--stream-watch")
        .ok_or("stream flag")?;
    dwell[flag] = "--stream-dwell".into();
    dwell.extend(
        [
            "--dwell-for-ns",
            "1000000000",
            "--dwell-max-gap-ns",
            "100000000",
        ]
        .map(OsString::from),
    );
    let dwell_report = good(run(&dwell)?)?;
    for report in [short_report, dwell_report] {
        let mut args = f.args();
        args.extend([
            "--approve".into(),
            digest_field(&report, "proposal_digest")?.into(),
        ]);
        refuses(run(&args)?, "ERR-WATCH-APPROVAL-STALE-001");
    }
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn unknown_source_time_refuses_before_decoding_or_publication() -> Test {
    let f = Fixture::mjpeg("unknown-time", Some(180), false)?;
    let before = f.snapshot()?;
    let mut args = f.args();
    args.extend(["--work-units", "0"].map(OsString::from));
    refuses(run(&args)?, "explicit capture-time hints");
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn frozen_frames_preserve_diagnostics_and_block_even_exact_approval() -> Test {
    let f = Fixture::mjpeg("health", Some(180), true)?;
    let before = f.snapshot()?;
    let mut args = f.args();
    args.extend(["--sensor-health", "conservative-v1"].map(OsString::from));
    let report = good(run(&args)?)?;
    assert_eq!(unsigned_field(&report, "frames_screened")?, FRAMES as u64);
    assert_eq!(unsigned_field(&report, "candidate_count")?, 1);
    assert!(report.contains("exact_frame_repetition"));
    assert!(report.contains("\"publication_blocked\":true"));
    assert!(report.contains("\"publish_command\":null"));
    args.extend([
        "--approve".into(),
        digest_field(&report, "proposal_digest")?.into(),
    ]);
    refuses(
        run(&args)?,
        "sensor-health findings or incomplete screening",
    );
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn no_entry_in_a_complete_recording_is_not_an_absence_certificate() -> Test {
    let f = Fixture::mjpeg("quiet", None, true)?;
    let before = f.snapshot()?;
    let report = good(run(&f.args())?)?;
    assert_eq!(unsigned_field(&report, "frames_decoded")?, FRAMES as u64);
    assert_eq!(unsigned_field(&report, "candidate_count")?, 0);
    assert!(report.contains("\"absence_certifiable\":false"));
    assert_eq!(f.snapshot()?, before);
    // The ordinary mode keeps its existing explicit 128-frame admission boundary.
    refuses(run(&base(&f.root, f.identity))?, "more than 128 frames");
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn h264_b_picture_recording_scans_in_display_order_and_publishes_once() -> Test {
    let bytes = include_bytes!("../../fss-reference/tests/fixtures/long_dwell_h264/square_300.mp4");
    let f = Fixture::import("h264", bytes, "mp4", true)?;
    let before = f.snapshot()?;
    let mut args = f.args();
    set(&mut args, "--interpretation", "ycbcr")?;
    for tolerant in [false, true] {
        let output = f.directory.0.join(format!("h264-budget-{tolerant}.json"));
        let mut limited = args.clone();
        limited.extend([
            "--stream-read-bytes".into(),
            "1".into(),
            "--report-out".into(),
            output.as_os_str().to_owned(),
        ]);
        if tolerant {
            limited.push("--tolerate-decode-refusals".into());
        }
        refuses(run(&limited)?, "ERR-WATCH-LIMIT-001");
        assert!(!output.exists());
        assert_eq!(f.snapshot()?, before);
    }
    let preview = good(run(&args)?)?;
    assert_eq!(unsigned_field(&preview, "frames_decoded")?, FRAMES as u64);
    assert_eq!(unsigned_field(&preview, "candidate_count")?, 1);
    digest_field(&preview, "entry_capsule_digest")?;
    args.extend([
        "--approve".into(),
        digest_field(&preview, "proposal_digest")?.into(),
    ]);
    let published = good(run(&args)?)?;
    assert!(published.contains("\"status\":\"published\""));
    let after = f.snapshot()?;
    assert_ne!(after.0, before.0);
    assert_eq!(after.1, before.1);
    let retry = good(run(&args)?)?;
    assert!(retry.contains("\"status\":\"already_published\""));
    assert_eq!(f.snapshot()?, after);
    set(&mut args, "--interpretation", "gray")?;
    let wrong = run(&args)?;
    assert!(!wrong.status.success());
    assert!(wrong.stdout.is_empty());
    assert_eq!(f.snapshot()?, after);
    Ok(())
}
