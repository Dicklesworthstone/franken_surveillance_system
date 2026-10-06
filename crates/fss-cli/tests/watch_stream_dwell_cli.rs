#![forbid(unsafe_code)]
//! Real CLI on long retained MJPEG sources. No external encoder, model or network service.

use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::{CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:stream-dwell-cli";
const FRAMES: usize = 300;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-stream-dwell-cli-{label}-{}-{attempt}",
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
    fn new(label: &str, known_time: bool, moving: bool) -> Test<Self> {
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
        for frame in 0..FRAMES {
            let mut pixels = vec![40_u8; 48 * 32];
            if moving && frame >= 3 {
                for y in 8..24 {
                    for x in 8..24 {
                        pixels[y * 48 + x] = 220;
                    }
                }
            }
            bytes.extend(encode_jpeg(48, 32, &pixels, &config)?);
        }
        fs::write(&input, bytes)?;
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:stream-dwell-cli".into(),
            operation_id: OperationId::parse("operation:stream-dwell-cli")?,
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
            SensorId::parse("sensor:stream-dwell")?,
            StreamId::parse("stream:stream-dwell")?,
        )
        .with_limits(limits)
        .with_receive_time(TimestampNs(1_000_000_000_000));
        if known_time {
            request = request.with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?);
        }
        let identity = FileIngestAdapter::ingest(request, &cx, &mut deployment)?.import_identity;
        drop(deployment);
        cx.drain_and_finalize();
        fs::remove_file(input)?;
        Ok(Self {
            root,
            identity,
            directory,
        })
    }
    fn args(&self) -> Vec<OsString> {
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
        args
    }
    fn snapshot(&self) -> Test<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(self.root.join("ledger/journal.fssj"))?,
            fs::read(self.root.join("effects/journal.fssj"))?,
        ))
    }
}
fn base(root: &std::path::Path, identity: ContentDigest) -> Vec<OsString> {
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
fn refuses(output: Output, expected: &str) {
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "refusal must not emit a JSON prefix"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(expected),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn field(text: &str, key: &str) -> Test<String> {
    // Used only for digest-valued fields of our synthetic report: escaped text is never parsed.
    let marker = format!("\"{key}\":\"");
    let rest = text.split_once(&marker).ok_or("missing field")?.1;
    let value = rest.split_once('"').ok_or("unterminated field")?.0;
    ContentDigest::parse(value)?;
    Ok(value.to_owned())
}
fn set(args: &mut [OsString], key: &str, value: &str) -> Test {
    let position = args.iter().position(|v| v == key).ok_or("missing option")?;
    *args.get_mut(position + 1).ok_or("missing option value")? = value.into();
    Ok(())
}

#[test]
fn long_preview_publish_and_cold_retry_use_one_event_after_original_file_removal() -> Test {
    let f = Fixture::new("publish", true, true)?;
    let mut args = f.args();
    let before = f.snapshot()?;
    let preview = good(run(&args)?)?;
    assert!(preview.contains("\"format\":\"fss.long_dwell_report.v1\""));
    assert!(preview.contains("\"frames_decoded\":300"));
    assert!(preview.contains("\"trigger_segment\":205"));
    assert!(preview.contains("\"candidate_count\":1"));
    assert!(preview.contains("--stream-dwell"));
    assert!(preview.contains("\"alert_authorized\":false"));
    assert_eq!(f.snapshot()?, before);
    let approval = field(&preview, "proposal_digest")?;
    args.extend(["--approve".into(), approval.into()]);
    let published = good(run(&args)?)?;
    assert!(published.contains("\"status\":\"published\""));
    let after = f.snapshot()?;
    assert_ne!(after.0, before.0);
    assert_eq!(after.1, before.1);
    let retry = good(run(&args)?)?;
    assert!(retry.contains("\"status\":\"already_published\""));
    assert_eq!(
        field(&retry, "analysis_digest")?,
        field(&preview, "analysis_digest")?
    );
    assert_eq!(f.snapshot()?, after);
    Ok(())
}

#[test]
fn aggregate_budget_refusal_leaves_no_report_file_or_authority_append() -> Test {
    let f = Fixture::new("budget", true, true)?;
    let before = f.snapshot()?;
    for (index, key) in [
        "--dwell-read-bytes",
        "--dwell-pixel-budget",
        "--dwell-assignment-work",
        "--dwell-trace-bytes",
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
fn invalid_stream_modes_are_rejected_before_deployment_io() -> Test {
    let directory = Directory::new("parse")?;
    let root = directory.0.join("must-not-exist");
    let prefix = base(&root, ContentDigest::sha256(b"not an import"));
    let rule = [
        "--stream-dwell",
        "--dwell-for-ns",
        "1",
        "--dwell-max-gap-ns",
        "1",
    ];
    let mut missing_rule = prefix.clone();
    missing_rule.push("--stream-dwell".into());
    refuses(run(&missing_rule)?, "requires");
    for extra in [
        vec!["--stream-dwell"],
        vec!["--detector-package", "/unused/model"],
        vec![
            "--retain-coverage",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        ],
        vec!["--segment-count", "65537"],
        vec!["--dwell-trace-bytes", "0"],
    ] {
        let mut args = prefix.clone();
        args.extend(rule.map(OsString::from));
        args.extend(extra.into_iter().map(OsString::from));
        let output = run(&args)?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!root.exists());
    }
    let mut no_mode = prefix;
    no_mode.extend(["--dwell-pixel-budget", "100"].map(OsString::from));
    refuses(run(&no_mode)?, "require --stream-dwell");
    assert!(!root.exists());
    Ok(())
}

#[test]
fn changed_temporal_rule_cannot_reuse_prior_approval() -> Test {
    let f = Fixture::new("rule", true, true)?;
    let mut args = f.args();
    let approval = field(&good(run(&args)?)?, "proposal_digest")?;
    let before = f.snapshot()?;
    set(&mut args, "--dwell-for-ns", "20100000000")?;
    args.extend(["--approve".into(), approval.into()]);
    refuses(run(&args)?, "ERR-WATCH-APPROVAL-STALE-001");
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn unknown_source_time_does_not_consume_codec_budget_or_publish() -> Test {
    let f = Fixture::new("unknown", false, true)?;
    let before = f.snapshot()?;
    let mut args = f.args();
    args.extend(["--work-units", "0"].map(OsString::from));
    refuses(run(&args)?, "explicit capture-time hints");
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn a_short_dwell_approval_cannot_authorize_streaming_mode() -> Test {
    let f = Fixture::new("separate", true, true)?;
    let mut args = f.args();
    args.retain(|v| v != "--stream-dwell");
    set(&mut args, "--segment-count", "128")?;
    set(&mut args, "--dwell-for-ns", "1000000000")?;
    let short = good(run(&args)?)?;
    assert!(short.contains("fss.recorded_dwell_report.v1"));
    let approval = field(&short, "proposal_digest")?;
    let before = f.snapshot()?;
    args.extend(["--stream-dwell".into(), "--approve".into(), approval.into()]);
    refuses(run(&args)?, "ERR-WATCH-APPROVAL-STALE-001");
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn complete_default_range_report_exports_without_inventing_absence() -> Test {
    let f = Fixture::new("static", true, false)?;
    let mut args = f.args();
    let position = args
        .iter()
        .position(|v| v == "--segment-count")
        .ok_or("missing count")?;
    drop(args.drain(position..position + 2));
    let output = f.directory.0.join("long report.json");
    args.extend(["--report-out".into(), output.as_os_str().to_owned()]);
    let before = f.snapshot()?;
    let json = good(run(&args)?)?;
    assert_eq!(fs::read_to_string(output)?, json);
    assert!(json.contains("\"frames_decoded\":300"));
    assert!(json.contains("\"candidate_count\":0"));
    assert!(json.contains("\"absence_certifiable\":false"));
    assert_eq!(f.snapshot()?, before);
    Ok(())
}
