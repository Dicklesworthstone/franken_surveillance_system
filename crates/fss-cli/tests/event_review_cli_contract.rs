#![forbid(unsafe_code)]
//! Generated JPEG -> native watch -> published candidate -> operator review via real binaries.
//! Synthetic moving squares prove wiring, not detector quality or verified human ground truth.
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchLimits, WatchPlan, WatchReport, WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::{FileIngestAdapter, FileIngestRequest};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn Error>>;
const REVIEW: &str = env!("CARGO_BIN_EXE_fss-review");
const SITE: &str = "site:review-cli";
const REASON: &str = "Owner reviewed this synthetic moving-square candidate";
struct Directory(PathBuf);
impl Directory {
    fn new(name: &str) -> Test<Self> {
        for n in 0..100 {
            let p = std::env::temp_dir().join(format!("fss-event-review-cli-{name}-{}-{n}", std::process::id()));
            match fs::create_dir(&p) {
                Ok(()) => return Ok(Self(p)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("temporary directory capacity".into())
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn success(output: Output) -> Test<String> {
    if !output.status.success() { return Err(format!("CLI refused: {}", String::from_utf8_lossy(&output.stderr)).into()); }
    Ok(String::from_utf8(output.stdout)?)
}
fn digest_field(json: &str, field: &str) -> Test<String> {
    let marker = format!("\"{field}\":\"");
    if json.matches(&marker).count() != 1 { return Err(format!("expected one {field}").into()); }
    let text = json.split_once(&marker).ok_or("missing field")?.1.split('"').next().ok_or("unterminated field")?;
    Ok(ContentDigest::parse(text)?.to_text())
}
fn journals(root: &Path) -> Test<(Vec<u8>, Vec<u8>)> {
    Ok((fs::read(root.join("ledger/journal.fssj"))?, fs::read(root.join("effects/journal.fssj"))?))
}
fn seed(directory: &Directory) -> Test<(PathBuf, String, String)> {
    let root = directory.0.join("deployment");
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:review-cli-fixture".into(), operation_id: OperationId::parse("operation:review-cli-fixture")?,
        principal: "principal:local-operator".into(), capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None, priority: 10,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).storage_operations(8192).build()?,
        privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()), generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let config = JpegConfig { quality: 90, subsampling: Subsampling::Grayscale, restart_interval: 0, custom_markers: vec![] };
    let mut stream = Vec::new();
    for frame in 0..14 {
        let mut pixels = vec![40_u8; 96 * 48];
        if frame >= 3 {
            let left = (frame - 3) * 8;
            for y in 8..24 { for x in left..left + 16 { pixels[y * 96 + x] = 220; } }
        }
        stream.extend(encode_jpeg(96, 48, &pixels, &config)?);
    }
    let path = directory.0.join("source.mjpeg"); fs::write(&path, stream)?;
    let request = FileIngestRequest::new(path, SensorId::parse("sensor:review-cli")?, StreamId::parse("stream:review-cli")?)
        .with_receive_time(TimestampNs(1_000_000_000));
    let import = FileIngestAdapter::ingest(request, &cx, &mut deployment)?.import_identity;
    let plan = WatchPlan {
        import_identity: import, interpretation: ComponentInterpretation::Grayscale,
        first_segment: 0, segment_count: 14,
        zones: vec![WatchZone { zone_id: "door".into(), x: 64, y: 0, width: 32, height: 32 }],
        detector: WatchDetectorConfig::default(), tracker: WatchTrackerConfig::default(),
    };
    let mut report = WatchReport::analyze(&deployment, &plan, &WatchLimits::default(), &cx)?;
    assert_eq!(report.candidates().len(), 1);
    let candidate = &report.candidates()[0];
    let event_id = candidate.event().event_id.to_string();
    let revision = candidate.event().revision_digest().to_text();
    let approve = candidate.proposal_digest();
    assert_eq!(report.publish(&mut deployment, &BTreeSet::from([approve]), &cx)?, 1);
    drop(deployment); cx.drain_and_finalize();
    Ok((root, event_id, revision))
}

#[test]
fn native_watch_candidate_is_reviewable_across_processes_and_old_approvals_cannot_replace_it() -> Test {
    let directory = Directory::new("workflow")?;
    let (root, event_id, original) = seed(&directory)?;
    let show = || -> Test<String> {
        success(Command::new(REVIEW).arg("show").arg("--root").arg(&root)
            .args(["--site", SITE, "--event-id", &event_id, "--principal", "principal:reader"]).output()?)
    };
    let call = |action: &str, expected: &str, reason: &str, approval: Option<&str>| -> Test<Output> {
        let mut c = Command::new(REVIEW);
        c.arg(action).arg("--root").arg(&root).args(["--site", SITE, "--event-id", &event_id,
            "--expected-revision", expected, "--reason", reason]);
        if let Some(approval) = approval { c.args(["--approve", approval]); }
        Ok(c.output()?)
    };
    let before = journals(&root)?;
    let shown = show()?;
    assert_eq!(digest_field(&shown, "revision_digest")?, original);
    assert!(shown.contains("not_an_operator_review"));
    let preview = success(call("reject", &original, REASON, None)?)?;
    assert!(preview.contains("\"status\":\"proposed\""));
    assert!(preview.contains("\"evidence_class\":\"assertion\""));
    assert_eq!(journals(&root)?, before);
    let approval = digest_field(&preview, "approval_digest")?;
    let wrong = call("reject", &original, "Another reason", Some(&approval))?;
    assert!(!wrong.status.success());
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("ERR-EVENT-REVIEW-APPROVAL-STALE-001"));
    assert_eq!(journals(&root)?, before);
    let committed = success(call("reject", &original, REASON, Some(&approval))?)?;
    assert!(committed.contains("\"status\":\"published\""));
    let after = journals(&root)?;
    assert_ne!(before.0, after.0); assert_eq!(before.1, after.1);
    let shown = show()?;
    assert!(shown.contains("verified_current_review"));
    assert!(shown.contains(REASON));
    assert!(shown.contains("principal:local-operator"));
    assert!(shown.contains("\"state\":\"rejected\""));
    assert_ne!(digest_field(&shown, "revision_digest")?, original);
    let retry = success(call("reject", &original, REASON, Some(&approval))?)?;
    assert!(retry.contains("\"status\":\"already_published\""));
    assert_eq!(journals(&root)?, after);
    assert!(!call("resolve", &original, REASON, Some(&approval))?.status.success());
    let current = digest_field(&shown, "revision_digest")?;
    assert!(!call("investigate", &current, REASON, None)?.status.success());
    assert_eq!(journals(&root)?, after);
    Ok(())
}

#[test]
fn malformed_or_missing_deployment_requests_never_create_the_root() -> Test {
    let directory = Directory::new("absent")?;
    let absent = directory.0.join("absent");
    for args in [
        vec!["show", "--site", SITE, "--event-id", "event:test"],
        vec!["reject", "--site", SITE, "--event-id", "event:test", "--expected-revision", "bad", "--reason", "No"],
    ] {
        let output = Command::new(REVIEW).args(args).arg("--root").arg(&absent).output()?;
        assert!(!output.status.success()); assert!(!absent.exists());
    }
    Ok(())
}
