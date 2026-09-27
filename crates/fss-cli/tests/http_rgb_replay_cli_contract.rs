#![forbid(unsafe_code)]
//! Actual local binaries: exact history discovery, configuration-only replay and safe refusals.
//! Full numerical/cold-source reconstruction is exercised by the reference integration suite.
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use fss_reference::ingest::http_replay::check::HttpCheckSource;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, CaptureInterval, ContentDigest, OperationId, SensorId, TimestampNs};
use fss_geometry::WorkBudget;
use fss_object::{MAX_MANIFEST_CHILDREN, SpoolLimits};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher};
use fss_reference::{ReferenceDeployment, ReplayCx};
use fss_reference::ingest::http_rgb_history::*;
use fss_reference::ingest::rgb_archive::{RgbArchiveAuthority, RgbArchiveOperation};
use fss_reference::ingest::rgb_evidence::RgbEvidenceBudget;
use fss_twin::image_tracking::ImageTrackingPolicy;
use fss_twin::image_zones::{ImageZoneBasis, ImageZonePolicy, ImageZoneSpec};

type Test<T = ()> = Result<T, Box<dyn Error>>;
const REPLAY: &str = env!("CARGO_BIN_EXE_fss-replay");
const SITE: &str = "site:history-replay-cli";
struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for n in 0..100 {
            let path = std::env::temp_dir().join(format!("fss-history-cli-{label}-{}-{n}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("fixture path bound".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
fn success(output: Output) -> Test<String> {
    if !output.status.success() {
        return Err(format!("binary refused: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(String::from_utf8(output.stdout)?)
}
struct Authority(ContentDigest);
impl HistoryAuthority for Authority {
    fn permits(&self, _: HistoryOperation, session: ContentDigest) -> bool { session == self.0 }
}
struct NoOriginals;
impl RgbArchiveAuthority for NoOriginals {
    fn permits(&self, _: RgbArchiveOperation, _: ContentDigest, _: ContentDigest) -> bool { false }
}
fn context(root: &std::path::Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:history-replay-cli-test".into(),
        operation_id: OperationId::parse("operation:history-replay-cli-test")?,
        principal: "principal:test-owner".into(), capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None, priority: 10,
        budgets: BudgetVector::builder().bytes(1024 * 1024 * 1024).storage_operations(1_000_000).build()?,
        privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()), generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(&authority, root.to_path_buf())?)
}
fn history(work: &mut WorkBudget<'_>) -> Test<HttpRgbHistory> {
    let d = ContentDigest::sha256(b"test configuration only, not executed model");
    let config = HttpRgbHistoryConfig::new(HttpRgbHistorySpec {
        source: HttpCheckSource { source: ContentDigest::sha256(b"source"), generation: 3,
            receive_clock: ContentDigest::sha256(b"receive-clock"),
            retention_evidence: ContentDigest::sha256(b"original-retention") }.scope()?,
        sensor: SensorId::parse("sensor:history-cli")?,
        validity: CaptureInterval::new(TimestampNs(0), TimestampNs(3_000_000_000))?,
        episode: [9; 32], head: d, model: d, retention: d, class_index: 0, class_selection: d,
        tracking: ImageTrackingPolicy {
            maximum_tracks: 8, maximum_detections: 8, maximum_exposures: 100,
            minimum_observations: 2, maximum_misses: 2, maximum_gap_ns: 10_000_000_000,
            maximum_speed: 1000, gate_padding: 4, miss_cost: 1000, ambiguity_margin: 0,
        },
        basis: ImageZoneBasis { camera: 1, clock: 2, calibration: [4; 32], image_domain: [3; 32], dimensions: [32, 16] },
        zone_policy: ImageZonePolicy { selection_evidence: [8; 32], maximum_sample_gap_ns: 10_000_000_000 },
        zones: vec![ImageZoneSpec { id: 1, vertices: vec![[14, 1], [30, 1], [30, 15], [14, 15]], margin: 0, dwell_ns: None }],
    }, work)?;
    Ok(HttpRgbHistory::new(config))
}
fn archive(root: &std::path::Path) -> Test {
    drop(LocalRootPublisher::open(root, LocalPublicationLimits::new(128, MAX_MANIFEST_CHILDREN, 128, 1024,
        SpoolLimits::new(1024, 64 * 1024 * 1024, 65536, 2048)))?);
    Ok(())
}

#[test]
fn help_exposes_inspection_and_exact_tip_replay_without_contacting_a_camera() -> Test {
    let help = success(Command::new(REPLAY).arg("--help").output()?)?;
    assert!(help.contains("inspect-http-rgb"));
    assert!(help.contains("--expected-root"));
    assert!(help.contains("--read-originals yes"));
    Ok(())
}

#[test]
fn missing_or_malformed_inputs_do_not_create_replacement_deployments() -> Test {
    let directory = Directory::new("missing")?;
    let root = directory.0.join("absent");
    let id = ContentDigest::sha256(b"session").to_text();
    for session in ["not-a-digest", id.as_str()] {
        let output = Command::new(REPLAY).arg("inspect-http-rgb").arg("--root").arg(&root)
            .args(["--site", SITE, "--session", session]).output()?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!root.exists());
    }
    let originals = directory.0.join("also-absent");
    let output = Command::new(REPLAY).arg("http-rgb").arg("--root").arg(&root)
        .args(["--site", SITE, "--session", &id, "--expected-root", &id, "--expected-revision", "1"])
        .arg("--original-root").arg(&originals).output()?;
    assert!(!output.status.success());
    assert!(!root.exists());
    assert!(!originals.exists());
    Ok(())
}

#[test]
fn actual_cli_discovers_and_replays_configuration_without_claiming_inference_or_completion() -> Test {
    let directory = Directory::new("config")?;
    let root = directory.0.join("deployment");
    let original = directory.0.join("original");
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let mut work = WorkBudget::new(1_000_000_000_000);
    let h = history(&mut work)?;
    let tip = h.tip()?;
    h.publish(tip, &mut deployment, HistoryAccess { history: &Authority(tip.session), evidence: &NoOriginals },
        HistoryLimits::default(), &mut RgbEvidenceBudget::new(1_000_000_000), &mut work, &cx)?;
    let anchor = deployment.current_anchor().clone();
    drop(deployment);
    archive(&original)?;
    let selected = tip.session.to_text();
    let inspected = success(Command::new(REPLAY).arg("inspect-http-rgb").arg("--root").arg(&root)
        .args(["--site", SITE, "--session", &selected]).output()?)?;
    assert!(inspected.contains(&tip.root.to_text()));
    assert!(inspected.contains("\"numerical_execution\":\"not_run\""));
    assert!(inspected.contains("\"pending_not_executed\":null"));
    let verify = |expected: ContentDigest| -> Test<Output> {
        Ok(Command::new(REPLAY).arg("http-rgb").arg("--root").arg(&root)
            .args(["--site", SITE, "--session", &selected, "--expected-root", &expected.to_text(),
                "--expected-revision", "0", "--read-originals", "yes", "--execute-model", "yes", "--max-attempts", "0"])
            .arg("--original-root").arg(&original).output()?)
    };
    let report = success(verify(tip.root)?)?;
    assert!(report.contains("\"status\":\"configuration_only\""));
    assert!(report.contains("\"source_complete\":false"));
    assert!(report.contains("\"execution_attempts\":0"));
    assert!(report.contains("\"verified_frames\":0"));
    let stale = verify(ContentDigest::sha256(b"not the selected root"))?;
    assert!(!stale.status.success());
    assert!(stale.stdout.is_empty());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("ERR-HTTP-RGB-REPLAY-STALE-001"));
    let reopened = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    assert_eq!(reopened.current_anchor(), &anchor, "inspection/replay cannot repair or append");
    drop(reopened);
    cx.drain_and_finalize();
    Ok(())
}
