#![forbid(unsafe_code)]
//! Cross-process event preparation, exact publication, restart, and export refusal.

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use fss_core::{BudgetVector, ContentDigest, EventHypothesis, EventState, OperationId, SensorId, StreamId, TimestampNs};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_reference::{ExecBudget, ReferenceDeployment, ReplayCx, ScalarExecCx};
use fss_reference::ingest::{FileIngestAdapter, FileIngestRequest, RetainedReadLimits};
use fss_reference::ingest::analysis::{AnalysisBudget, AnalysisFrame, AnalysisLimits, AnalysisPlan, AnalysisReport};
use fss_reference::ingest::detections::{BoxEncoding, CoordinateSpace, DetectionSpec};
use fss_reference::ingest::inference::{RecordedInference, RecordedModel};
use fss_reference::ingest::recorded_decode::{ComponentInterpretation, DecodeBudget, DecodeLimits, RecordedDecodeRequest, RecordedFrame};
use fss_reference::ingest::tracking::TrackingConfig;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const JPEG: &[u8] = include_bytes!("fixtures/retained_file_8x8.jpg");
const MODEL: &[u8] = include_bytes!("fixtures/detector_rows_8x8.fssmodel");
struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> TestResult<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!("fss-event-cli-{label}-{}-{attempt}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(e) => return Err(e.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
struct Fixture { directory: Directory, root: PathBuf, report: PathBuf, bytes: Vec<u8>, digest: String, track: String, import: String, runs: PathBuf }
fn fixture(label: &str) -> TestResult<Fixture> {
    let directory = Directory::new(label)?;
    let root = directory.0.join("deployment");
    let source = directory.0.join("source.mjpeg");
    fs::write(&source, [JPEG, JPEG].concat())?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:event-cli-test".into(), operation_id: OperationId::parse("operation:event-cli-test")?,
        principal: "principal:event-cli-test".into(), capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None, priority: 10, budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"site:event-cli"), generation: 1,
    })?;
    authority.validate()?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
    let mut deployment = ReferenceDeployment::open(&root, "site:event-cli", &cx)?;
    let imported = FileIngestAdapter::ingest(FileIngestRequest::new(&source,
        SensorId::parse("sensor:event-cli")?, StreamId::parse("stream:event-cli")?)
        .with_receive_time(TimestampNs(1_000_000_000)), &cx, &mut deployment)?;
    let model = RecordedModel::decode(MODEL, ContentDigest::sha256(MODEL))?;
    let mut frames = Vec::new();
    for segment_index in 0..2 {
        let request = RecordedDecodeRequest { import_identity: imported.import_identity, segment_index,
            interpretation: ComponentInterpretation::Grayscale, read_limits: RetainedReadLimits::default(),
            decode_limits: DecodeLimits::default() };
        RecordedFrame::decode_and_publish(&mut deployment, &request, &mut DecodeBudget::new(100_000_000), &cx)?;
        let run = RecordedInference::run_and_publish(&mut deployment, &request, &model,
            ExecBudget::new(100_000_000, 64 * 1024 * 1024), &ScalarExecCx::new(), &cx)?;
        frames.push(AnalysisFrame { segment_index, run_identity: run.identity() });
    }
    let runs = directory.0.join("runs.txt");
    fs::write(&runs, frames.iter().map(|f| format!("{} {}\n", f.segment_index, f.run_identity)).collect::<String>())?;
    let import = imported.import_identity.to_text();
    let plan = AnalysisPlan::new(imported.import_identity, ComponentInterpretation::Grayscale,
        DetectionSpec { model_digest: model.digest(), output_port: "detections".into(),
            labels: vec!["vehicle".into(), "animal".into()], encoding: BoxEncoding::Xyxy,
            coordinates: CoordinateSpace::Normalized, minimum_score_ppm: 500_000, nms_iou_ppm: 500_000,
            maximum_rows: 4096, maximum_detections: 128 },
        TrackingConfig { minimum_iou_ppm: 100_000, confirmation_hits: 2, maximum_missed_frames: 1, maximum_tracks: 128 }, frames)?;
    let report = AnalysisReport::read(&deployment, &plan, &AnalysisLimits::default(),
        &mut AnalysisBudget::new(100_000_000, 100_000_000), &cx)?;
    let track = report.observations()[0].tracking().tracks.first().ok_or("fixture track missing")?.id.to_text();
    let bytes = report.encoded().to_vec(); let digest = report.digest().to_text();
    let path = directory.0.join("analysis.bin"); fs::write(&path, &bytes)?;
    fs::remove_file(&source)?;
    drop(deployment); cx.drain_and_finalize();
    Ok(Fixture { directory, root, report: path, bytes, digest, track, import, runs })
}
fn command(f: &Fixture, action: &str) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_fss-event"));
    c.arg(action).arg("--root").arg(&f.root).args(["--site", "site:event-cli"]);
    if matches!(action, "prepare" | "publish") { c.arg("--report").arg(&f.report).args(["--report-digest", &f.digest, "--track", &f.track]); }
    c
}
fn success(output: &Output) {
    assert!(output.status.success(), "stdout={} stderr={}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}
fn field(output: &Output, key: &str) -> TestResult<String> {
    std::str::from_utf8(&output.stdout)?.lines().find_map(|s| s.strip_prefix(&format!("{key}=")))
        .map(str::to_owned).ok_or_else(|| std::io::Error::other(format!("missing {key}")).into())
}

/// Serializes this binary's tests. Tests open a `ReferenceDeployment` in this process, which holds
/// its native flock owner lock, and spawn real CLI processes. A child spawned by a concurrent test
/// thread inherits, until its exec closes it, every descriptor open at that instant, including
/// another test's held deployment lock; the flock then outlives its owner's drop, and that test's
/// next child or read-only inspection sees the deployment as Locked or as having an active writer.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn prepare_publish_and_restart_recover_canonical_event_and_report() -> TestResult {
    let _serial = serial();
    let f = fixture("restart")?;
    let prepared = command(&f, "prepare").output()?; success(&prepared);
    let id = field(&prepared, "event_id")?;
    let missing = command(&f, "read").args(["--event-id", &id]).output()?;
    assert_eq!(missing.status.code(), Some(1));
    let published = command(&f, "publish").args(["--proposal-digest", &field(&prepared, "proposal_digest")?]).output()?;
    success(&published);
    fs::remove_file(&f.report)?;
    let event_path = f.directory.0.join("event.json"); let report_path = f.directory.0.join("recovered.bin");
    let read = command(&f, "read").args(["--event-id", &id]).arg("--event-out").arg(&event_path)
        .arg("--report-out").arg(&report_path).output()?;
    success(&read);
    assert_eq!(field(&read, "authority_sequence")?, field(&published, "authority_sequence")?);
    assert_eq!(field(&read, "event_root")?, field(&published, "event_root")?);
    assert_eq!(fs::read(report_path)?, f.bytes);
    let event = EventHypothesis::from_json(&fs::read_to_string(event_path)?)?;
    assert_eq!(event.state, EventState::Indeterminate); assert!(event.decision_path.abstained);
    assert!(event.evidence.iter().all(|e| !e.supports));
    assert_eq!(field(&read, "absence_certifiable")?, "false");
    assert_eq!(field(&read, "effects_authorized")?, "false");
    Ok(())
}

#[test]
fn wrong_approval_refuses_and_exact_publication_retry_reuses_authority() -> TestResult {
    let _serial = serial();
    let f = fixture("approval")?;
    let prepared = command(&f, "prepare").output()?; success(&prepared);
    let bad = ContentDigest::sha256(b"unapproved").to_text();
    let result = command(&f, "publish").args(["--proposal-digest", &bad]).output()?;
    assert_eq!(result.status.code(), Some(1));
    let result = command(&f, "read").args(["--event-id", &field(&prepared, "event_id")?]).output()?;
    assert_eq!(result.status.code(), Some(1));
    let approved = field(&prepared, "proposal_digest")?;
    let first = command(&f, "publish").args(["--proposal-digest", &approved]).output()?;
    let second = command(&f, "publish").args(["--proposal-digest", &approved]).output()?;
    success(&first); success(&second);
    for key in ["authority_sequence", "event_root", "event_revision_digest", "revision"] {
        assert_eq!(field(&first, key)?, field(&second, key)?);
    }
    Ok(())
}

#[test]
fn exports_never_overwrite_or_enter_the_deployment() -> TestResult {
    let _serial = serial();
    let f = fixture("export")?;
    let existing = f.directory.0.join("existing.json"); fs::write(&existing, b"operator-owned")?;
    let refused = command(&f, "prepare").arg("--event-out").arg(&existing).output()?;
    assert_eq!(refused.status.code(), Some(1)); assert_eq!(fs::read(&existing)?, b"operator-owned");
    let inside = f.root.join("not-an-evidence-object");
    let refused = command(&f, "prepare").arg("--event-out").arg(&inside).output()?;
    assert_eq!(refused.status.code(), Some(1)); assert!(!inside.exists());
    Ok(())
}

#[test]
fn malformed_approval_and_missing_deployment_do_not_create_storage() -> TestResult {
    let _serial = serial();
    let directory = Directory::new("absent")?; let root = directory.0.join("absent");
    let digest = ContentDigest::sha256(b"absent").to_text();
    let parsed = Command::new(env!("CARGO_BIN_EXE_fss-event")).arg("publish").arg("--root").arg(&root)
        .args(["--site", "site:event-cli", "--report", "missing.bin", "--report-digest", &digest, "--track", &digest]).output()?;
    assert_eq!(parsed.status.code(), Some(2)); assert!(!root.exists());
    let missing = Command::new(env!("CARGO_BIN_EXE_fss-event")).arg("read").arg("--root").arg(&root)
        .args(["--site", "site:event-cli", "--event-id", "event:missing"]).output()?;
    assert_eq!(missing.status.code(), Some(1)); assert!(!root.exists());
    Ok(())
}

#[test]
fn report_command_reproduces_the_library_recipe_and_lists_event_candidates() -> TestResult {
    let _serial = serial();
    let f = fixture("report")?;
    let path = f.directory.0.join("cli-analysis.bin");
    let result = command(&f, "report").args(["--import-id", &f.import, "--interpretation", "gray",
        "--model-digest", &ContentDigest::sha256(MODEL).to_text(), "--output-port", "detections",
        "--labels", "vehicle,animal", "--box-format", "xyxy", "--coordinates", "normalized"])
        .arg("--runs").arg(&f.runs).arg("--report-out").arg(&path).output()?;
    success(&result);
    assert_eq!(field(&result, "report_digest")?, f.digest);
    assert_eq!(fs::read(path)?, f.bytes);
    assert_eq!(field(&result, "frames")?, "2");
    assert!(std::str::from_utf8(&result.stdout)?.lines().any(|s| s == format!("track={}", f.track)));
    Ok(())
}
