#![forbid(unsafe_code)]

use super::*;
use std::fs;
use std::path::{Path, PathBuf};
use fss_core::{BudgetVector, OperationId, SensorId, StreamId, TimestampNs};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use crate::{ExecBudget, ScalarExecCx};
use crate::ingest::{FileIngestAdapter, FileIngestRequest, RetainedReadLimits};
use crate::ingest::analysis::{AnalysisFrame, AnalysisPlan};
use crate::ingest::detections::{BoxEncoding, CoordinateSpace, DetectionSpec};
use crate::ingest::inference::{RecordedInference, RecordedModel};
use crate::ingest::recorded_decode::{ComponentInterpretation, DecodeBudget, DecodeLimits, RecordedDecodeRequest, RecordedFrame};
use crate::ingest::tracking::TrackingConfig;

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;
const JPEG: &[u8] = include_bytes!("../../../../fss-cli/tests/fixtures/retained_file_8x8.jpg");
const MODEL: &[u8] = include_bytes!("../../../../fss-cli/tests/fixtures/detector_rows_8x8.fssmodel");
struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> TestResult<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!("fss-recorded-event-{label}-{}-{attempt}", std::process::id()));
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
fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:event-test".into(), operation_id: OperationId::parse("operation:event-test")?,
        principal: "principal:event-test".into(), capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None, priority: 10, budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"site:event-test"), generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(&authority, root.to_path_buf())?)
}
fn budget() -> AnalysisBudget { AnalysisBudget::new(100_000_000, 100_000_000) }
struct Fixture {
    // Drop the deployment's owned handles before removing the test directory.
    deployment: ReferenceDeployment,
    cx: ReplayCx,
    directory: Directory,
    report: AnalysisReport,
    full: AnalysisReport,
    track: ContentDigest,
}
fn fixture(label: &str) -> TestResult<Fixture> {
    let directory = Directory::new(label)?;
    let root = directory.0.join("deployment");
    let source = directory.0.join("source.mjpeg");
    fs::write(&source, [JPEG, JPEG, JPEG].concat())?;
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, "site:event-test", &cx)?;
    let imported = FileIngestAdapter::ingest(FileIngestRequest::new(source,
        SensorId::parse("sensor:event-test")?, StreamId::parse("stream:event-test")?)
        .with_receive_time(TimestampNs(1_000_000_000)), &cx, &mut deployment)?;
    let model = RecordedModel::decode(MODEL, ContentDigest::sha256(MODEL))?;
    let mut frames = Vec::new();
    for segment_index in 0..3 {
        let request = RecordedDecodeRequest { import_identity: imported.import_identity, segment_index,
            interpretation: ComponentInterpretation::Grayscale, read_limits: RetainedReadLimits::default(),
            decode_limits: DecodeLimits::default() };
        RecordedFrame::decode_and_publish(&mut deployment, &request, &mut DecodeBudget::new(100_000_000), &cx)?;
        let inference = RecordedInference::run_and_publish(&mut deployment, &request, &model,
            ExecBudget::new(100_000_000, 64 * 1024 * 1024), &ScalarExecCx::new(), &cx)?;
        frames.push(AnalysisFrame { segment_index, run_identity: inference.identity() });
    }
    let spec = DetectionSpec { model_digest: model.digest(), output_port: "detections".into(),
        labels: vec!["vehicle".into(), "animal".into()], encoding: BoxEncoding::Xyxy,
        coordinates: CoordinateSpace::Normalized, minimum_score_ppm: 500_000, nms_iou_ppm: 500_000,
        maximum_rows: 4096, maximum_detections: 128 };
    let tracking = TrackingConfig { minimum_iou_ppm: 100_000, confirmation_hits: 2,
        maximum_missed_frames: 1, maximum_tracks: 128 };
    let plan = AnalysisPlan::new(imported.import_identity, ComponentInterpretation::Grayscale,
        spec.clone(), tracking, frames[..2].to_vec())?;
    let full_plan = AnalysisPlan::new(imported.import_identity, ComponentInterpretation::Grayscale,
        spec, tracking, frames)?;
    let report = AnalysisReport::read(&deployment, &plan, &AnalysisLimits::default(), &mut budget(), &cx)?;
    let full = AnalysisReport::read(&deployment, &full_plan, &AnalysisLimits::default(), &mut budget(), &cx)?;
    let track = report.observations()[0].tracking().tracks.iter().find(|t| t.class_index == 0)
        .ok_or_else(|| std::io::Error::other("fixture track missing"))?.id;
    Ok(Fixture { deployment, cx, directory, report, full, track })
}
fn prepare(f: &Fixture, full: bool) -> TestResult<RecordedEventProposal> {
    let report = if full { &f.full } else { &f.report };
    Ok(RecordedEventProposal::prepare(&f.deployment, report.encoded(), report.digest(), f.track,
        &AnalysisLimits::default(), &mut budget(), &f.cx)?)
}
fn publish(f: &mut Fixture, proposal: &RecordedEventProposal) -> TestResult<RecordedEvent> {
    Ok(proposal.publish(&mut f.deployment, proposal.digest(), &AnalysisLimits::default(), &mut budget(), &f.cx)?)
}

#[test]
fn preparation_is_read_only_and_never_upgrades_model_authority() -> TestResult {
    let f = fixture("prepare")?;
    let anchor = f.deployment.current_anchor().clone();
    let objects = f.deployment.publisher().spool().object_count();
    let proposal = prepare(&f, false)?;
    let event = proposal.event();
    assert_eq!(event.state, EventState::Indeterminate);
    assert_eq!(event.kind, EventKind::Unclassified);
    assert_eq!(event.probability, ProbabilityInterval::new(0.0, 1.0)?);
    assert!(event.decision_path.abstained);
    assert!(event.evidence.iter().all(|e| !e.supports && e.class == EvidenceClass::Derived));
    assert_eq!(event.interval, CaptureInterval::new(TimestampNs(0), TimestampNs(1_000_000_000))?);
    assert_eq!(event.model_receipts.len(), 2);
    assert_eq!(f.deployment.current_anchor(), &anchor);
    assert_eq!(f.deployment.publisher().spool().object_count(), objects);
    assert_eq!(prepare(&f, false)?.digest(), proposal.digest());
    Ok(())
}

#[test]
fn publication_restarts_without_source_or_report_files_and_retries_idempotently() -> TestResult {
    let mut f = fixture("restart")?;
    let proposal = prepare(&f, false)?;
    let published = publish(&mut f, &proposal)?;
    let anchor = f.deployment.current_anchor().clone();
    let retry = publish(&mut f, &proposal)?;
    assert_eq!(retry.event(), published.event());
    assert_eq!(retry.authority_anchor(), published.authority_anchor());
    assert_eq!(f.deployment.current_anchor(), &anchor);
    fs::remove_file(f.directory.0.join("source.mjpeg"))?;
    let root = f.directory.0.join("deployment");
    drop(f.deployment);
    let reopened = ReferenceDeployment::open(&root, "site:event-test", &f.cx)?;
    let recovered = RecordedEvent::open(&reopened, &published.event().event_id,
        &AnalysisLimits::default(), &mut budget(), &f.cx)?;
    assert_eq!(recovered.event(), published.event());
    assert_eq!(recovered.root(), published.root());
    assert_eq!(recovered.authority_anchor(), published.authority_anchor());
    assert_eq!(recovered.report().encoded(), f.report.encoded());
    assert_eq!(reopened.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn exact_history_extension_supersedes_without_dropping_evidence() -> TestResult {
    let mut f = fixture("extension")?;
    let old = prepare(&f, false)?;
    let first = publish(&mut f, &old)?;
    let next = prepare(&f, true)?;
    assert_eq!(next.event().event_id, first.event().event_id);
    assert_eq!(next.event().revision, 2);
    assert_eq!(next.event().supersedes, Some(first.event().revision_digest()));
    assert!(first.event().evidence.iter().all(|e| next.event().evidence.contains(e)));
    let second = publish(&mut f, &next)?;
    EventHypothesis::verify_chain(&[first.event().clone(), second.event().clone()])?;
    let anchor = f.deployment.current_anchor().clone();
    assert!(old.publish(&mut f.deployment, old.digest(), &AnalysisLimits::default(), &mut budget(), &f.cx).is_err());
    assert_eq!(f.deployment.current_anchor(), &anchor);
    let recovered = RecordedEvent::open(&f.deployment, &second.event().event_id,
        &AnalysisLimits::default(), &mut budget(), &f.cx)?;
    assert_eq!(recovered.event(), second.event());
    assert_eq!(recovered.report().digest(), f.full.digest());
    Ok(())
}

#[test]
fn wrong_approval_and_tampered_reports_publish_nothing() -> TestResult {
    let mut f = fixture("tamper")?;
    let proposal = prepare(&f, false)?;
    let anchor = f.deployment.current_anchor().clone();
    assert!(matches!(proposal.publish(&mut f.deployment, ContentDigest::sha256(b"not approved"),
        &AnalysisLimits::default(), &mut budget(), &f.cx), Err(RecordedEventError::StaleProposal)));
    let mut bad = f.report.encoded().to_vec(); bad.push(0);
    for digest in [f.report.digest(), ContentDigest::sha256(&bad)] {
        assert!(RecordedEventProposal::prepare(&f.deployment, &bad, digest, f.track,
            &AnalysisLimits::default(), &mut budget(), &f.cx).is_err());
    }
    assert_eq!(f.deployment.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn unknown_tracks_and_exhausted_budgets_create_no_empty_absence_events() -> TestResult {
    let f = fixture("refusal")?;
    let anchor = f.deployment.current_anchor().clone();
    assert!(matches!(RecordedEventProposal::prepare(&f.deployment, f.report.encoded(), f.report.digest(),
        ContentDigest::sha256(b"unknown track"), &AnalysisLimits::default(), &mut budget(), &f.cx),
        Err(RecordedEventError::TrackUnavailable)));
    assert!(RecordedEventProposal::prepare(&f.deployment, f.report.encoded(), f.report.digest(), f.track,
        &AnalysisLimits::default(), &mut AnalysisBudget::new(0, 0), &f.cx).is_err());
    let mut limits = AnalysisLimits::default(); limits.maximum_frames = 1;
    assert!(RecordedEventProposal::prepare(&f.deployment, f.report.encoded(), f.report.digest(), f.track,
        &limits, &mut budget(), &f.cx).is_err());
    assert_eq!(f.deployment.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn cancelled_staging_changes_neither_event_authority_nor_object_count() -> TestResult {
    let mut f = fixture("cancel-stage")?;
    let proposal = prepare(&f, false)?;
    let anchor = f.deployment.current_anchor().clone();
    let count = f.deployment.publisher().spool().object_count();
    f.cx.set_cancel_at_checkpoint("recorded_event:stage");
    assert!(matches!(proposal.publish(&mut f.deployment, proposal.digest(), &AnalysisLimits::default(),
        &mut budget(), &f.cx), Err(RecordedEventError::Cancelled)));
    assert_eq!(f.deployment.current_anchor(), &anchor);
    assert_eq!(f.deployment.publisher().spool().object_count(), count);
    assert!(f.cx.is_drain_completed());
    Ok(())
}

#[test]
fn root_without_final_event_is_incomplete_and_exact_retry_resumes() -> TestResult {
    let mut f = fixture("pending")?;
    let proposal = prepare(&f, false)?;
    let before = f.deployment.current_anchor().clone();
    f.cx.set_cancel_at_checkpoint(STAGE_RECORDED_EVENT_COMMIT);
    assert!(matches!(proposal.publish(&mut f.deployment, proposal.digest(), &AnalysisLimits::default(),
        &mut budget(), &f.cx), Err(RecordedEventError::Cancelled)));
    assert!(f.deployment.current_anchor().commit_sequence > before.commit_sequence);
    f.cx = context(&f.directory.0.join("deployment"))?;
    assert!(matches!(RecordedEvent::open(&f.deployment, &proposal.event().event_id,
        &AnalysisLimits::default(), &mut budget(), &f.cx), Err(RecordedEventError::Unavailable)));
    let resumed = publish(&mut f, &proposal)?;
    assert_eq!(resumed.event().revision, 1);
    let recovered = RecordedEvent::open(&f.deployment, &resumed.event().event_id,
        &AnalysisLimits::default(), &mut budget(), &f.cx)?;
    assert_eq!(recovered.root(), resumed.root());
    Ok(())
}

#[test]
fn an_independent_owner_decision_is_never_overwritten() -> TestResult {
    let mut f = fixture("owner")?;
    let proposal = prepare(&f, false)?;
    let first = publish(&mut f, &proposal)?;
    let mut owned = first.event().clone();
    owned.revision = 2; owned.supersedes = Some(first.event().revision_digest());
    owned.decision_path.policy_generation = ContentDigest::sha256(b"separate operator decision");
    f.deployment.publish_event(&ReferencePolicyDecision { event: owned,
        action: ReferencePolicyAction::Hold }, &f.cx)?;
    let anchor = f.deployment.current_anchor().clone();
    assert!(prepare(&f, true).is_err());
    assert!(proposal.publish(&mut f.deployment, proposal.digest(), &AnalysisLimits::default(),
        &mut budget(), &f.cx).is_err());
    assert_eq!(f.deployment.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn event_provenance_retains_full_report_and_actual_model_receipts() -> TestResult {
    let mut f = fixture("closure")?;
    let proposal = prepare(&f, false)?;
    let published = publish(&mut f, &proposal)?;
    let root = published.event().decision_path.fingerprint;
    let graph = ObjectManifest::from_canonical_bytes(&f.deployment.publisher().spool().read(root)?)?;
    assert!(graph.children().contains(&f.report.digest()));
    for digest in &published.event().model_receipts {
        assert!(graph.children().contains(digest));
        assert!(f.deployment.ledger().batches().iter().flat_map(|b| &b.deltas)
            .any(|d| d.family == "model_invocation_receipt" && d.payload_digest == *digest));
    }
    assert!(f.deployment.ledger().batches().iter().flat_map(|b| &b.deltas)
        .filter(|d| d.family == "event_revision").all(|d| d.plane == Plane::Authority));
    assert!(published.event().evidence.iter().all(|e| e.relation == EvidenceEdgeRelation::DerivedFrom));
    Ok(())
}
