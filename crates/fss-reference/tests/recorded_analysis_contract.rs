#![forbid(unsafe_code)]
//! An authored arithmetic model exercises retained recording -> inference -> detector ->
//! association -> restart verification. This fixture makes no trained-model quality claim.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use fss_core::{BudgetVector, ContentDigest, Generation, OperationId, SensorId, StreamId, TimestampNs};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_model_ir::{AttrValue, AttributeMap, GraphNode, ModelIrGraph, ModelIrVersion, OpCode, TensorPort};
use fss_tensor::{DType, Shape};
use fss_reference::{ExecBudget, ReferenceDeployment, ReplayCx, ScalarExecCx};
use fss_reference::ingest::{FileIngestAdapter, FileIngestRequest, RetainedReadLimits};
use fss_reference::ingest::recorded_decode::{ComponentInterpretation, DecodeBudget, DecodeLimits, RecordedDecodeRequest, RecordedFrame};
use fss_reference::ingest::inference::{RecordedInference, RecordedModel};
use fss_reference::ingest::detections::{BoxEncoding, CoordinateSpace, DetectionSpec};
use fss_reference::ingest::tracking::{TrackReset, TrackingConfig};
use fss_reference::ingest::analysis::{AnalysisBudget, AnalysisError, AnalysisFrame, AnalysisLimits, AnalysisPlan, AnalysisReport};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const JPEG: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
struct Directory(PathBuf);
impl Directory {
    fn new() -> TestResult<Self> {
        for n in 0..100 {
            let path = std::env::temp_dir().join(format!("fss-analysis-{}-{n}", std::process::id()));
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
fn detector_model(width: u32, height: u32) -> TestResult<RecordedModel> {
    let pixels = width as usize * height as usize;
    let generation = Generation(3);
    let port = |name: &str, shape: Vec<usize>| -> TestResult<TensorPort> {
        Ok(TensorPort::new(name, DType::F32, Shape::new(shape)?, generation)?)
    };
    let node = |id: &str, op, inputs: &[&str], output: &str, attrs| -> TestResult<GraphNode> {
        Ok(GraphNode::new(id, op, id, inputs.iter().map(|s| s.to_string()).collect(), vec![output.into()], attrs)?)
    };
    let graph = ModelIrGraph::new_validated("model:analysis-fixture", ModelIrVersion::V1, generation,
        vec![port("image",vec![1,1,height as usize,width as usize])?,
            port("weights",vec![pixels,6])?, port("bias",vec![1,6])?],
        vec![port("detections",vec![1,6])?],
        vec![node("flatten",OpCode::Reshape,&["image"],"flat",
                BTreeMap::from([("shape".into(),AttrValue::IntList(vec![1,pixels as i64]))]))?,
            node("multiply",OpCode::MatMul,&["flat","weights"],"zero",AttributeMap::new())?,
            node("add",OpCode::Add,&["zero","bias"],"detections",AttributeMap::new())?])?;
    Ok(RecordedModel::publish(&graph,"image",true,BTreeMap::from([
        ("weights".into(),vec![0.0;pixels*6]),
        ("bias".into(),vec![0.125,0.125,0.5,0.5,0.9,0.]),
    ]))?)
}
fn spec(model: &RecordedModel) -> DetectionSpec {
    DetectionSpec { model_digest:model.digest(), output_port:"detections".into(),
        labels:vec!["vehicle".into()], encoding:BoxEncoding::Xyxy,
        coordinates:CoordinateSpace::Normalized, minimum_score_ppm:500_000, nms_iou_ppm:500_000,
        maximum_rows:4096, maximum_detections:128 }
}
fn tracking() -> TrackingConfig {
    TrackingConfig { minimum_iou_ppm:100_000, confirmation_hits:2, maximum_missed_frames:1, maximum_tracks:128 }
}
#[test]
fn retained_sequence_rebuilds_after_restart_and_rejects_forged_reports() -> TestResult {
    let dir = Directory::new()?;
    let root = dir.0.join("deployment");
    let source = dir.0.join("source.mjpeg");
    fs::write(&source,[JPEG,JPEG,JPEG].concat())?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id:"trace:analysis-test".into(), operation_id:OperationId::parse("operation:analysis-test")?,
        principal:"principal:analysis-test".into(), capabilities:vec!["ADP-REPLAY-001".into()],
        deadline:None,priority:10,budgets:BudgetVector::builder().bytes(64*1024*1024).build()?,
        privacy_scope:"privacy:test".into(),retention_scope:"retention:test".into(),
        anchor_universe:ContentDigest::sha256(b"site:analysis-test"),generation:1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority,root.clone())?;
    let mut deployment = ReferenceDeployment::open(&root,"site:analysis-test",&cx)?;
    let imported = FileIngestAdapter::ingest(FileIngestRequest::new(&source,
        SensorId::parse("sensor:analysis-test")?,StreamId::parse("stream:analysis-test")?)
        .with_receive_time(TimestampNs(1_000_000_000)),&cx,&mut deployment)?;
    let mut request = RecordedDecodeRequest { import_identity:imported.import_identity,segment_index:0,
        interpretation:ComponentInterpretation::Grayscale,read_limits:RetainedReadLimits::default(),decode_limits:DecodeLimits::default() };
    let first = RecordedFrame::decode_and_publish(&mut deployment,&request,&mut DecodeBudget::new(100_000_000),&cx)?;
    let [w,h] = first.receipt().dimensions();
    let model = detector_model(w,h)?;
    let mut selections = Vec::new();
    for segment_index in 0..3 {
        request.segment_index = segment_index;
        RecordedFrame::decode_and_publish(&mut deployment,&request,&mut DecodeBudget::new(100_000_000),&cx)?;
        let run = RecordedInference::run_and_publish(&mut deployment,&request,&model,
            ExecBudget::new(100_000_000,64*1024*1024),&ScalarExecCx::new(),&cx)?;
        selections.push(AnalysisFrame { segment_index, run_identity:run.identity() });
    }
    let plan = AnalysisPlan::new(imported.import_identity,ComponentInterpretation::Grayscale,
        spec(&model),tracking(),selections.clone())?;
    let limits = AnalysisLimits::default();
    let before = deployment.current_anchor().clone();
    let mut budget = AnalysisBudget::new(100,10_000);
    let report = AnalysisReport::read(&deployment,&plan,&limits,&mut budget,&cx)?;
    assert_eq!(report.observations().len(),3);
    let observations = report.observations();
    assert_eq!(observations[0].tracking().tracks.len(),1);
    let id = observations[0].tracking().tracks[0].id;
    for observation in observations {
        assert_eq!(observation.tracking().tracks[0].id,id);
        assert_eq!(observation.detection().capsule(),&observation.tracking().capsule);
    }
    assert!(observations[2].tracking().tracks[0].confirmed);
    assert_eq!(observations[2].tracking().tracks[0].observations,3);
    assert_eq!(observations[2].tracking().predecessor,Some(observations[1].tracking().digest()?));
    assert_eq!(budget.detection.used(),3);
    assert!(budget.association.used() > 0);
    assert_eq!(*deployment.current_anchor(),before);

    let gap = AnalysisPlan::new(imported.import_identity,ComponentInterpretation::Grayscale,
        spec(&model),tracking(),vec![selections[0],selections[2]])?;
    let gap_report = AnalysisReport::read(&deployment,&gap,&limits,&mut AnalysisBudget::new(100,10_000),&cx)?;
    assert!(gap_report.observations()[1].tracking().resets.contains(&TrackReset::SequenceGap));
    assert_eq!(gap_report.observations()[1].tracking().retired[0].id,id);
    assert_ne!(gap_report.observations()[1].tracking().tracks[0].id,id);

    let mut duplicates = selections.clone(); duplicates[1].segment_index = 0;
    assert!(AnalysisPlan::new(imported.import_identity,ComponentInterpretation::Grayscale,
        spec(&model),tracking(),duplicates).is_err());
    let mut wrong = selections.clone(); wrong[1].run_identity = wrong[0].run_identity;
    let rebound = AnalysisPlan::new(imported.import_identity,ComponentInterpretation::Grayscale,
        spec(&model),tracking(),wrong)?;
    assert!(AnalysisReport::read(&deployment,&rebound,&limits,&mut AnalysisBudget::new(100,10_000),&cx).is_err());

    let mut exhausted = AnalysisBudget::new(100,0);
    assert!(AnalysisReport::read(&deployment,&plan,&limits,&mut exhausted,&cx).is_err());
    assert!(exhausted.detection.used() >= 2); // Failed work is not refunded.
    assert!(matches!(AnalysisReport::read(&deployment,&plan,
        &AnalysisLimits { maximum_frames:2,..limits.clone() },&mut AnalysisBudget::new(100,10_000),&cx),Err(AnalysisError::Limit)));
    assert!(matches!(AnalysisReport::read(&deployment,&plan,
        &AnalysisLimits { maximum_report_bytes:plan.encoded().len(),..limits.clone() },
        &mut AnalysisBudget::new(100,10_000),&cx),Err(AnalysisError::Limit)));

    fs::remove_file(&source)?;
    drop(deployment);
    let reopened = ReferenceDeployment::open(&root,"site:analysis-test",&cx)?;
    let restored = AnalysisReport::verify(&reopened,report.encoded(),report.digest(),&limits,
        &mut AnalysisBudget::new(100,10_000),&cx)?;
    assert_eq!(restored.encoded(),report.encoded());
    assert_eq!(*reopened.current_anchor(),before);
    let mut forged = report.encoded().to_vec();
    let end = forged.len()-1; forged[end] ^= 1;
    assert!(matches!(AnalysisReport::verify(&reopened,&forged,ContentDigest::sha256(&forged),&limits,
        &mut AnalysisBudget::new(100,10_000),&cx),Err(AnalysisError::Mismatch)));
    cx.request_cancellation();
    assert!(matches!(AnalysisReport::read(&reopened,&plan,&limits,&mut AnalysisBudget::new(100,10_000),&cx),Err(AnalysisError::Cancelled)));
    Ok(())
}
