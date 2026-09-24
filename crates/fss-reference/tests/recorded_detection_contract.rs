#![forbid(unsafe_code)]
//! Real retained-inference-to-detection regression. The graph is authored arithmetic,
//! not a trained detector; it exists to verify wiring, provenance, and restart behavior.

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, ContentDigest, Generation, OperationId, SensorId, StreamId, TimestampNs,
};
use fss_model_ir::{
    AttrValue, AttributeMap, GraphNode, ModelIrGraph, ModelIrVersion, OpCode, TensorPort,
};
use fss_reference::ingest::detections::{
    BoxEncoding, CoordinateSpace, DetectionBudget, DetectionContract, DetectionError,
    DetectionFrame, DetectionSpec,
};
use fss_reference::ingest::inference::{RecordedInference, RecordedModel};
use fss_reference::ingest::recorded_decode::{
    ComponentInterpretation, DecodeBudget, DecodeLimits, RecordedDecodeRequest, RecordedFrame,
};
use fss_reference::ingest::{FileIngestAdapter, FileIngestRequest, RetainedReadLimits};
use fss_reference::{ExecBudget, ReferenceDeployment, ReplayCx, ScalarExecCx};
use fss_tensor::{DType, Shape};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const JPEG: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
struct Directory(PathBuf);
impl Directory {
    fn new() -> TestResult<Self> {
        for n in 0..100 {
            let path =
                std::env::temp_dir().join(format!("fss-detections-{}-{n}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn detector_model(width: u32, height: u32) -> TestResult<RecordedModel> {
    let pixels = width as usize * height as usize;
    let generation = Generation(3);
    let port = |name: &str, shape: Vec<usize>| -> TestResult<TensorPort> {
        Ok(TensorPort::new(
            name,
            DType::F32,
            Shape::new(shape)?,
            generation,
        )?)
    };
    let node = |id: &str, op, inputs: &[&str], output: &str, attrs| -> TestResult<GraphNode> {
        Ok(GraphNode::new(
            id,
            op,
            id,
            inputs.iter().map(|s| s.to_string()).collect(),
            vec![output.into()],
            attrs,
        )?)
    };
    let graph = ModelIrGraph::new_validated(
        "model:detector-row-fixture",
        ModelIrVersion::V1,
        generation,
        vec![
            port("image", vec![1, 1, height as usize, width as usize])?,
            port("weights", vec![pixels, 18])?,
            port("bias", vec![1, 18])?,
        ],
        vec![port("detections", vec![3, 6])?],
        vec![
            node(
                "flatten",
                OpCode::Reshape,
                &["image"],
                "flat",
                BTreeMap::from([("shape".into(), AttrValue::IntList(vec![1, pixels as i64]))]),
            )?,
            node(
                "multiply",
                OpCode::MatMul,
                &["flat", "weights"],
                "zero",
                AttributeMap::new(),
            )?,
            node(
                "add",
                OpCode::Add,
                &["zero", "bias"],
                "rows",
                AttributeMap::new(),
            )?,
            node(
                "reshape",
                OpCode::Reshape,
                &["rows"],
                "detections",
                BTreeMap::from([("shape".into(), AttrValue::IntList(vec![3, 6]))]),
            )?,
        ],
    )?;
    Ok(RecordedModel::publish(
        &graph,
        "image",
        true,
        BTreeMap::from([
            ("weights".into(), vec![0.0; pixels * 18]),
            (
                "bias".into(),
                vec![
                    0.125, 0.125, 0.5, 0.5, 0.9, 0., 0.125, 0.125, 0.5, 0.5, 0.8, 0., 0.125, 0.125,
                    0.5, 0.5, 0.7, 1.,
                ],
            ),
        ]),
    )?)
}
fn spec(model: &RecordedModel) -> DetectionSpec {
    DetectionSpec {
        model_digest: model.digest(),
        output_port: "detections".into(),
        labels: vec!["vehicle".into(), "animal".into()],
        encoding: BoxEncoding::Xyxy,
        coordinates: CoordinateSpace::Normalized,
        minimum_score_ppm: 500_000,
        nms_iou_ppm: 500_000,
        maximum_rows: 4096,
        maximum_detections: 256,
    }
}
#[test]
fn retained_model_detections_reopen_without_source_or_model_files() -> TestResult {
    let dir = Directory::new()?;
    let root = dir.0.join("deployment");
    let source = dir.0.join("source.mjpeg");
    fs::write(&source, [JPEG, JPEG].concat())?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:detection-test".into(),
        operation_id: OperationId::parse("operation:detection-test")?,
        principal: "principal:detection-test".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"site:detection-test"),
        generation: 1,
    })?;
    authority.validate()?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
    let mut deployment = ReferenceDeployment::open(&root, "site:detection-test", &cx)?;
    let imported = FileIngestAdapter::ingest(
        FileIngestRequest::new(
            &source,
            SensorId::parse("sensor:detection-test")?,
            StreamId::parse("stream:detection-test")?,
        )
        .with_receive_time(TimestampNs(1_000_000_000)),
        &cx,
        &mut deployment,
    )?;
    let mut request = RecordedDecodeRequest {
        import_identity: imported.import_identity,
        segment_index: 0,
        interpretation: ComponentInterpretation::Grayscale,
        read_limits: RetainedReadLimits::default(),
        decode_limits: DecodeLimits::default(),
    };
    let frame = RecordedFrame::decode_and_publish(
        &mut deployment,
        &request,
        &mut DecodeBudget::new(100_000_000),
        &cx,
    )?;
    let [w, h] = frame.receipt().dimensions();
    let model = detector_model(w, h)?;
    let run = RecordedInference::run_and_publish(
        &mut deployment,
        &request,
        &model,
        ExecBudget::new(100_000_000, 64 * 1024 * 1024),
        &ScalarExecCx::new(),
        &cx,
    )?;
    let contract = DetectionContract::new(spec(&model))?;
    let before = deployment.current_anchor().clone();
    let mut budget = DetectionBudget::new(100);
    let first = DetectionFrame::read(
        &deployment,
        run.identity(),
        &request,
        &contract,
        &mut budget,
        &cx,
    )?;
    assert_eq!(first.counts(), [3, 0, 1]);
    assert_eq!(first.detections().len(), 2);
    assert_eq!(first.run_identity(), run.identity());
    assert_eq!(first.frame_root(), frame.publication_root());
    assert_eq!(first.capsule(), frame.receipt().capsule());
    assert_eq!(*deployment.current_anchor(), before);
    assert!(matches!(
        DetectionFrame::read(
            &deployment,
            run.identity(),
            &request,
            &contract,
            &mut DetectionBudget::new(0),
            &cx
        ),
        Err(DetectionError::BudgetExceeded)
    ));
    let mut wrong = spec(&model);
    wrong.model_digest = ContentDigest::sha256(b"different weights");
    assert!(matches!(
        DetectionFrame::read(
            &deployment,
            run.identity(),
            &request,
            &DetectionContract::new(wrong)?,
            &mut budget,
            &cx
        ),
        Err(DetectionError::InvalidContract)
    ));
    request.segment_index = 1;
    RecordedFrame::decode_and_publish(
        &mut deployment,
        &request,
        &mut DecodeBudget::new(100_000_000),
        &cx,
    )?;
    assert!(
        DetectionFrame::read(
            &deployment,
            run.identity(),
            &request,
            &contract,
            &mut budget,
            &cx
        )
        .is_err()
    );
    request.segment_index = 0;
    let after = deployment.current_anchor().clone();
    fs::remove_file(&source)?;
    drop(deployment);
    let reopened = ReferenceDeployment::open(&root, "site:detection-test", &cx)?;
    let restored = DetectionFrame::read(
        &reopened,
        run.identity(),
        &request,
        &contract,
        &mut budget,
        &cx,
    )?;
    assert_eq!(first.encoded()?, restored.encoded()?);
    assert_eq!(first.digest()?, restored.digest()?);
    assert_eq!(*reopened.current_anchor(), after);
    cx.request_cancellation();
    assert!(matches!(
        DetectionFrame::read(
            &reopened,
            run.identity(),
            &request,
            &contract,
            &mut budget,
            &cx
        ),
        Err(DetectionError::Cancelled)
    ));
    Ok(())
}
