#![forbid(unsafe_code)]

use super::*;
use crate::ingest::recorded_decode::{ComponentInterpretation, DecodeBudget, DecodeLimits};
use crate::ingest::{FileIngestAdapter, FileIngestRequest, RetainedReadLimits};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, Generation, OperationId, SensorId, StreamId, TimestampNs};
use fss_model_ir::{AttributeMap, GraphNode, ModelIrGraph, ModelIrVersion, OpCode, TensorPort};
use fss_tensor::Shape;
use std::fs;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const JPEG: &[u8] = include_bytes!("../../../../fss-codec-mjpeg/tests/fixtures/gray.jpg");

struct Directory(PathBuf);
impl Directory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-inference-{name}-{}-{attempt}",
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
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:model-test".to_owned(),
        operation_id: OperationId::parse("operation:model-test")?,
        principal: "principal:model-test".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(b"site:model-test"),
        generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}
fn fixture(
    name: &str,
) -> TestResult<(
    Directory,
    ReplayCx,
    ReferenceDeployment,
    RecordedDecodeRequest,
    RecordedFrame,
)> {
    let dir = Directory::new(name)?;
    let root = dir.0.join("deployment");
    let path = dir.0.join("source.mjpeg");
    fs::write(&path, [JPEG, JPEG].concat())?;
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, "site:model-test", &cx)?;
    let imported = FileIngestAdapter::ingest(
        FileIngestRequest::new(
            path,
            SensorId::parse("sensor:model-test")?,
            StreamId::parse("stream:model-test")?,
        )
        .with_receive_time(TimestampNs(1_000_000_000)),
        &cx,
        &mut deployment,
    )?;
    let request = RecordedDecodeRequest {
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
    Ok((dir, cx, deployment, request, frame))
}
fn graph(width: usize, height: usize, op: OpCode) -> TestResult<ModelIrGraph> {
    let shape = Shape::new(vec![1, 1, height, width])?;
    Ok(ModelIrGraph::new_validated(
        "model:numeric-fixture",
        ModelIrVersion::V1,
        Generation(3),
        vec![
            TensorPort::new("image", DType::F32, shape.clone(), Generation(3))?,
            TensorPort::new("parameter", DType::F32, Shape::new(vec![1])?, Generation(3))?,
        ],
        vec![TensorPort::new("result", DType::F32, shape, Generation(3))?],
        vec![GraphNode::new(
            "node:0",
            op,
            "numeric fixture, not trained detector",
            vec!["image".to_owned(), "parameter".to_owned()],
            vec!["result".to_owned()],
            AttributeMap::new(),
        )?],
    )?)
}
fn model(frame: &RecordedFrame, value: f32, scale: bool) -> TestResult<RecordedModel> {
    let [w, h] = frame.receipt().dimensions();
    Ok(RecordedModel::publish(
        &graph(w as usize, h as usize, OpCode::Add)?,
        "image",
        scale,
        BTreeMap::from([("parameter".to_owned(), vec![value])]),
    )?)
}
fn budget() -> ExecBudget {
    ExecBudget::new(100_000_000, 64 * 1024 * 1024)
}

#[test]
fn model_roundtrip_pins_weights_and_preprocessing() -> TestResult {
    let g = graph(8, 8, OpCode::Add)?;
    let a = RecordedModel::publish(
        &g,
        "image",
        true,
        BTreeMap::from([("parameter".to_owned(), vec![0.25])]),
    )?;
    let b = RecordedModel::publish(
        &g,
        "image",
        true,
        BTreeMap::from([("parameter".to_owned(), vec![0.5])]),
    )?;
    let c = RecordedModel::publish(
        &g,
        "image",
        false,
        BTreeMap::from([("parameter".to_owned(), vec![0.25])]),
    )?;
    assert_ne!(a.digest(), b.digest());
    assert_ne!(a.digest(), c.digest());
    let decoded = RecordedModel::decode(a.encoded(), a.digest())?;
    assert_eq!(decoded.encoded(), a.encoded());
    assert_eq!(decoded.graph().generation(), Generation(3));
    assert!(RecordedModel::decode(a.encoded(), b.digest()).is_err());
    Ok(())
}

#[test]
fn missing_extra_nonfinite_and_wrong_count_parameters_are_refused() -> TestResult {
    let g = graph(8, 8, OpCode::Add)?;
    for parameters in [
        BTreeMap::new(),
        BTreeMap::from([("other".to_owned(), vec![1.0])]),
        BTreeMap::from([("parameter".to_owned(), vec![f32::NAN])]),
        BTreeMap::from([("parameter".to_owned(), vec![1.0, 2.0])]),
    ] {
        assert!(RecordedModel::publish(&g, "image", true, parameters).is_err());
    }
    Ok(())
}

#[test]
fn model_parser_rejects_every_prefix_and_appended_bytes() -> TestResult {
    let g = graph(8, 8, OpCode::Add)?;
    let m = RecordedModel::publish(
        &g,
        "image",
        true,
        BTreeMap::from([("parameter".to_owned(), vec![1.0])]),
    )?;
    for n in 0..m.encoded().len() {
        let bytes = &m.encoded()[..n];
        assert!(RecordedModel::decode(bytes, ContentDigest::sha256(bytes)).is_err());
    }
    let mut bytes = m.encoded().to_vec();
    bytes.push(0);
    assert!(RecordedModel::decode(&bytes, ContentDigest::sha256(&bytes)).is_err());
    Ok(())
}

#[test]
fn real_numeric_execution_is_retained_and_reopens_without_source_or_model_file() -> TestResult {
    let (dir, cx, mut deployment, request, frame) = fixture("restart")?;
    let m = model(&frame, 0.25, true)?;
    let run = RecordedInference::run_and_publish(
        &mut deployment,
        &request,
        &m,
        budget(),
        &ScalarExecCx::new(),
        &cx,
    )?;
    let actual = run.outputs().get("result").ok_or(ModelRunError::Mismatch)?;
    let expected: Vec<_> = frame
        .pixels()
        .iter()
        .map(|&p| f32::from(p) * (1.0_f32 / 255.0) + 0.25)
        .collect();
    assert_eq!(*actual, expected);
    assert_eq!(run.executed_macs(), actual.len() as u64);
    assert_eq!(run.frame_root(), frame.publication_root());
    assert!(run.authority_anchor().commit_sequence > frame.authority_anchor().commit_sequence);
    let identity = run.identity();
    let final_anchor = deployment.current_anchor().clone();
    fs::remove_file(dir.0.join("source.mjpeg"))?;
    drop(deployment);
    drop(m);
    let reopened = ReferenceDeployment::open(&dir.0.join("deployment"), "site:model-test", &cx)?;
    let restored = RecordedInference::open(&reopened, identity, &request, &cx)?;
    assert_eq!(restored.output_bytes(), run.output_bytes());
    restored.verify_by_replay(&reopened, &request, budget(), &ScalarExecCx::new(), &cx)?;
    assert_eq!(*reopened.current_anchor(), final_anchor);
    assert!(
        reopened
            .ledger()
            .batches()
            .iter()
            .flat_map(|b| &b.deltas)
            .filter(|d| d.family == "model_invocation_receipt")
            .all(|d| d.plane == Plane::Cognition)
    );
    Ok(())
}

#[test]
fn exact_successful_retries_do_not_duplicate_authority() -> TestResult {
    let (_dir, cx, mut deployment, request, frame) = fixture("retry")?;
    let m = model(&frame, 0.5, false)?;
    let first = RecordedInference::run_and_publish(
        &mut deployment,
        &request,
        &m,
        budget(),
        &ScalarExecCx::new(),
        &cx,
    )?;
    let anchor = deployment.current_anchor().clone();
    let second = RecordedInference::run_and_publish(
        &mut deployment,
        &request,
        &m,
        budget(),
        &ScalarExecCx::new(),
        &cx,
    )?;
    assert_eq!(first.identity(), second.identity());
    assert_eq!(first.receipt_bytes()?, second.receipt_bytes()?);
    assert_eq!(*deployment.current_anchor(), anchor);
    Ok(())
}

#[test]
fn exhausted_budgets_and_dimension_mismatch_publish_no_model_results() -> TestResult {
    let (_dir, cx, mut deployment, request, frame) = fixture("bounds")?;
    let m = model(&frame, 0.5, true)?;
    let before = deployment.current_anchor().clone();
    for limits in [
        ExecBudget::new(0, 64 * 1024 * 1024),
        ExecBudget::new(1_000_000, 1),
    ] {
        assert!(
            RecordedInference::run_and_publish(
                &mut deployment,
                &request,
                &m,
                limits,
                &ScalarExecCx::new(),
                &cx
            )
            .is_err()
        );
    }
    let wrong = RecordedModel::publish(
        &graph(1, 1, OpCode::Add)?,
        "image",
        true,
        BTreeMap::from([("parameter".to_owned(), vec![1.0])]),
    )?;
    assert!(
        RecordedInference::run_and_publish(
            &mut deployment,
            &request,
            &wrong,
            budget(),
            &ScalarExecCx::new(),
            &cx
        )
        .is_err()
    );
    assert_eq!(*deployment.current_anchor(), before);
    Ok(())
}

#[test]
fn nonfinite_results_and_executor_cancellation_are_not_published() -> TestResult {
    let (_dir, cx, mut deployment, request, frame) = fixture("nonfinite")?;
    let [w, h] = frame.receipt().dimensions();
    let m = RecordedModel::publish(
        &graph(w as usize, h as usize, OpCode::Div)?,
        "image",
        false,
        BTreeMap::from([("parameter".to_owned(), vec![0.0])]),
    )?;
    let before = deployment.current_anchor().clone();
    assert!(
        RecordedInference::run_and_publish(
            &mut deployment,
            &request,
            &m,
            budget(),
            &ScalarExecCx::new(),
            &cx
        )
        .is_err()
    );
    let exec = ScalarExecCx::new();
    exec.request_cancellation();
    assert!(
        RecordedInference::run_and_publish(
            &mut deployment,
            &request,
            &model(&frame, 1.0, true)?,
            budget(),
            &exec,
            &cx
        )
        .is_err()
    );
    assert_eq!(*deployment.current_anchor(), before);
    Ok(())
}

#[test]
fn interrupted_final_publication_is_not_complete_and_exact_retry_resumes() -> TestResult {
    let (dir, cx, mut deployment, request, frame) = fixture("interrupted")?;
    let m = model(&frame, 1.0, true)?;
    let (receipt, _, _) = execute(&frame, &m, budget(), &ScalarExecCx::new())?;
    cx.set_cancel_at_checkpoint(STAGE_INFERENCE_COMMIT);
    assert!(
        RecordedInference::run_and_publish(
            &mut deployment,
            &request,
            &m,
            budget(),
            &ScalarExecCx::new(),
            &cx
        )
        .is_err()
    );
    let fresh = context(&dir.0.join("deployment"))?;
    assert!(matches!(
        RecordedInference::open(&deployment, receipt.identity(), &request, &fresh),
        Err(ModelRunError::Unavailable)
    ));
    let finished = RecordedInference::run_and_publish(
        &mut deployment,
        &request,
        &m,
        budget(),
        &ScalarExecCx::new(),
        &fresh,
    )?;
    assert_eq!(finished.identity(), receipt.identity());
    finished.verify_by_replay(
        &deployment,
        &request,
        budget(),
        &ScalarExecCx::new(),
        &fresh,
    )?;
    Ok(())
}

#[test]
fn run_identity_cannot_rebind_identical_pixels_to_another_capsule() -> TestResult {
    let (_dir, cx, mut deployment, request, frame) = fixture("source-binding")?;
    let m = model(&frame, 1.0, true)?;
    let first = RecordedInference::run_and_publish(
        &mut deployment,
        &request,
        &m,
        budget(),
        &ScalarExecCx::new(),
        &cx,
    )?;
    let mut other = request.clone();
    other.segment_index = 1;
    RecordedFrame::decode_and_publish(
        &mut deployment,
        &other,
        &mut DecodeBudget::new(100_000_000),
        &cx,
    )?;
    assert!(RecordedInference::open(&deployment, first.identity(), &other, &cx).is_err());
    let second = RecordedInference::run_and_publish(
        &mut deployment,
        &other,
        &m,
        budget(),
        &ScalarExecCx::new(),
        &cx,
    )?;
    assert_ne!(first.identity(), second.identity());
    assert_eq!(first.output_bytes(), second.output_bytes());
    Ok(())
}

#[test]
fn receipt_truncation_and_wrong_tensor_shape_fail_closed() -> TestResult {
    let (_dir, _cx, _deployment, _request, frame) = fixture("receipts")?;
    let m = model(&frame, 1.0, true)?;
    let (receipt, _, output) = execute(&frame, &m, budget(), &ScalarExecCx::new())?;
    let bytes = receipt.encoded()?;
    for end in 0..bytes.len() {
        assert!(Receipt::decode(&bytes[..end], ContentDigest::sha256(&bytes[..end])).is_err());
    }
    let wrong = RecordedModel::publish(
        &graph(1, 1, OpCode::Add)?,
        "image",
        true,
        BTreeMap::from([("parameter".to_owned(), vec![1.0])]),
    )?;
    assert!(decode_outputs(&output, &wrong).is_err());
    let mut suffix = output;
    suffix.push(0);
    assert!(decode_outputs(&suffix, &m).is_err());
    Ok(())
}
