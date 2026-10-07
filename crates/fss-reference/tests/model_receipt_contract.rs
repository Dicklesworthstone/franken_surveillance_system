#![forbid(unsafe_code)]
//! Emitted model invocation receipts (fss-2h5zq.47 / fss-2h5zq.48).
//!
//! One receipt per reachable outcome (ok, error, budget_exhausted, cancelled), plus the
//! package-backed activity receipt. Each receipt's emitted JSON must equal the committed fixture
//! under `tests/fixtures/model_receipts/`. `tests/test_json_instance_validate.py` validates those
//! same bytes against `schemas/model_execution_receipt.v1.json`, so the schema check runs on what
//! Rust actually emits, not on hand-written dictionaries. The operator trace chain is recomputed
//! here independently of the receipt code.

use std::error::Error;

use fss_codec_mjpeg::ComponentInterpretation;
use fss_codec_mjpeg::DecodeBudget;
use fss_codec_mjpeg::color::{DecodedRgb, RgbDecodeLimits, decode_rgb};
use fss_core::{CanonicalEncoder, ContentDigest, Generation, SensorId, TimestampNs};
use fss_model_ir::{AttributeMap, GraphNode, ModelIrGraph, OpCode, TensorPort};
use fss_reference::executor_activity::{
    ActivityExecutorModel, ActivityFrameBinding, ActivityThresholdPolicy,
};
use fss_reference::model_receipt::{
    ModelInvocationReceipt, ReceiptDigest, ReceiptOutcome, ReceiptRecordContext,
    execute_and_record_receipt,
};
use fss_reference::{ExecBudget, ScalarExecCx, VirtualClock};
use fss_tensor::{DType, Shape, Tensor};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const BACKGROUND: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/background.jpg");
const GRADIENT: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");

const FIXTURES: [(&str, &str); 5] = [
    (
        "ok",
        include_str!("../../../tests/fixtures/model_receipts/ok.json"),
    ),
    (
        "error",
        include_str!("../../../tests/fixtures/model_receipts/error.json"),
    ),
    (
        "budget_exhausted",
        include_str!("../../../tests/fixtures/model_receipts/budget_exhausted.json"),
    ),
    (
        "cancelled",
        include_str!("../../../tests/fixtures/model_receipts/cancelled.json"),
    ),
    (
        "activity_package",
        include_str!("../../../tests/fixtures/model_receipts/activity_package.json"),
    ),
];

fn g() -> Generation {
    Generation::from_u64(1)
}

fn relu_graph(dtype: DType) -> TestResult<ModelIrGraph> {
    Ok(ModelIrGraph::builder("receipt_contract_relu", g())
        .add_input(TensorPort::new("x", dtype, Shape::new(vec![1, 3])?, g())?)
        .add_output(TensorPort::new("y", dtype, Shape::new(vec![1, 3])?, g())?)
        .add_node(GraphNode::new(
            "relu_1",
            OpCode::Relu,
            "relu",
            vec!["x".into()],
            vec!["y".into()],
            AttributeMap::new(),
        )?)
        .build_and_validate()?)
}

fn context(job_id: &str) -> ReceiptRecordContext<'_> {
    ReceiptRecordContext {
        job_id,
        preprocess_program: None,
        model_package_root: None,
        virtual_clock: None,
        source_roots: &[],
        preprocess_resize: None,
    }
}

fn relu_input() -> TestResult<Vec<(&'static str, Tensor)>> {
    Ok(vec![(
        "x",
        Tensor::from_values(Shape::new(vec![1, 3])?, &[-1.5_f32, 0.0, 2.5], g())?,
    )])
}

fn decode(bytes: &[u8]) -> TestResult<DecodedRgb> {
    Ok(decode_rgb(
        bytes,
        ContentDigest::sha256(bytes).bytes(),
        ComponentInterpretation::Grayscale,
        RgbDecodeLimits::default(),
        &mut DecodeBudget::new(10_000_000),
    )?)
}

fn bind<'a>(bytes: &[u8], decoded: &'a DecodedRgb) -> ActivityFrameBinding<'a> {
    ActivityFrameBinding {
        pixels: decoded.pixels(),
        receipt: decoded.receipt(),
        source_digest: ContentDigest::sha256(bytes),
        capsule_digest: ContentDigest::sha256(bytes),
    }
}

/// Every case's receipt and the graph it ran (for the trace recomputation).
fn receipts() -> TestResult<Vec<(&'static str, ModelInvocationReceipt)>> {
    let mut out = Vec::new();
    let clock = VirtualClock::new(0, TimestampNs(50_000));
    let graph = relu_graph(DType::F32)?;
    let mut ok_context = context("job:receipt-contract:ok");
    ok_context.virtual_clock = Some(&clock);
    let (run, ok) = execute_and_record_receipt(
        &graph,
        &relu_input()?,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
        ok_context,
    );
    run?;
    out.push(("ok", ok));

    // F16 passes IR validation but the scalar executor admits only F32: a typed error.
    let (run, error) = execute_and_record_receipt(
        &relu_graph(DType::F16)?,
        &relu_input()?,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
        context("job:receipt-contract:error"),
    );
    assert!(run.is_err());
    out.push(("error", error));

    let (run, budget) = execute_and_record_receipt(
        &graph,
        &relu_input()?,
        ExecBudget::new(1, 1),
        &ScalarExecCx::new(),
        context("job:receipt-contract:budget"),
    );
    assert!(run.is_err());
    out.push(("budget_exhausted", budget));

    let cancelled_cx = ScalarExecCx::new();
    cancelled_cx.request_cancellation();
    let (run, cancelled) = execute_and_record_receipt(
        &graph,
        &relu_input()?,
        ExecBudget::unlimited(),
        &cancelled_cx,
        context("job:receipt-contract:cancelled"),
    );
    assert!(run.is_err());
    out.push(("cancelled", cancelled));

    let model = ActivityExecutorModel::load_committed(&ScalarExecCx::new())?;
    let frame = decode(GRADIENT)?;
    let reference = decode(BACKGROUND)?;
    let (_, activity) = model.invoke(
        &SensorId::parse("sensor:file-cam")?,
        bind(GRADIENT, &frame),
        bind(BACKGROUND, &reference),
        &ActivityThresholdPolicy::reference()?,
        ExecBudget::new(10_000_000, 16 * 1024 * 1024),
        "job:receipt-contract:activity",
        &ScalarExecCx::new(),
    )?;
    out.push(("activity_package", activity));
    Ok(out)
}

#[test]
fn emitted_receipts_match_the_schema_validated_fixtures() -> TestResult {
    let receipts = receipts()?;
    assert_eq!(receipts.len(), FIXTURES.len());
    let mut drift = Vec::new();
    for ((name, receipt), (fixture_name, fixture)) in receipts.iter().zip(FIXTURES) {
        assert_eq!(*name, fixture_name);
        let json = receipt.to_json_canonical();
        let outcome = receipt.outcome.as_str();
        println!(
            "CAPLOG {{\"bead\":\"fss-2h5zq.48\",\"step\":\"receipt\",\"case\":\"{name}\",\"outcome\":\"{outcome}\",\"receipt_digest\":\"{}\",\"json_sha256\":\"{}\"}}",
            receipt.compute_canonical_digest(),
            ContentDigest::sha256(json.as_bytes())
        );
        if json != fixture.trim_end_matches('\n') {
            println!("RECEIPT_FIXTURE_DRIFT {name} {json}");
            drift.push(*name);
        }
        receipt.verify(receipt.generation, &receipt.compute_canonical_digest())?;
    }
    assert!(drift.is_empty(), "receipt JSON drifted for {drift:?}");
    // Each reachable outcome is covered exactly once by the outcome-only cases.
    let outcomes: Vec<_> = receipts.iter().map(|(_, r)| r.outcome).collect();
    for expected in [
        ReceiptOutcome::Ok,
        ReceiptOutcome::Error,
        ReceiptOutcome::BudgetExhausted,
        ReceiptOutcome::Cancelled,
    ] {
        assert!(outcomes.contains(&expected));
    }
    Ok(())
}

#[test]
fn receipts_are_deterministic_and_sentinels_never_parse_as_content() -> TestResult {
    let first = receipts()?;
    let second = receipts()?;
    for ((_, a), (_, b)) in first.iter().zip(&second) {
        assert_eq!(a, b);
        assert_eq!(a.to_json_canonical(), b.to_json_canonical());
        assert_eq!(a.usage.wall_ns, b.usage.wall_ns);
    }
    for (name, receipt) in &first {
        let mut digests: Vec<&ReceiptDigest> = receipt.input_roots.iter().collect();
        digests.extend([
            &receipt.model_package_root,
            &receipt.activation_generation,
            &receipt.preprocess_program,
            &receipt.postprocess_program,
            &receipt.operator_registry_generation,
            &receipt.execution_plan_digest,
            &receipt.numeric_policy_digest,
            &receipt.decision_path_digest,
        ]);
        for digest in digests {
            let text = digest.to_text();
            match digest {
                ReceiptDigest::Content(content) => {
                    assert_eq!(ContentDigest::parse(&text)?, *content, "{name}");
                }
                ReceiptDigest::NotApplicable { .. } => {
                    assert!(text.starts_with("fss-na:"), "{name}");
                    assert!(ContentDigest::parse(&text).is_err(), "{name}");
                }
            }
        }
        assert!(receipt.activation_generation.is_not_applicable());
        assert!(receipt.is_reference_only());
    }
    // Only the package-backed receipt names a real package root.
    for (name, receipt) in &first {
        assert_eq!(
            receipt.model_package_root.is_content(),
            *name == "activity_package",
            "{name}"
        );
    }
    Ok(())
}

#[test]
fn operator_trace_chain_recomputes_independently() -> TestResult {
    let graph = relu_graph(DType::F32)?;
    let (run, receipt) = execute_and_record_receipt(
        &graph,
        &relu_input()?,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
        context("job:receipt-contract:trace"),
    );
    let outcome = run?;
    // seed = sha256(tag); link = sha256(prev || id || opcode || first output tensor digest).
    let mut current = ContentDigest::sha256(b"fss.model_execution_receipt.v1/operator_trace");
    for node in graph.nodes() {
        let mut encoder = CanonicalEncoder::new();
        encoder.digest(current);
        encoder.text(node.id());
        encoder.text(node.op().stable_id());
        let output = outcome
            .get_output(&node.outputs()[0])
            .ok_or("node output missing")?;
        encoder.digest(output.content_digest()?);
        current = ContentDigest::sha256(&encoder.finish());
    }
    assert_eq!(
        receipt.operator_trace_digest,
        Some(ReceiptDigest::Content(current))
    );
    // The relu output is exactly [0, 0, 2.5]; the output root binds that tensor.
    let y = outcome.get_output("y").ok_or("missing y")?;
    assert_eq!(y.to_vec::<f32>()?, vec![0.0, 0.0, 2.5]);
    Ok(())
}
