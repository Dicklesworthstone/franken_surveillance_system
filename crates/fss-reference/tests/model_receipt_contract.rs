#![forbid(unsafe_code)]
//! Emitted model invocation receipts (fss-2h5zq.47 / fss-2h5zq.48).
//!
//! One receipt per reachable outcome (ok, error, budget_exhausted, cancelled), plus the
//! package-backed activity receipt. Each receipt's emitted JSON must equal the committed fixture
//! under `tests/fixtures/model_receipts/`. `tests/test_json_instance_validate.py` validates those
//! same bytes against `schemas/model_execution_receipt.v1.json`, so the schema check runs on what
//! Rust actually emits, not on hand-written dictionaries. The operator trace chain is recomputed
//! here independently of the receipt code.

use std::collections::BTreeMap;
use std::error::Error;

use fss_codec_mjpeg::ComponentInterpretation;
use fss_codec_mjpeg::DecodeBudget;
use fss_codec_mjpeg::color::{DecodedRgb, RgbDecodeLimits, decode_rgb};
use fss_core::{
    CanonicalEncoder, CapsuleId, CaptureInterval, ClockBasis, ContentDigest, Generation,
    SensorCapsule, SensorId, SensorSourceBytesSpec, StreamId, TimestampNs,
};
use fss_model_ir::{AttributeMap, GraphNode, ModelIrGraph, OpCode, TensorPort};
use fss_reference::executor_activity::{
    ACTIVITY_FRAME_INPUT, ACTIVITY_REFERENCE_INPUT, ACTIVITY_SCORE_OUTPUT,
    ACTIVITY_TENSOR_GENERATION, ACTIVITY_WEIGHTS_INPUT, ActivityExecutorModel,
    ActivityFrameBinding, ActivityThresholdPolicy, rgb_decode_receipt_bytes,
};
use fss_reference::model_receipt::{
    ModelInvocationReceipt, ReceiptDigest, ReceiptOutcome, ReceiptRecordContext,
    compute_execution_plan_digest, compute_resized_preprocess_program_digest,
    execute_and_record_receipt,
};
use fss_reference::{ExecBudget, ScalarExecCx, VirtualClock};
use fss_tensor::{DType, Shape, Tensor};

mod caplog_support;
use caplog_support::Record;

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

fn bind<'a>(
    bytes: &[u8],
    decoded: &'a DecodedRgb,
    capsule: &'a SensorCapsule,
) -> ActivityFrameBinding<'a> {
    ActivityFrameBinding {
        pixels: decoded.pixels(),
        receipt: decoded.receipt(),
        source_digest: ContentDigest::sha256(bytes),
        capsule,
    }
}

/// The sensor capsule of `source` as recorded by `sensor` (fss-2h5zq.51: a binding carries the
/// frame's actual capsule, checked against its source bytes and sensor).
fn capsule_for(source: &[u8], sensor: &str, sequence: u64) -> TestResult<SensorCapsule> {
    let capture = CaptureInterval::new(TimestampNs(0), TimestampNs(5_000_000_000))?;
    Ok(SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
        capsule_id: CapsuleId::parse(format!("capsule:contract:{sequence}"))?,
        sensor_id: SensorId::parse(sensor)?,
        stream_id: StreamId::parse("stream:contract")?,
        sequence,
        capture,
        receive_time: capture.latest,
        clock_basis: ClockBasis::Estimated,
        source,
        frame_count: 1,
        gap_before: false,
    })?)
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
    let frame_capsule = capsule_for(GRADIENT, "sensor:file-cam", 1)?;
    let reference_capsule = capsule_for(BACKGROUND, "sensor:file-cam", 0)?;
    let (_, activity) = model.invoke(
        &SensorId::parse("sensor:file-cam")?,
        bind(GRADIENT, &frame, &frame_capsule),
        bind(BACKGROUND, &reference, &reference_capsule),
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
        let fixture = fixture.trim_end_matches('\n');
        // The case name states the outcome it exercises; the package case is a successful run.
        let expected_outcome = if *name == "activity_package" {
            "ok"
        } else {
            *name
        };
        let verified = receipt
            .verify(receipt.generation, &receipt.compute_canonical_digest())
            .is_ok();
        let matches = json == fixture;
        Record::new(&format!("receipt_{name}"))
            .check("outcome", expected_outcome, receipt.outcome.as_str())
            .check(
                "json_sha256",
                ContentDigest::sha256(fixture.as_bytes()).to_string(),
                ContentDigest::sha256(json.as_bytes()).to_string(),
            )
            .check_eq("verifies", true, verified)
            .emit_checked(
                0,
                matches && verified && receipt.outcome.as_str() == expected_outcome,
            );
        if !matches {
            println!("RECEIPT_FIXTURE_DRIFT {name} {json}");
            drift.push(*name);
        }
        assert!(verified, "{name} receipt does not verify");
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

/// The package-backed receipt binds, each recomputed here from its own inputs rather than read
/// back from the receipt code: the package manifest, the execution plan over the verified
/// graph, the recorded resize program, the three input tensors (both preprocessed frames and the
/// package weights), the two decode-receipt records, and an output root over the score the
/// result reports.
#[test]
fn activity_receipt_binds_package_graph_tensors_and_decode_receipts() -> TestResult {
    let cx = ScalarExecCx::new();
    let model = ActivityExecutorModel::load_committed(&cx)?;
    let package = model.package();
    let frame = decode(GRADIENT)?;
    let reference = decode(BACKGROUND)?;
    let frame_capsule = capsule_for(GRADIENT, "sensor:file-cam", 1)?;
    let reference_capsule = capsule_for(BACKGROUND, "sensor:file-cam", 0)?;
    let (result, receipt) = model.invoke(
        &SensorId::parse("sensor:file-cam")?,
        bind(GRADIENT, &frame, &frame_capsule),
        bind(BACKGROUND, &reference, &reference_capsule),
        &ActivityThresholdPolicy::reference()?,
        ExecBudget::new(10_000_000, 16 * 1024 * 1024),
        "job:receipt-contract:binding",
        &cx,
    )?;
    let [fw, fh] = frame.dimensions();
    let [rw, rh] = reference.dimensions();
    let weights = Tensor::from_values(
        Shape::new(vec![package.mean_weights().len(), 1])?,
        package.mean_weights(),
        ACTIVITY_TENSOR_GENERATION,
    )?;
    let expected_inputs: Vec<String> = [
        model
            .preprocess(frame.pixels(), fw, fh, &cx)?
            .content_digest()?,
        model
            .preprocess(reference.pixels(), rw, rh, &cx)?
            .content_digest()?,
        weights.content_digest()?,
        ContentDigest::sha256(&rgb_decode_receipt_bytes(&frame.receipt())),
        ContentDigest::sha256(&rgb_decode_receipt_bytes(&reference.receipt())),
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let observed_inputs: Vec<String> = receipt
        .input_roots
        .iter()
        .map(ReceiptDigest::to_text)
        .collect();
    let plan = compute_execution_plan_digest(
        package.graph(),
        &[
            ACTIVITY_FRAME_INPUT,
            ACTIVITY_REFERENCE_INPUT,
            ACTIVITY_WEIGHTS_INPUT,
        ],
    )?;
    let spec = package.spec();
    let preprocess =
        compute_resized_preprocess_program_digest(&spec.program, spec.filter, spec.aspect);
    let score = result.outcome.score().ok_or("no score")?;
    let score_tensor = Tensor::from_values(
        Shape::new(vec![1, 1])?,
        &[score],
        ACTIVITY_TENSOR_GENERATION,
    )?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.canonical.v1");
    encoder.text("fss.model_execution_receipt.v1/output_root");
    encoder.u64(1);
    encoder.text(ACTIVITY_SCORE_OUTPUT);
    encoder.digest(score_tensor.content_digest()?);
    let output_root = ContentDigest::sha256(&encoder.finish());
    let text = |digest: Option<&ReceiptDigest>| {
        digest.map_or_else(|| "<absent>".to_owned(), ReceiptDigest::to_text)
    };
    let checks = [
        (
            "model_package_root",
            package.manifest_digest().to_string(),
            receipt.model_package_root.to_text(),
        ),
        (
            "execution_plan_digest",
            plan.to_string(),
            receipt.execution_plan_digest.to_text(),
        ),
        (
            "preprocess_program",
            preprocess.to_string(),
            receipt.preprocess_program.to_text(),
        ),
        (
            "output_root",
            output_root.to_string(),
            text(receipt.output_root.as_ref()),
        ),
        (
            "outcome",
            "ok".to_owned(),
            receipt.outcome.as_str().to_owned(),
        ),
    ];
    let mut record = Record::new("receipt_activity_binding").check(
        "input_roots",
        expected_inputs.clone(),
        observed_inputs.clone(),
    );
    for (name, expected, observed) in &checks {
        record = record.check(name, expected.as_str(), observed.as_str());
    }
    record.emit_checked(
        0,
        expected_inputs == observed_inputs
            && checks
                .iter()
                .all(|(_, expected, observed)| expected == observed),
    );
    assert_eq!(observed_inputs, expected_inputs);
    for (name, expected, observed) in &checks {
        assert_eq!(observed, expected, "{name}");
    }
    // The result links the receipt to the source bytes and the capsule.
    assert_eq!(result.input_capture_root, ContentDigest::sha256(GRADIENT));
    assert_eq!(
        result.reference_capture_root,
        ContentDigest::sha256(BACKGROUND)
    );
    assert_eq!(
        result.invocation_receipt_digest,
        receipt.compute_canonical_digest()
    );
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

/// The operator trace as it was computed before fss-2h5zq.47's review fix: every node's id and
/// opcode were chained, but an output digest was chained only when the node's first output was a
/// declared graph output. Intermediates (`delta`, `energy`, `flat` in the activity graph) never
/// reached the chain. Kept here, independent of the receipt code, to show what the fix changes.
fn final_node_only_trace(
    graph: &ModelIrGraph,
    outputs: &BTreeMap<String, Tensor>,
    order: &[&str],
) -> TestResult<ContentDigest> {
    let mut current = ContentDigest::sha256(b"fss.model_execution_receipt.v1/operator_trace");
    for id in order {
        let node = graph
            .nodes()
            .iter()
            .find(|node| node.id() == *id)
            .ok_or("node missing")?;
        let mut encoder = CanonicalEncoder::new();
        encoder.digest(current);
        encoder.text(node.id());
        encoder.text(node.op().stable_id());
        if let Some(tensor) = outputs.get(&node.outputs()[0]) {
            encoder.digest(tensor.content_digest()?);
        }
        current = ContentDigest::sha256(&encoder.finish());
    }
    Ok(current)
}

/// The current trace, recomputed here from intermediate tensors this test builds itself from the
/// graph's documented arithmetic (`delta = frame - reference`, `energy = delta * delta`,
/// `flat = reshape(energy, [1, 1024])`, `score = flat x mean_weights`), not from the executor.
fn independent_full_trace(
    graph: &ModelIrGraph,
    frame: &[f32],
    reference: &[f32],
    score: f32,
) -> TestResult<ContentDigest> {
    let delta: Vec<f32> = frame.iter().zip(reference).map(|(f, r)| f - r).collect();
    let energy: Vec<f32> = delta.iter().map(|d| d * d).collect();
    let plane = Shape::new(vec![1, 1, 32, 32])?;
    let tensors = [
        (
            "node:delta",
            Tensor::from_values(plane.clone(), &delta, ACTIVITY_TENSOR_GENERATION)?,
        ),
        (
            "node:energy",
            Tensor::from_values(plane, &energy, ACTIVITY_TENSOR_GENERATION)?,
        ),
        (
            "node:flatten",
            Tensor::from_values(
                Shape::new(vec![1, 1024])?,
                &energy,
                ACTIVITY_TENSOR_GENERATION,
            )?,
        ),
        (
            "node:mean",
            Tensor::from_values(
                Shape::new(vec![1, 1])?,
                &[score],
                ACTIVITY_TENSOR_GENERATION,
            )?,
        ),
    ];
    let mut current = ContentDigest::sha256(b"fss.model_execution_receipt.v1/operator_trace");
    for (id, tensor) in tensors {
        let node = graph
            .nodes()
            .iter()
            .find(|node| node.id() == id)
            .ok_or("node missing")?;
        let mut encoder = CanonicalEncoder::new();
        encoder.digest(current);
        encoder.text(node.id());
        encoder.text(node.op().stable_id());
        encoder.digest(tensor.content_digest()?);
        current = ContentDigest::sha256(&encoder.finish());
    }
    Ok(current)
}

const ACTIVITY_NODE_ORDER: [&str; 4] = ["node:delta", "node:energy", "node:flatten", "node:mean"];

fn package_weights(model: &ActivityExecutorModel) -> TestResult<Tensor> {
    let package = model.package();
    Ok(Tensor::from_values(
        Shape::new(vec![package.mean_weights().len(), 1])?,
        package.mean_weights(),
        ACTIVITY_TENSOR_GENERATION,
    )?)
}

/// Review finding (2026-10-08, fss-2h5zq.47): the trace must chain every node's output, not only
/// the declared outputs. On the real 4-node activity graph two runs whose intermediates differ
/// (the changed half of the frame is the top half in one run and the bottom half in the other)
/// produce the bit-identical score 0.5, so the old final-node-only chain collides; the current
/// chain separates them and equals an independent recomputation over every intermediate.
#[test]
fn activity_trace_chains_every_intermediate_and_separates_equal_scores() -> TestResult {
    let cx = ScalarExecCx::new();
    let model = ActivityExecutorModel::load_committed(&cx)?;
    let package = model.package();
    let graph = package.graph();
    let weights = package_weights(&model)?;
    let half = |top: bool| -> Vec<f32> {
        (0..1024)
            .map(|i| if (i < 512) == top { 1.0 } else { 0.0 })
            .collect()
    };
    let reference = vec![0.0_f32; 1024];
    let plane = Shape::new(vec![1, 1, 32, 32])?;
    let mut runs = Vec::new();
    for (name, frame) in [("top", half(true)), ("bottom", half(false))] {
        let inputs = [
            (
                ACTIVITY_FRAME_INPUT,
                Tensor::from_values(plane.clone(), &frame, ACTIVITY_TENSOR_GENERATION)?,
            ),
            (
                ACTIVITY_REFERENCE_INPUT,
                Tensor::from_values(plane.clone(), &reference, ACTIVITY_TENSOR_GENERATION)?,
            ),
            (ACTIVITY_WEIGHTS_INPUT, weights.clone()),
        ];
        let (run, receipt) = execute_and_record_receipt(
            graph,
            &inputs,
            ExecBudget::new(10_000_000, 16 * 1024 * 1024),
            &cx,
            ReceiptRecordContext {
                job_id: "job:receipt-contract:trace-collision",
                preprocess_program: None,
                model_package_root: Some(package.manifest_digest()),
                virtual_clock: None,
                source_roots: &[],
                preprocess_resize: None,
            },
        );
        let outcome = run?;
        let order: Vec<&str> = outcome
            .node_output_digests()
            .iter()
            .map(|entry| entry.node_id.as_str())
            .collect();
        assert_eq!(order, ACTIVITY_NODE_ORDER, "{name}");
        let score = outcome
            .get_output(ACTIVITY_SCORE_OUTPUT)
            .ok_or("no score")?
            .to_vec::<f32>()?;
        let old = final_node_only_trace(graph, outcome.outputs(), &ACTIVITY_NODE_ORDER)?;
        let independent = independent_full_trace(graph, &frame, &reference, score[0])?;
        let trace = match &receipt.operator_trace_digest {
            Some(ReceiptDigest::Content(trace)) => *trace,
            other => return Err(format!("{name}: no content trace: {other:?}").into()),
        };
        runs.push((score[0], old, independent, trace));
    }
    let (score_top, old_top, independent_top, trace_top) = runs[0];
    let (score_bottom, old_bottom, independent_bottom, trace_bottom) = runs[1];
    let same_score = score_top.to_bits() == score_bottom.to_bits() && score_top == 0.5;
    let old_collides = old_top == old_bottom;
    let new_separates = trace_top != trace_bottom;
    let independent_matches = trace_top == independent_top && trace_bottom == independent_bottom;
    Record::new("receipt_trace_chains_intermediates")
        .check_eq("same_score_bits", true, same_score)
        .check_eq("final_node_only_chain_collides", true, old_collides)
        .check_eq("full_chain_separates", true, new_separates)
        .check_eq("full_chain_matches_independent", true, independent_matches)
        .emit_checked(
            0,
            same_score && old_collides && new_separates && independent_matches,
        );
    assert!(same_score, "{score_top} vs {score_bottom}");
    assert_eq!(old_top, old_bottom);
    assert_ne!(trace_top, trace_bottom);
    assert_eq!(trace_top, independent_top);
    assert_eq!(trace_bottom, independent_bottom);
    Ok(())
}

/// `operatorTraceDigest` of `activity_package.json` before fss-2h5zq.47's review fix (main
/// 81a1c5b), when the chain bound only the declared `score` output.
const ACTIVITY_PACKAGE_TRACE_BEFORE_FIX: &str =
    "sha256:d552deb6246e64814b309c44fd303094278511ddd4aa1c9782b16e0a10bcd060";
/// SHA-256 of the whole `activity_package.json` file (with its trailing newline) before the fix.
const ACTIVITY_PACKAGE_FIXTURE_BEFORE_FIX_SHA256: &str =
    "sha256:c3d0f8725bc6ac26a6ad7cf1451abef4cb09764d2423f4fc174d2e95d780a39b";

/// Why `activity_package.json` was re-pinned, and that nothing else in it moved: the old trace is
/// reproduced from this run by the old final-node-only rule, the fixture differs from its
/// pre-fix bytes only in `operatorTraceDigest`, and the current trace chains the three
/// intermediates. The 1-node `ok.json` is unchanged because its only node's output is the
/// declared output, so both rules chain the same bytes.
#[test]
fn activity_package_fixture_repin_is_only_the_intermediate_chain() -> TestResult {
    let receipts = receipts()?;
    let (_, activity) = receipts
        .iter()
        .find(|(name, _)| *name == "activity_package")
        .ok_or("activity receipt")?;
    let cx = ScalarExecCx::new();
    let model = ActivityExecutorModel::load_committed(&cx)?;
    let frame = decode(GRADIENT)?;
    let reference = decode(BACKGROUND)?;
    let [fw, fh] = frame.dimensions();
    let [rw, rh] = reference.dimensions();
    let frame_tensor = model.preprocess(frame.pixels(), fw, fh, &cx)?;
    let reference_tensor = model.preprocess(reference.pixels(), rw, rh, &cx)?;
    let frame_values = frame_tensor.to_vec::<f32>()?;
    let reference_values = reference_tensor.to_vec::<f32>()?;
    let graph = model.package().graph();
    let (run, _) = execute_and_record_receipt(
        graph,
        &[
            (ACTIVITY_FRAME_INPUT, frame_tensor),
            (ACTIVITY_REFERENCE_INPUT, reference_tensor),
            (ACTIVITY_WEIGHTS_INPUT, package_weights(&model)?),
        ],
        ExecBudget::new(10_000_000, 16 * 1024 * 1024),
        &cx,
        context("job:receipt-contract:activity"),
    );
    let outcome = run?;
    let old = final_node_only_trace(graph, outcome.outputs(), &ACTIVITY_NODE_ORDER)?;
    let score = outcome
        .get_output(ACTIVITY_SCORE_OUTPUT)
        .ok_or("no score")?
        .to_vec::<f32>()?[0];
    let independent = independent_full_trace(graph, &frame_values, &reference_values, score)?;
    let current = activity
        .operator_trace_digest
        .as_ref()
        .map(ReceiptDigest::to_text)
        .ok_or("no trace")?;
    let fixture = FIXTURES
        .iter()
        .find(|(name, _)| *name == "activity_package")
        .ok_or("fixture")?
        .1;
    let restored = fixture.replace(&current, ACTIVITY_PACKAGE_TRACE_BEFORE_FIX);
    let restored_sha = ContentDigest::sha256(restored.as_bytes()).to_string();
    Record::new("receipt_activity_trace_repin")
        .check(
            "old_rule_trace",
            ACTIVITY_PACKAGE_TRACE_BEFORE_FIX,
            old.to_string(),
        )
        .check("current_trace", independent.to_string(), current.clone())
        .check(
            "fixture_with_old_trace_sha256",
            ACTIVITY_PACKAGE_FIXTURE_BEFORE_FIX_SHA256,
            restored_sha.as_str(),
        )
        .emit_checked(
            0,
            old.to_string() == ACTIVITY_PACKAGE_TRACE_BEFORE_FIX
                && independent.to_string() == current
                && restored_sha == ACTIVITY_PACKAGE_FIXTURE_BEFORE_FIX_SHA256,
        );
    assert_eq!(old.to_string(), ACTIVITY_PACKAGE_TRACE_BEFORE_FIX);
    assert_eq!(current, independent.to_string());
    assert_ne!(current, ACTIVITY_PACKAGE_TRACE_BEFORE_FIX);
    assert_eq!(fixture.matches(current.as_str()).count(), 1);
    assert_eq!(restored_sha, ACTIVITY_PACKAGE_FIXTURE_BEFORE_FIX_SHA256);
    Ok(())
}
