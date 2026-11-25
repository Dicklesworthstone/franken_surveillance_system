#![forbid(unsafe_code)]
//! End-to-end qualification contract for `FSS-139` (`fss-x4a.14.10`):
//! scalar operator executor for the first detector graph.
//!
//! Verifies:
//! 1. Real ONNX detector graph (`detector_split_pool.onnx`: 12-node Conv -> Split -> Relu +
//!    3x Padded MaxPool -> Concat -> Conv -> Transpose -> Reshape) imported via `fss-model-ir`,
//!    re-exported & decoded canonically, fed from real RGB HWC U8 bytes through
//!    `PreprocessProgram`, and certified **bit-identically (0 ULP)** across FOUR independent paths:
//!    - `execute_and_record_receipt` (`ScalarExecutor` + `ModelInvocationReceipt`),
//!    - `CompiledScalarPlan` (liveness-planned peak-memory execution over the unchanged scalar backend),
//!    - `OptimizedGraph` (packed-weight tiled CPU execution at 1 and 2 threads), and
//!    - an independent direct-loop mathematical oracle directly over raw RGB pixels.
//! 2. Model IR v2 detector neck/head (`Conv2d` + `Silu` + `MaxPool2d` + grouped `Conv2d` +
//!    residual `Add` + `Reshape` + `MatMul` + `Sigmoid` + `Softmax` + `LayerNorm`) certified
//!    bit-identically across `ScalarExecutor`, `CompiledScalarPlan`, and `OptimizedGraph`
//!    (including fused Conv+SiLU) with full receipt & JSON canonical verification.
//! 3. Fail-closed fault campaign over the real detector graph: MAC/byte budget exhaustion
//!    (1-short), cooperative cancellation with drain confirmation, stale generation, missing
//!    weight port, shape mismatch, unsupported U8 dtype, and non-finite score abstention.

use std::collections::BTreeMap;

use fss_core::{ContentDigest, Generation, TimestampNs};
use fss_model_ir::{
    AttrValue, AttributeMap, GraphNode, MemoryPlanLimits, ModelIrGraph, ModelIrVersion,
    OnnxExportLimits, OnnxLimits, OpCode, TensorPort, decode_canonical_model_ir,
    export_onnx_artifacts, import_onnx,
};
use fss_reference::executor_activity::{
    ActivityThresholdPolicy, ExecutorAbstentionReason, ExecutorModelOutcome,
};
use fss_reference::planned_scalar::{CompiledScalarPlan, PeakExecBudget, PlannedExecError};
use fss_reference::{
    ChannelTransform, ExecBudget, ExecError, ExecThreads, OptimizedGraph, PreprocessProgram,
    ReceiptOutcome, ReceiptRecordContext, ScalarExecCx, ScalarExecutor, VirtualClock,
    execute_and_record_receipt,
};
use fss_tensor::{DType, Shape, Tensor};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const DETECTOR_ONNX: &[u8] =
    include_bytes!("../../fss-model-ir/tests/fixtures/onnx/detector_split_pool.onnx");
const DETECTOR_GEN: Generation = Generation(23);

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn bits(values: &[f32]) -> Vec<u32> {
    values.iter().map(|v| v.to_bits()).collect()
}

/// Independent mathematical oracle for 3x3 stride-1 pad-1 MaxPool excluding padding.
fn oracle_pool_3x3_pad1(values: &[f32], h: usize, w: usize) -> Vec<f32> {
    let mut out = Vec::with_capacity(h * w);
    for oy in 0..h {
        for ox in 0..w {
            let mut max_val = f32::NEG_INFINITY;
            let mut found = false;
            for ky in 0..3_usize {
                let sy = oy + ky;
                if sy == 0 || sy > h {
                    continue;
                }
                let iy = sy - 1;
                for kx in 0..3_usize {
                    let sx = ox + kx;
                    if sx == 0 || sx > w {
                        continue;
                    }
                    let ix = sx - 1;
                    let v = values[iy * w + ix];
                    if !found || v > max_val {
                        max_val = v;
                        found = true;
                    }
                }
            }
            out.push(max_val);
        }
    }
    out
}

/// Independent mathematical oracle for the complete `Preprocess(RGB HWC U8 -> unit NCHW) +
/// detector_split_pool.onnx` pipeline, computed directly from raw RGB pixel bytes.
fn oracle_detector_from_rgb_hwc(raw_rgb_hwc: &[u8]) -> (Vec<f32>, Vec<f32>) {
    let scale = 1.0_f32 / 255.0_f32;
    let mut r = Vec::with_capacity(16);
    let mut g = Vec::with_capacity(16);
    let mut b = Vec::with_capacity(16);
    for px in 0..16 {
        r.push((raw_rgb_hwc[px * 3] as f32) * scale);
        g.push((raw_rgb_hwc[px * 3 + 1] as f32) * scale);
        b.push((raw_rgb_hwc[px * 3 + 2] as f32) * scale);
    }
    // stem_kernel:
    //   ch0: 1*r + 0*g + 0*b - 1.0
    //   ch1: 0*r + 1*g + 0*b + 2.0  (pool_seed)
    //   ch2: 0*r + 0*g + 1*b - 3.0
    //   ch3: 0.5*r + 0.25*g + 0*b + 0.0
    // Note: match exact IEEE-754 accumulation order (0.0 + r*w0 + g*w1 + b*w2) + bias.
    let mut bypass = Vec::with_capacity(16);
    let mut pool_seed = Vec::with_capacity(16);
    let mut branch0 = Vec::with_capacity(16);
    let mut branch1 = Vec::with_capacity(16);
    for px in 0..16 {
        bypass.push((0.0_f32 + r[px] * 1.0 + g[px] * 0.0 + b[px] * 0.0) + (-1.0));
        pool_seed.push((0.0_f32 + r[px] * 0.0 + g[px] * 1.0 + b[px] * 0.0) + 2.0);
        branch0.push((0.0_f32 + r[px] * 0.0 + g[px] * 0.0 + b[px] * 1.0) + (-3.0));
        branch1.push((0.0_f32 + r[px] * 0.5 + g[px] * 0.25 + b[px] * 0.0) + 0.0);
    }
    let pool1 = oracle_pool_3x3_pad1(&pool_seed, 4, 4);
    let pool2 = oracle_pool_3x3_pad1(&pool1, 4, 4);
    let pool3 = oracle_pool_3x3_pad1(&pool2, 4, 4);

    let mut head = Vec::with_capacity(16 * 6);
    for px in 0..16 {
        let b0 = if branch0[px] > 0.0 { branch0[px] } else { 0.0 };
        let b1 = if branch1[px] > 0.0 { branch1[px] } else { 0.0 };
        let c = [
            bypass[px],
            pool_seed[px],
            pool1[px],
            pool2[px],
            pool3[px],
            b0,
            b1,
        ];
        // head_kernel rows 0..5 are identity on channels 0..5, row 5 is 1.0*c[5] + 0.5*c[6]
        for out_ch in 0..6 {
            let mut acc = 0.0_f32;
            for (in_ch, &val) in c.iter().enumerate() {
                let w = if out_ch < 5 {
                    if in_ch == out_ch { 1.0_f32 } else { 0.0_f32 }
                } else if in_ch == 5 {
                    1.0_f32
                } else if in_ch == 6 {
                    0.5_f32
                } else {
                    0.0_f32
                };
                acc += val * w;
            }
            head.push(acc + 0.0_f32);
        }
    }
    (head, pool_seed)
}

type LoadedDetector = (ModelIrGraph, BTreeMap<String, Tensor>, ContentDigest);

fn load_canonical_detector_graph() -> Result<LoadedDetector, Box<dyn std::error::Error>> {
    let imported = import_onnx(
        DETECTOR_ONNX,
        ContentDigest::sha256(DETECTOR_ONNX),
        DETECTOR_GEN,
        OnnxLimits::default(),
        &|| false,
    )?;
    let artifacts = export_onnx_artifacts(&imported, OnnxExportLimits::default(), &|| false)?;
    let graph = decode_canonical_model_ir(artifacts.graph_bytes(), artifacts.graph_digest())?;
    let pkg_root = artifacts.graph_digest();
    Ok((graph, imported.parameters().clone(), pkg_root))
}

#[test]
fn first_detector_graph_real_onnx_preprocess_receipt_and_four_way_bit_exact_equivalence()
-> TestResult {
    let (graph, params, pkg_root) = load_canonical_detector_graph()?;
    assert_eq!(graph.nodes().len(), 12);
    assert_eq!(params.len(), 3);

    // Build realistic raw 4x4 RGB HWC U8 camera frame and run PreprocessProgram.
    let raw_rgb_hwc: Vec<u8> = (0..48_usize)
        .map(|i| ((i.wrapping_mul(37).wrapping_add(19)) % 256) as u8)
        .collect();
    let frame_source_digest = ContentDigest::sha256(&raw_rgb_hwc);
    let preprocess = PreprocessProgram::new(4, 4, ChannelTransform::Rgb, true);
    let image_tensor = preprocess.execute_bytes(&raw_rgb_hwc, 4, 4, 3, DETECTOR_GEN)?;
    assert_eq!(image_tensor.shape().dims(), &[1, 3, 4, 4]);
    assert_eq!(image_tensor.generation(), DETECTOR_GEN);

    // Assemble full input bindings for ScalarExecutor + PlannedScalar.
    let mut all_inputs: Vec<(String, Tensor)> =
        params.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    all_inputs.push(("image".to_owned(), image_tensor.clone()));
    let borrowed_inputs: Vec<(&str, Tensor)> = all_inputs
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();

    // Path 1: Production ScalarExecutor + ModelInvocationReceipt (`execute_and_record_receipt`).
    let cx = ScalarExecCx::new();
    let clock = VirtualClock::new(139, TimestampNs(1_700_000_000_000));
    let (scalar_res, receipt) = execute_and_record_receipt(
        &graph,
        &borrowed_inputs,
        ExecBudget::unlimited(),
        &cx,
        ReceiptRecordContext {
            job_id: "job:fss-139:detector-split-pool:001",
            preprocess_program: Some(&preprocess),
            model_package_root: Some(pkg_root),
            virtual_clock: Some(&clock),
            source_roots: &[frame_source_digest],
            preprocess_resize: None,
        },
    );
    let scalar_outcome = scalar_res?;
    assert_eq!(scalar_outcome.nodes_executed(), 12);
    assert_eq!(scalar_outcome.node_output_digests().len(), 12);
    assert!(scalar_outcome.executed_macs() > 0);
    assert!(scalar_outcome.allocated_bytes() > 0);

    // Verify receipt structural, cryptographic, and JSON schema contracts.
    assert_eq!(receipt.outcome, ReceiptOutcome::Ok);
    assert!(receipt.output_root.is_some());
    assert!(receipt.operator_trace_digest.is_some());
    assert!(receipt.error_id.is_none());
    assert!(receipt.cancel_reason.is_none());
    let receipt_digest = receipt.compute_canonical_digest();
    receipt.verify(DETECTOR_GEN, &receipt_digest)?;
    let receipt_json = receipt.to_json_canonical();
    assert!(receipt_json.contains(r#""schema":"fss.model_execution_receipt.v1""#));
    assert!(receipt_json.contains(r#""outcome":"ok""#));

    // Repeated run must produce bit-identical outputs AND bit-identical receipt digest!
    let (repeat_res, repeat_receipt) = execute_and_record_receipt(
        &graph,
        &borrowed_inputs,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
        ReceiptRecordContext {
            job_id: "job:fss-139:detector-split-pool:001",
            preprocess_program: Some(&preprocess),
            model_package_root: Some(pkg_root),
            virtual_clock: Some(&clock),
            source_roots: &[frame_source_digest],
            preprocess_resize: None,
        },
    );
    let _repeat_outcome = repeat_res?;
    assert_eq!(repeat_receipt.compute_canonical_digest(), receipt_digest);

    // Path 2: Liveness-planned memory-bounded scalar execution (`CompiledScalarPlan`).
    let plan =
        CompiledScalarPlan::compile(&graph, MemoryPlanLimits::default(), &ScalarExecCx::new())?;
    let req = plan.minimum_requirements();
    assert_eq!(req.macs, scalar_outcome.executed_macs());
    assert!(req.peak_bytes <= scalar_outcome.allocated_bytes());
    let planned_outcome = plan.run(
        &borrowed_inputs,
        PeakExecBudget::new(req.macs, req.peak_bytes, req.scratch_bytes),
        &ScalarExecCx::new(),
    )?;

    // Path 3: Packed-weight tiled CPU execution (`OptimizedGraph`) at 1 thread AND 2 threads!
    let mut constants: BTreeMap<String, Vec<f32>> = BTreeMap::new();
    for (k, t) in &params {
        constants.insert(k.clone(), t.to_vec::<f32>()?);
    }
    let optimized = OptimizedGraph::prepare(&graph, &constants, &ScalarExecCx::new())?;
    let (opt_1t, _rep_1t) = optimized.run_with_report(
        &[("image", image_tensor.clone())],
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;
    let (opt_2t, _rep_2t) = optimized.run_threaded(
        &[("image", image_tensor)],
        ExecBudget::unlimited(),
        ExecThreads::new(2)?,
        &ScalarExecCx::new(),
    )?;

    // Path 4: Independent pure-Rust mathematical oracle directly from raw RGB HWC U8 bytes!
    let (oracle_head, oracle_seed) = oracle_detector_from_rgb_hwc(&raw_rgb_hwc);

    // Assert 0-ULP BIT-EXACT IDENTITY across ALL FOUR execution paths!
    let scalar_head = scalar_outcome
        .get_output("head")
        .ok_or("missing head")?
        .to_vec::<f32>()?;
    let scalar_seed = scalar_outcome
        .get_output("pool_seed")
        .ok_or("missing pool_seed")?
        .to_vec::<f32>()?;
    let planned_head = planned_outcome
        .execution()
        .get_output("head")
        .ok_or("missing planned head")?
        .to_vec::<f32>()?;
    let planned_seed = planned_outcome
        .execution()
        .get_output("pool_seed")
        .ok_or("missing planned pool_seed")?
        .to_vec::<f32>()?;
    let opt1_head = opt_1t
        .get_output("head")
        .ok_or("missing opt1 head")?
        .to_vec::<f32>()?;
    let opt1_seed = opt_1t
        .get_output("pool_seed")
        .ok_or("missing opt1 pool_seed")?
        .to_vec::<f32>()?;
    let opt2_head = opt_2t
        .get_output("head")
        .ok_or("missing opt2 head")?
        .to_vec::<f32>()?;
    let opt2_seed = opt_2t
        .get_output("pool_seed")
        .ok_or("missing opt2 pool_seed")?
        .to_vec::<f32>()?;

    assert_eq!(bits(&scalar_head), bits(&oracle_head));
    assert_eq!(bits(&scalar_seed), bits(&oracle_seed));
    assert_eq!(bits(&planned_head), bits(&scalar_head));
    assert_eq!(bits(&planned_seed), bits(&scalar_seed));
    assert_eq!(bits(&opt1_head), bits(&scalar_head));
    assert_eq!(bits(&opt1_seed), bits(&scalar_seed));
    assert_eq!(bits(&opt2_head), bits(&scalar_head));
    assert_eq!(bits(&opt2_seed), bits(&scalar_seed));

    emit_caplog(
        "fss_139_first_detector_four_way_equivalence",
        "scalar_planned_optimized1t_optimized2t_oracle_0ulp_identical_with_verified_receipt",
        "scalar_planned_optimized1t_optimized2t_oracle_0ulp_identical_with_verified_receipt",
        "pass",
    );
    Ok(())
}

#[test]
fn detector_neck_and_head_v2_silu_sigmoid_softmax_conv_matmul_equivalence() -> TestResult {
    // Realistic Model IR v2 detector neck + detection head:
    //   image [1, 2, 4, 4]
    //     -> Conv2d(3x3, pad=1, bias) -> [1, 2, 4, 4]
    //     -> Silu (exercises fused Conv+SiLU in OptimizedGraph!) -> [1, 2, 4, 4]
    //     -> MaxPool2d(2x2, stride=2) -> [1, 2, 2, 2]
    //     -> Conv2d(1x1, groups=2) -> [1, 2, 2, 2]
    //     -> Add(residual from MaxPool) -> [1, 2, 2, 2]
    //     -> Reshape -> [1, 8]
    //     -> LayerNorm([8]) -> [1, 8]
    //     -> MatMul(w_head [8, 4]) -> [1, 4]
    //        -> Sigmoid -> obj_scores [1, 4]
    //        -> Softmax(axis=-1) -> class_probs [1, 4]
    let g = Generation(42);
    let mut conv1_attrs = AttributeMap::new();
    conv1_attrs.insert("strides".to_owned(), AttrValue::IntList(vec![1, 1]));
    conv1_attrs.insert("padding".to_owned(), AttrValue::IntList(vec![1, 1, 1, 1]));
    conv1_attrs.insert("groups".to_owned(), AttrValue::Int(1));

    let mut pool_attrs = AttributeMap::new();
    pool_attrs.insert("kernel_size".to_owned(), AttrValue::IntList(vec![2, 2]));
    pool_attrs.insert("strides".to_owned(), AttrValue::IntList(vec![2, 2]));
    pool_attrs.insert("padding".to_owned(), AttrValue::IntList(vec![0, 0, 0, 0]));

    let mut conv2_attrs = AttributeMap::new();
    conv2_attrs.insert("strides".to_owned(), AttrValue::IntList(vec![1, 1]));
    conv2_attrs.insert("padding".to_owned(), AttrValue::IntList(vec![0, 0, 0, 0]));
    conv2_attrs.insert("groups".to_owned(), AttrValue::Int(2));

    let mut reshape_attrs = AttributeMap::new();
    reshape_attrs.insert("shape".to_owned(), AttrValue::IntList(vec![1, 8]));

    let mut ln_attrs = AttributeMap::new();
    ln_attrs.insert("normalized_shape".to_owned(), AttrValue::IntList(vec![8]));

    let mut sm_attrs = AttributeMap::new();
    sm_attrs.insert("axis".to_owned(), AttrValue::Int(-1));

    let graph = ModelIrGraph::new_validated(
        "detector_neck_head_v2",
        ModelIrVersion::V2,
        g,
        vec![
            TensorPort::new("image", DType::F32, Shape::new(vec![1, 2, 4, 4])?, g)?,
            TensorPort::new("w1", DType::F32, Shape::new(vec![2, 2, 3, 3])?, g)?,
            TensorPort::new("b1", DType::F32, Shape::new(vec![2])?, g)?,
            TensorPort::new("w2", DType::F32, Shape::new(vec![2, 1, 1, 1])?, g)?,
            TensorPort::new("w_head", DType::F32, Shape::new(vec![8, 4])?, g)?,
        ],
        vec![
            TensorPort::new("obj_scores", DType::F32, Shape::new(vec![1, 4])?, g)?,
            TensorPort::new("class_probs", DType::F32, Shape::new(vec![1, 4])?, g)?,
        ],
        vec![
            GraphNode::new(
                "n_conv1",
                OpCode::Conv2d,
                "conv1",
                vec!["image".into(), "w1".into(), "b1".into()],
                vec!["c1".into()],
                conv1_attrs,
            )?,
            GraphNode::new(
                "n_silu",
                OpCode::Silu,
                "silu",
                vec!["c1".into()],
                vec!["s1".into()],
                AttributeMap::new(),
            )?,
            GraphNode::new(
                "n_pool",
                OpCode::MaxPool2d,
                "pool",
                vec!["s1".into()],
                vec!["p1".into()],
                pool_attrs,
            )?,
            GraphNode::new(
                "n_conv2",
                OpCode::Conv2d,
                "conv2_grouped",
                vec!["p1".into(), "w2".into()],
                vec!["c2".into()],
                conv2_attrs,
            )?,
            GraphNode::new(
                "n_add",
                OpCode::Add,
                "residual",
                vec!["c2".into(), "p1".into()],
                vec!["res".into()],
                AttributeMap::new(),
            )?,
            GraphNode::new(
                "n_reshape",
                OpCode::Reshape,
                "flatten",
                vec!["res".into()],
                vec!["flat".into()],
                reshape_attrs,
            )?,
            GraphNode::new(
                "n_ln",
                OpCode::LayerNorm,
                "norm",
                vec!["flat".into()],
                vec!["normed".into()],
                ln_attrs,
            )?,
            GraphNode::new(
                "n_matmul",
                OpCode::MatMul,
                "head_proj",
                vec!["normed".into(), "w_head".into()],
                vec!["logits".into()],
                AttributeMap::new(),
            )?,
            GraphNode::new(
                "n_sigmoid",
                OpCode::Sigmoid,
                "objectness",
                vec!["logits".into()],
                vec!["obj_scores".into()],
                AttributeMap::new(),
            )?,
            GraphNode::new(
                "n_softmax",
                OpCode::Softmax,
                "class_dist",
                vec!["logits".into()],
                vec!["class_probs".into()],
                sm_attrs,
            )?,
        ],
    )?;

    let img_vals: Vec<f32> = (0..32).map(|i| ((i as f32) - 15.5) * 0.125).collect();
    let w1_vals: Vec<f32> = (0..36)
        .map(|i| if i % 2 == 0 { 0.25 } else { -0.15 })
        .collect();
    let b1_vals = vec![0.1_f32, -0.2];
    let w2_vals = vec![0.75_f32, -0.5];
    let w_head_vals: Vec<f32> = (0..32).map(|i| ((i % 7) as f32 - 3.0) * 0.2).collect();

    let img_t = Tensor::from_values(Shape::new(vec![1, 2, 4, 4])?, &img_vals, g)?;
    let w1_t = Tensor::from_values(Shape::new(vec![2, 2, 3, 3])?, &w1_vals, g)?;
    let b1_t = Tensor::from_values(Shape::new(vec![2])?, &b1_vals, g)?;
    let w2_t = Tensor::from_values(Shape::new(vec![2, 1, 1, 1])?, &w2_vals, g)?;
    let wh_t = Tensor::from_values(Shape::new(vec![8, 4])?, &w_head_vals, g)?;

    let inputs = [
        ("image", img_t.clone()),
        ("w1", w1_t),
        ("b1", b1_t),
        ("w2", w2_t),
        ("w_head", wh_t),
    ];

    let (scalar_res, receipt) = execute_and_record_receipt(
        &graph,
        &inputs,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
        ReceiptRecordContext {
            job_id: "job:fss-139:neck-head-v2:001",
            preprocess_program: None,
            model_package_root: Some(ContentDigest::sha256(b"pkg-v2-detector")),
            virtual_clock: None,
            source_roots: &[],
            preprocess_resize: None,
        },
    );
    let scalar_out = scalar_res?;
    assert_eq!(scalar_out.nodes_executed(), 10);
    assert_eq!(receipt.outcome, ReceiptOutcome::Ok);
    receipt.verify(g, &receipt.compute_canonical_digest())?;

    // PlannedScalar equivalence!
    let plan =
        CompiledScalarPlan::compile(&graph, MemoryPlanLimits::default(), &ScalarExecCx::new())?;
    let req = plan.minimum_requirements();
    let planned_out = plan.run(
        &inputs,
        PeakExecBudget::new(req.macs, req.peak_bytes, req.scratch_bytes),
        &ScalarExecCx::new(),
    )?;

    // OptimizedGraph (with fused Conv2d+SiLU!) equivalence!
    let mut constants = BTreeMap::new();
    constants.insert("w1".to_owned(), w1_vals);
    constants.insert("b1".to_owned(), b1_vals);
    constants.insert("w2".to_owned(), w2_vals);
    constants.insert("w_head".to_owned(), w_head_vals);
    let optimized = OptimizedGraph::prepare(&graph, &constants, &ScalarExecCx::new())?;
    let (opt_out, _rep) = optimized.run_with_report(
        &[("image", img_t)],
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;

    let s_obj = scalar_out
        .get_output("obj_scores")
        .ok_or("missing obj_scores")?
        .to_vec::<f32>()?;
    let s_cls = scalar_out
        .get_output("class_probs")
        .ok_or("missing class_probs")?
        .to_vec::<f32>()?;

    assert!(
        s_obj
            .iter()
            .all(|&p| p.is_finite() && (0.0..=1.0).contains(&p))
    );
    let prob_sum: f32 = s_cls.iter().sum();
    assert!((prob_sum - 1.0_f32).abs() < 1e-5, "softmax sum={prob_sum}");

    // 0-ULP bit-exact equivalence across ScalarExecutor == PlannedScalar == OptimizedGraph!
    assert_eq!(
        bits(
            &planned_out
                .execution()
                .get_output("obj_scores")
                .ok_or("missing planned obj")?
                .to_vec::<f32>()?
        ),
        bits(&s_obj)
    );
    assert_eq!(
        bits(
            &planned_out
                .execution()
                .get_output("class_probs")
                .ok_or("missing planned cls")?
                .to_vec::<f32>()?
        ),
        bits(&s_cls)
    );
    assert_eq!(
        bits(
            &opt_out
                .get_output("obj_scores")
                .ok_or("missing opt obj")?
                .to_vec::<f32>()?
        ),
        bits(&s_obj)
    );
    assert_eq!(
        bits(
            &opt_out
                .get_output("class_probs")
                .ok_or("missing opt cls")?
                .to_vec::<f32>()?
        ),
        bits(&s_cls)
    );

    emit_caplog(
        "fss_139_detector_neck_head_v2_equivalence",
        "v2_conv_silu_pool_grouped_add_ln_matmul_sigmoid_softmax_0ulp_identical",
        "v2_conv_silu_pool_grouped_add_ln_matmul_sigmoid_softmax_0ulp_identical",
        "pass",
    );
    Ok(())
}

#[test]
fn detector_executor_faults_budget_cancel_generation_dtype_shape_and_nonfinite_abstain()
-> TestResult {
    let (graph, params, pkg_root) = load_canonical_detector_graph()?;
    let preprocess = PreprocessProgram::new(4, 4, ChannelTransform::Rgb, true);
    let image_tensor = preprocess.execute_bytes(&[128_u8; 48], 4, 4, 3, DETECTOR_GEN)?;

    let mut all_inputs: Vec<(String, Tensor)> =
        params.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    all_inputs.push(("image".to_owned(), image_tensor.clone()));
    let borrowed: Vec<(&str, Tensor)> = all_inputs
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();

    let baseline = ScalarExecutor::run(
        &graph,
        &borrowed,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;
    let exact_macs = baseline.executed_macs();
    let exact_bytes = baseline.allocated_bytes();

    // 1. MAC budget 1-short -> BudgetExhausted receipt, zero outputs!
    let (mac_res, mac_rec) = execute_and_record_receipt(
        &graph,
        &borrowed,
        ExecBudget::new(exact_macs - 1, exact_bytes),
        &ScalarExecCx::new(),
        ReceiptRecordContext {
            job_id: "job:fss-139:fault:mac-budget",
            preprocess_program: Some(&preprocess),
            model_package_root: Some(pkg_root),
            virtual_clock: None,
            source_roots: &[],
            preprocess_resize: None,
        },
    );
    assert!(matches!(mac_res, Err(ExecError::BudgetExceeded { .. })));
    assert_eq!(mac_rec.outcome, ReceiptOutcome::BudgetExhausted);
    assert!(mac_rec.output_root.is_none());
    assert!(mac_rec.operator_trace_digest.is_none());
    mac_rec.verify(DETECTOR_GEN, &mac_rec.compute_canonical_digest())?;

    // 2. Byte budget 1-short -> BudgetExhausted receipt, zero outputs!
    let (byte_res, byte_rec) = execute_and_record_receipt(
        &graph,
        &borrowed,
        ExecBudget::new(exact_macs, exact_bytes - 1),
        &ScalarExecCx::new(),
        ReceiptRecordContext {
            job_id: "job:fss-139:fault:byte-budget",
            preprocess_program: Some(&preprocess),
            model_package_root: Some(pkg_root),
            virtual_clock: None,
            source_roots: &[],
            preprocess_resize: None,
        },
    );
    assert!(matches!(byte_res, Err(ExecError::BudgetExceeded { .. })));
    assert_eq!(byte_rec.outcome, ReceiptOutcome::BudgetExhausted);
    byte_rec.verify(DETECTOR_GEN, &byte_rec.compute_canonical_digest())?;

    // 3. Cooperative cancellation -> drain confirmed + Cancelled receipt!
    let cancel_cx = ScalarExecCx::new();
    cancel_cx.request_cancellation();
    let (cancel_res, cancel_rec) = execute_and_record_receipt(
        &graph,
        &borrowed,
        ExecBudget::unlimited(),
        &cancel_cx,
        ReceiptRecordContext {
            job_id: "job:fss-139:fault:cancel",
            preprocess_program: Some(&preprocess),
            model_package_root: Some(pkg_root),
            virtual_clock: None,
            source_roots: &[],
            preprocess_resize: None,
        },
    );
    assert!(matches!(
        cancel_res,
        Err(ExecError::CancellationRequested { .. })
    ));
    assert!(cancel_cx.is_drain_completed());
    assert_eq!(cancel_rec.outcome, ReceiptOutcome::Cancelled);
    assert!(cancel_rec.cancel_reason.is_some());
    assert!(cancel_rec.output_root.is_none());
    cancel_rec.verify(DETECTOR_GEN, &cancel_rec.compute_canonical_digest())?;

    // 4. Stale tensor generation -> ERR-EXEC-GENERATION-MISMATCH-001!
    let stale_img = preprocess.execute_bytes(&[128_u8; 48], 4, 4, 3, Generation(999))?;
    let mut stale_inputs: Vec<(&str, Tensor)> = params
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();
    stale_inputs.push(("image", stale_img));
    let (gen_res, gen_rec) = execute_and_record_receipt(
        &graph,
        &stale_inputs,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
        ReceiptRecordContext {
            job_id: "job:fss-139:fault:stale-gen",
            preprocess_program: Some(&preprocess),
            model_package_root: Some(pkg_root),
            virtual_clock: None,
            source_roots: &[],
            preprocess_resize: None,
        },
    );
    assert!(matches!(gen_res, Err(ExecError::GenerationMismatch { .. })));
    assert_eq!(gen_rec.outcome, ReceiptOutcome::Error);
    assert_eq!(
        gen_rec.error_id.as_deref(),
        Some("ERR-EXEC-GENERATION-MISMATCH-001")
    );
    gen_rec.verify(DETECTOR_GEN, &gen_rec.compute_canonical_digest())?;

    // 5. Missing weight port -> ERR-EXEC-MISSING-PORT-001!
    let missing_inputs: Vec<(&str, Tensor)> = borrowed
        .iter()
        .filter(|(k, _)| *k != "head_kernel")
        .cloned()
        .collect();
    let (miss_res, miss_rec) = execute_and_record_receipt(
        &graph,
        &missing_inputs,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
        ReceiptRecordContext {
            job_id: "job:fss-139:fault:missing-port",
            preprocess_program: Some(&preprocess),
            model_package_root: Some(pkg_root),
            virtual_clock: None,
            source_roots: &[],
            preprocess_resize: None,
        },
    );
    assert!(matches!(miss_res, Err(ExecError::MissingInputPort { .. })));
    assert_eq!(
        miss_rec.error_id.as_deref(),
        Some("ERR-EXEC-MISSING-PORT-001")
    );

    // 6. Shape mismatch (wrong resolution [1, 3, 5, 5]) -> ERR-EXEC-SHAPE-MISMATCH-001!
    let wrong_shape_img =
        Tensor::from_values(Shape::new(vec![1, 3, 5, 5])?, &[0.5_f32; 75], DETECTOR_GEN)?;
    let mut shape_inputs: Vec<(&str, Tensor)> = params
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();
    shape_inputs.push(("image", wrong_shape_img));
    let (shape_res, shape_rec) = execute_and_record_receipt(
        &graph,
        &shape_inputs,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
        ReceiptRecordContext {
            job_id: "job:fss-139:fault:shape",
            preprocess_program: Some(&preprocess),
            model_package_root: Some(pkg_root),
            virtual_clock: None,
            source_roots: &[],
            preprocess_resize: None,
        },
    );
    assert!(matches!(shape_res, Err(ExecError::ShapeMismatch { .. })));
    assert_eq!(
        shape_rec.error_id.as_deref(),
        Some("ERR-EXEC-SHAPE-MISMATCH-001")
    );

    // 7. Unsupported raw U8 input offered directly -> ERR-EXEC-UNSUPPORTED-DTYPE-001!
    let u8_img = Tensor::from_values(Shape::new(vec![1, 3, 4, 4])?, &[128_u8; 48], DETECTOR_GEN)?;
    let mut dtype_inputs: Vec<(&str, Tensor)> = params
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();
    dtype_inputs.push(("image", u8_img));
    let (dtype_res, dtype_rec) = execute_and_record_receipt(
        &graph,
        &dtype_inputs,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
        ReceiptRecordContext {
            job_id: "job:fss-139:fault:dtype",
            preprocess_program: Some(&preprocess),
            model_package_root: Some(pkg_root),
            virtual_clock: None,
            source_roots: &[],
            preprocess_resize: None,
        },
    );
    assert!(matches!(dtype_res, Err(ExecError::UnsupportedDType { .. })));
    assert_eq!(
        dtype_rec.error_id.as_deref(),
        Some("ERR-EXEC-UNSUPPORTED-DTYPE-001")
    );

    // 8. Non-finite (NaN) input propagates honestly and policy abstains (never becomes absence or alert)!
    let mut nan_vals = vec![0.25_f32; 48];
    nan_vals[0] = f32::NAN;
    let nan_img = Tensor::from_values(Shape::new(vec![1, 3, 4, 4])?, &nan_vals, DETECTOR_GEN)?;
    let mut nan_inputs: Vec<(&str, Tensor)> = params
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();
    nan_inputs.push(("image", nan_img));
    let nan_out = ScalarExecutor::run(
        &graph,
        &nan_inputs,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;
    let head_vals = nan_out
        .get_output("head")
        .ok_or("missing nan head")?
        .to_vec::<f32>()?;
    assert!(head_vals[0].is_nan(), "NaN must not be silently clamped");
    let policy = ActivityThresholdPolicy::reference()?;
    assert_eq!(
        policy.classify(head_vals[0]),
        ExecutorModelOutcome::Abstained {
            reason: ExecutorAbstentionReason::NonFiniteScore,
            receipt_outcome: ReceiptOutcome::Ok,
        }
    );

    // 9. CompiledScalarPlan peak-budget 1-short refuses fail-closed!
    let plan =
        CompiledScalarPlan::compile(&graph, MemoryPlanLimits::default(), &ScalarExecCx::new())?;
    let req = plan.minimum_requirements();
    assert!(matches!(
        plan.run(
            &borrowed,
            PeakExecBudget::new(req.macs, req.peak_bytes - 1, req.scratch_bytes),
            &ScalarExecCx::new(),
        ),
        Err(PlannedExecError::BudgetExceeded { .. })
    ));

    emit_caplog(
        "fss_139_detector_faults_and_nonfinite_abstention",
        "budget_cancel_stale_gen_missing_port_shape_dtype_and_nan_abstain_verified",
        "budget_cancel_stale_gen_missing_port_shape_dtype_and_nan_abstain_verified",
        "pass",
    );
    Ok(())
}
