#![forbid(unsafe_code)]
//! Comprehensive certification suite for `FSS-142` (`fss-x4a.14.13`: packed-weight and tiled CPU
//! matrix kernels in `#![forbid(unsafe_code)]` safe Rust).
//!
//! Proves bit-for-bit (`0-ULP`) equivalence against [`ScalarExecutor`] across:
//! 1. Packed-weight Conv2d variants: dense 3x3, 1x1 pointwise, grouped (`groups=3`),
//!    depthwise (`groups=C`), strided/dilated/asymmetric-padded, biasless (`+0.0`), and fused
//!    `Conv2d + SiLU` — across non-tile-multiple channel/spatial edge dimensions (`MR=4, NR=8`).
//! 2. Tiled `4x8` broadcast batched `MatMul` across non-multiple edge shapes (`M=1..13`,
//!    `K=1..17`, `N=1..19`), higher-rank batch broadcasts (`[2, 1, M, K] x [1, 3, K, N]`), and
//!    runtime-operand attention-style matrix multiplies.
//! 3. Special IEEE-754 binary32 values (`-0.0`, subnormals, `±inf`, `NaN`) verifying exact sign
//!    bit preservation on finite/infinite cells and matching `NaN` positions.
//! 4. Structured scoped multi-threading invariance (`threads = 1, 2, 4`) + packed resident byte
//!    witness (`resident_bytes > 0`) + cancellation + budget refusal + `StaticKernelDispatcher`
//!    (`FSS-141`) receipt integration with zero scalar fallback.

use std::collections::BTreeMap;

use fss_core::Generation;
use fss_model_ir::{
    AttrValue, AttributeMap, GraphNode, ModelIrGraph, ModelIrVersion, OpCode, TensorPort,
};
use fss_reference::kernel_dispatch::{
    DispatchOutcomeState, KernelDispatchPolicy, StaticKernelDispatcher,
};
use fss_reference::optimized_executor::{ExecThreads, KernelBackend, OptimizedGraph};
use fss_reference::{ExecBudget, ExecError, ScalarExecCx, ScalarExecutor};
use fss_tensor::{DType, Shape, Tensor};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const KERNEL_GEN: Generation = Generation(142);

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn port(name: &str, dims: &[usize]) -> TestResult<TensorPort> {
    Ok(TensorPort::new(
        name,
        DType::F32,
        Shape::new(dims.to_vec())?,
        KERNEL_GEN,
    )?)
}

fn det_values(len: usize, seed: u64) -> Vec<f32> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let raw = ((state >> 33) as i32) % 2001 - 1000;
        out.push((raw as f32) * 0.003_906_25_f32);
    }
    out
}

fn assert_bit_exact_f32(label: &str, actual: &[f32], expected: &[f32]) {
    assert_eq!(actual.len(), expected.len(), "{label}: length mismatch");
    for (idx, (&a, &e)) in actual.iter().zip(expected.iter()).enumerate() {
        if a.is_nan() && e.is_nan() {
            continue;
        }
        assert_eq!(
            a.to_bits(),
            e.to_bits(),
            "{label}[{idx}]: bit mismatch actual={a:?} (0x{:08x}) vs expected={e:?} (0x{:08x})",
            a.to_bits(),
            e.to_bits()
        );
    }
}

struct ConvCase {
    name: &'static str,
    n: usize,
    c_in: usize,
    h_in: usize,
    w_in: usize,
    c_out: usize,
    k_h: usize,
    k_w: usize,
    strides: [usize; 2],
    padding: [usize; 4],
    dilations: [usize; 2],
    groups: usize,
    with_bias: bool,
    fuse_silu: bool,
}

fn conv_out_dim(in_d: usize, pad0: usize, pad1: usize, k: usize, dil: usize, s: usize) -> usize {
    let eff_k = dil * (k - 1) + 1;
    (in_d + pad0 + pad1 - eff_k) / s + 1
}

#[test]
fn packed_conv2d_variants_and_fused_silu_are_0ulp_bit_exact_across_threads() -> TestResult {
    let cases = [
        // Non-multiple channels & spatial edges around MR=4, NR=8 tiles
        ConvCase {
            name: "dense_3x3_asym_pad_nonmultiple",
            n: 2,
            c_in: 5,
            h_in: 7,
            w_in: 11,
            c_out: 7,
            k_h: 3,
            k_w: 3,
            strides: [1, 1],
            padding: [1, 2, 0, 1],
            dilations: [1, 1],
            groups: 1,
            with_bias: true,
            fuse_silu: false,
        },
        // 1x1 pointwise flattened kernel + fused SiLU
        ConvCase {
            name: "pointwise_1x1_fused_silu",
            n: 1,
            c_in: 9,
            h_in: 5,
            w_in: 13,
            c_out: 11,
            k_h: 1,
            k_w: 1,
            strides: [1, 1],
            padding: [0, 0, 0, 0],
            dilations: [1, 1],
            groups: 1,
            with_bias: true,
            fuse_silu: true,
        },
        // Grouped convolution (groups=3) with non-multiple channels per group & biasless
        ConvCase {
            name: "grouped_3_strided_biasless",
            n: 2,
            c_in: 9,
            h_in: 8,
            w_in: 10,
            c_out: 15,
            k_h: 3,
            k_w: 2,
            strides: [2, 1],
            padding: [1, 0, 1, 1],
            dilations: [1, 1],
            groups: 3,
            with_bias: false,
            fuse_silu: false,
        },
        // Depthwise convolution (groups == c_in == c_out) with dilation + fused SiLU
        ConvCase {
            name: "depthwise_dilated_fused_silu",
            n: 1,
            c_in: 7,
            h_in: 9,
            w_in: 13,
            c_out: 7,
            k_h: 3,
            k_w: 3,
            strides: [1, 2],
            padding: [2, 2, 2, 2],
            dilations: [2, 2],
            groups: 7,
            with_bias: true,
            fuse_silu: true,
        },
    ];

    let cx = ScalarExecCx::new();
    for (idx, c) in cases.iter().enumerate() {
        let h_out = conv_out_dim(
            c.h_in,
            c.padding[0],
            c.padding[2],
            c.k_h,
            c.dilations[0],
            c.strides[0],
        );
        let w_out = conv_out_dim(
            c.w_in,
            c.padding[1],
            c.padding[3],
            c.k_w,
            c.dilations[1],
            c.strides[1],
        );
        let cpg_in = c.c_in / c.groups;

        let mut inputs = vec![
            port("x", &[c.n, c.c_in, c.h_in, c.w_in])?,
            port("w", &[c.c_out, cpg_in, c.k_h, c.k_w])?,
        ];
        let mut conv_inputs = vec!["x".to_owned(), "w".to_owned()];
        if c.with_bias {
            inputs.push(port("b", &[c.c_out])?);
            conv_inputs.push("b".to_owned());
        }
        let mut attrs = AttributeMap::new();
        attrs.insert(
            "strides".to_owned(),
            AttrValue::IntList(vec![c.strides[0] as i64, c.strides[1] as i64]),
        );
        attrs.insert(
            "padding".to_owned(),
            AttrValue::IntList(c.padding.iter().map(|&v| v as i64).collect()),
        );
        attrs.insert(
            "dilations".to_owned(),
            AttrValue::IntList(vec![c.dilations[0] as i64, c.dilations[1] as i64]),
        );
        attrs.insert("groups".to_owned(), AttrValue::Int(c.groups as i64));

        let final_out_name = if c.fuse_silu { "y_silu" } else { "y_conv" };
        let mut nodes = vec![GraphNode::new(
            "conv0",
            OpCode::Conv2d,
            "conv",
            conv_inputs,
            vec!["y_conv".to_owned()],
            attrs,
        )?];
        if c.fuse_silu {
            nodes.push(GraphNode::new(
                "silu0",
                OpCode::Silu,
                "silu",
                vec!["y_conv".to_owned()],
                vec!["y_silu".to_owned()],
                AttributeMap::new(),
            )?);
        }

        let graph = ModelIrGraph::new_validated(
            format!("fss:fss142:{}", c.name),
            ModelIrVersion::V2,
            KERNEL_GEN,
            inputs,
            vec![port(final_out_name, &[c.n, c.c_out, h_out, w_out])?],
            nodes,
        )?;

        let x_vals = det_values(c.n * c.c_in * c.h_in * c.w_in, 100 + idx as u64);
        let w_vals = det_values(c.c_out * cpg_in * c.k_h * c.k_w, 200 + idx as u64);
        let b_vals = det_values(c.c_out, 300 + idx as u64);

        let mut constants = BTreeMap::new();
        constants.insert("w".to_owned(), w_vals.clone());
        let x_tensor = Tensor::from_values(
            Shape::new(vec![c.n, c.c_in, c.h_in, c.w_in])?,
            &x_vals,
            KERNEL_GEN,
        )?;
        let mut scalar_inputs = vec![
            ("x".to_owned(), x_tensor.clone()),
            (
                "w".to_owned(),
                Tensor::from_values(
                    Shape::new(vec![c.c_out, cpg_in, c.k_h, c.k_w])?,
                    &w_vals,
                    KERNEL_GEN,
                )?,
            ),
        ];
        if c.with_bias {
            constants.insert("b".to_owned(), b_vals.clone());
            scalar_inputs.push((
                "b".to_owned(),
                Tensor::from_values(Shape::new(vec![c.c_out])?, &b_vals, KERNEL_GEN)?,
            ));
        }

        // 1. Scalar reference oracle
        let scalar_out = ScalarExecutor::run(&graph, &scalar_inputs, ExecBudget::unlimited(), &cx)?;
        let expected = scalar_out
            .get_output(final_out_name)
            .ok_or("missing scalar conv output")?
            .to_vec::<f32>()?;

        // 2. OptimizedGraph packed kernel across threads = 1, 2, 4
        let prepared = OptimizedGraph::prepare(&graph, &constants, &cx)?;
        assert!(
            prepared.resident_bytes() > 0,
            "{}: packed weights must be resident",
            c.name
        );
        for t in [1_usize, 2, 4] {
            let (opt_out, report) = prepared.run_threaded(
                &[("x", x_tensor.clone())],
                ExecBudget::unlimited(),
                ExecThreads::new(t)?,
                &cx,
            )?;
            assert!(report.resident_bytes > 0);
            let actual = opt_out
                .get_output(final_out_name)
                .ok_or("missing optimized conv output")?
                .to_vec::<f32>()?;
            assert_bit_exact_f32(c.name, &actual, &expected);
        }

        // 3. StaticKernelDispatcher (FSS-141) certifies zero scalar fallback + 0-ULP oracle match!
        let dispatched = StaticKernelDispatcher::compile(
            &graph,
            &constants,
            KernelDispatchPolicy {
                backend: KernelBackend::OptimizedCpuV1,
                threads: ExecThreads::new(2)?,
                allow_scalar_fallback: false,
                verify_against_scalar_oracle: true,
                ..KernelDispatchPolicy::default()
            },
            &cx,
        )?;
        assert_eq!(
            dispatched.receipt().outcome_state,
            DispatchOutcomeState::StaticOptimizedExact
        );
        assert_eq!(dispatched.receipt().fallback_node_count, 0);
        let exec = dispatched.execute(&[("x", x_tensor)], ExecBudget::unlimited(), &cx)?;
        assert!(exec.oracle_bit_exact_verified);
    }

    emit_caplog(
        "fss_142_packed_conv2d",
        "dense_pointwise_grouped_depthwise_and_fused_silu_0ulp_across_threads",
        "dense_pointwise_grouped_depthwise_and_fused_silu_0ulp_across_threads",
        "pass",
    );
    Ok(())
}

#[test]
fn tiled_4x8_broadcast_matmul_edge_shapes_ieee754_specials_and_faults() -> TestResult {
    let cx = ScalarExecCx::new();

    // 1. Edge dimensions around MR=4, NR=8 tiles with higher-rank broadcast batches.
    let shapes: &[(&[usize], &[usize], &[usize])] = &[
        (&[1, 1], &[1, 1], &[1, 1]),
        (&[3, 7], &[7, 5], &[3, 5]),
        (&[4, 8], &[8, 8], &[4, 8]),
        (&[5, 13], &[13, 17], &[5, 17]),
        (&[13, 17], &[17, 19], &[13, 19]),
        (&[2, 1, 5, 9], &[1, 3, 9, 11], &[2, 3, 5, 11]),
    ];

    for (idx, &(a_dims, b_dims, out_dims)) in shapes.iter().enumerate() {
        let graph = ModelIrGraph::new_validated(
            format!("fss:fss142:matmul:{idx}"),
            ModelIrVersion::V2,
            KERNEL_GEN,
            vec![port("a", a_dims)?, port("b", b_dims)?],
            vec![port("c", out_dims)?],
            vec![GraphNode::new(
                "mm0",
                OpCode::MatMul,
                "matmul",
                vec!["a".to_owned(), "b".to_owned()],
                vec!["c".to_owned()],
                AttributeMap::new(),
            )?],
        )?;

        let a_len: usize = a_dims.iter().product();
        let b_len: usize = b_dims.iter().product();
        let a_vals = det_values(a_len, 1000 + idx as u64);
        let b_vals = det_values(b_len, 2000 + idx as u64);

        let a_tensor = Tensor::from_values(Shape::new(a_dims.to_vec())?, &a_vals, KERNEL_GEN)?;
        let b_tensor = Tensor::from_values(Shape::new(b_dims.to_vec())?, &b_vals, KERNEL_GEN)?;

        let scalar = ScalarExecutor::run(
            &graph,
            &[
                ("a".to_owned(), a_tensor.clone()),
                ("b".to_owned(), b_tensor.clone()),
            ],
            ExecBudget::unlimited(),
            &cx,
        )?;
        let expected = scalar
            .get_output("c")
            .ok_or("missing scalar matmul output")?
            .to_vec::<f32>()?;

        // Test runtime-runtime operands (attention style) with measured stack accumulator scratch.
        let prepared_runtime = OptimizedGraph::prepare(&graph, &BTreeMap::new(), &cx)?;
        let (opt_out, report) = prepared_runtime.run_with_report(
            &[("a", a_tensor.clone()), ("b", b_tensor.clone())],
            ExecBudget::unlimited(),
            &cx,
        )?;
        assert!(report.scratch_bytes >= 4 * 8 * 4);
        let actual = opt_out
            .get_output("c")
            .ok_or("missing opt matmul output")?
            .to_vec::<f32>()?;
        assert_bit_exact_f32("matmul_runtime", &actual, &expected);

        let dispatched = StaticKernelDispatcher::compile(
            &graph,
            &BTreeMap::new(),
            KernelDispatchPolicy {
                backend: KernelBackend::OptimizedCpuV1,
                threads: ExecThreads::SINGLE,
                allow_scalar_fallback: false,
                verify_against_scalar_oracle: true,
                ..KernelDispatchPolicy::default()
            },
            &cx,
        )?;
        assert_eq!(
            dispatched.receipt().outcome_state,
            DispatchOutcomeState::StaticOptimizedExact
        );
        let exec = dispatched.execute(
            &[("a", a_tensor), ("b", b_tensor)],
            ExecBudget::unlimited(),
            &cx,
        )?;
        assert!(exec.oracle_bit_exact_verified);
    }

    // 2. Special IEEE-754 binary32 values: -0.0, subnormals, ±inf, NaN!
    let special_graph = ModelIrGraph::new_validated(
        "fss:fss142:matmul:ieee754",
        ModelIrVersion::V2,
        KERNEL_GEN,
        vec![port("a", &[5, 4])?, port("b", &[4, 9])?],
        vec![port("c", &[5, 9])?],
        vec![GraphNode::new(
            "mm_spec",
            OpCode::MatMul,
            "matmul_spec",
            vec!["a".to_owned(), "b".to_owned()],
            vec!["c".to_owned()],
            AttributeMap::new(),
        )?],
    )?;
    let specials = [
        -0.0_f32,
        0.0_f32,
        f32::from_bits(1),
        f32::from_bits(0x8000_0001),
        1.5_f32,
        -2.25_f32,
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::NAN,
    ];
    let a_spec: Vec<f32> = (0..20).map(|i| specials[i % specials.len()]).collect();
    let b_spec: Vec<f32> = (0..36)
        .map(|i| specials[(i * 5 + 3) % specials.len()])
        .collect();
    let a_spec_t = Tensor::from_values(Shape::new(vec![5, 4])?, &a_spec, KERNEL_GEN)?;
    let b_spec_t = Tensor::from_values(Shape::new(vec![4, 9])?, &b_spec, KERNEL_GEN)?;

    let scalar_spec = ScalarExecutor::run(
        &special_graph,
        &[
            ("a".to_owned(), a_spec_t.clone()),
            ("b".to_owned(), b_spec_t.clone()),
        ],
        ExecBudget::unlimited(),
        &cx,
    )?;
    let prepared_spec = OptimizedGraph::prepare(&special_graph, &BTreeMap::new(), &cx)?;
    let opt_spec = prepared_spec.run(
        &[("a", a_spec_t.clone()), ("b", b_spec_t.clone())],
        ExecBudget::unlimited(),
        &cx,
    )?;
    assert_bit_exact_f32(
        "matmul_ieee754_specials",
        &opt_spec
            .get_output("c")
            .ok_or("missing c")?
            .to_vec::<f32>()?,
        &scalar_spec
            .get_output("c")
            .ok_or("missing c")?
            .to_vec::<f32>()?,
    );

    // 3. Cancellation and budget refusal fail closed cleanly.
    let cancel_cx = ScalarExecCx::new();
    cancel_cx.request_cancellation();
    let cancel_err = prepared_spec
        .run(
            &[("a", a_spec_t.clone()), ("b", b_spec_t.clone())],
            ExecBudget::unlimited(),
            &cancel_cx,
        )
        .expect_err("cancelled tiled matmul must fail closed");
    assert!(matches!(
        cancel_err,
        ExecError::CancellationRequested { .. }
    ));

    let tight_budget = ExecBudget {
        max_macs: 1,
        ..ExecBudget::unlimited()
    };
    let budget_err = prepared_spec
        .run(&[("a", a_spec_t), ("b", b_spec_t)], tight_budget, &cx)
        .expect_err("over-budget tiled matmul must fail closed");
    assert!(matches!(budget_err, ExecError::BudgetExceeded { .. }));

    emit_caplog(
        "fss_142_tiled_matmul_and_ieee754",
        "edge_shapes_broadcast_ieee754_specials_cancel_and_budget_verified",
        "edge_shapes_broadcast_ieee754_specials_cancel_and_budget_verified",
        "pass",
    );
    Ok(())
}
