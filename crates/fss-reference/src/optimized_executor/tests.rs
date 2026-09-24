//! Differential certification of every optimized kernel against the scalar reference.
//!
//! Contract under test: BIT-IDENTICAL outputs (tolerance 0 ULP). Reason: each optimized kernel
//! performs, for every output element, the same IEEE-754 operations in the same order as the
//! scalar kernel (same reduction order, same `+0.0` start, bias last, padded taps skipped rather
//! than multiplied by zero, no reassociation and no fused multiply-add). NaN outputs must occur
//! at the same positions; their payload bits are not compared because Rust leaves NaN payload
//! propagation unspecified. Inputs are drawn from a fixed-seed generator (property style), and
//! include signed zeros, subnormals, huge magnitudes, infinities and NaN.

use std::collections::BTreeMap;

use fss_core::Generation;
use fss_model_ir::{
    AttrValue, AttributeMap, GraphNode, ModelIrGraph, ModelIrVersion, OpCode, TensorPort,
    infer_operator_outputs,
};
use fss_tensor::{DType, Shape, Tensor};

use super::pointwise::silu_in_place;
use super::{KernelBackend, OptimizedGraph, optimized_kernel_generation, scalar_kernel_generation};
use crate::scalar_executor::activation_silu;
use crate::{ExecBudget, ExecError, ScalarExecCx, ScalarExecutor};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const G: Generation = Generation(1);

/// SplitMix64: deterministic, seedable, dependency-free.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below(hi - lo + 1)
    }
    /// Mostly moderate values; `special` enables zeros, subnormals, huge values, inf and NaN.
    fn value(&mut self, special: bool) -> f32 {
        if special && self.below(16) == 0 {
            return match self.below(9) {
                0 => 0.0,
                1 => -0.0,
                2 => f32::from_bits(1 + self.below(1000) as u32),
                3 => 3.0e38,
                4 => -3.0e38,
                5 => f32::INFINITY,
                6 => f32::NEG_INFINITY,
                7 => f32::NAN,
                _ => 1.0e-30,
            };
        }
        let unit = (self.next() >> 40) as f32 / (1_u64 << 24) as f32;
        (unit * 4.0 - 2.0) * if self.below(8) == 0 { 50.0 } else { 1.0 }
    }
    fn values(&mut self, n: usize, special: bool) -> Vec<f32> {
        (0..n).map(|_| self.value(special)).collect()
    }
}

fn ints(v: &[usize]) -> AttrValue {
    AttrValue::IntList(v.iter().map(|&x| x as i64).collect())
}

/// One-node graph whose output port comes from the IR's own shape inference. `None` when the
/// random geometry is invalid for the operator.
fn one_node(
    op: OpCode,
    inputs: &[(&str, Vec<usize>)],
    attrs: AttributeMap,
) -> TestResult<Option<ModelIrGraph>> {
    let ports: Vec<TensorPort> = inputs
        .iter()
        .map(|(n, d)| TensorPort::new(*n, DType::F32, Shape::new(d.clone())?, G))
        .collect::<Result<_, _>>()?;
    let refs: Vec<&TensorPort> = ports.iter().collect();
    let names: Vec<String> = inputs.iter().map(|(n, _)| (*n).to_owned()).collect();
    let Ok(out) = infer_operator_outputs("n0", op, &refs, &["y".to_owned()], &attrs, G) else {
        return Ok(None);
    };
    let node = GraphNode::new("n0", op, "n0", names, vec!["y".to_owned()], attrs)?;
    Ok(Some(ModelIrGraph::new_validated(
        "diff",
        ModelIrVersion::V1,
        G,
        ports,
        out,
        vec![node],
    )?))
}

fn same_bits(a: &[f32], b: &[f32]) -> Result<(), String> {
    if a.len() != b.len() {
        return Err(format!("length {} vs {}", a.len(), b.len()));
    }
    for (i, (x, y)) in a.iter().zip(b).enumerate() {
        let ok = if x.is_nan() || y.is_nan() {
            x.is_nan() && y.is_nan()
        } else {
            x.to_bits() == y.to_bits()
        };
        if !ok {
            return Err(format!(
                "element {i}: optimized {x:e} ({:#010x}) vs scalar {y:e} ({:#010x})",
                x.to_bits(),
                y.to_bits()
            ));
        }
    }
    Ok(())
}

/// Run `graph` through the scalar reference (all inputs as tensors) and through the prepared
/// optimized graph (`constant` inputs bound at preparation); require identical accounting and
/// bit-identical outputs. Returns the kernel labels the optimized plan chose.
fn differential(
    graph: &ModelIrGraph,
    values: &BTreeMap<String, Vec<f32>>,
    constant: &[&str],
) -> TestResult<Vec<&'static str>> {
    let cx = ScalarExecCx::new();
    let mut all = Vec::new();
    let mut runtime = Vec::new();
    let mut constants = BTreeMap::new();
    for port in graph.inputs() {
        let v = values.get(port.name()).ok_or("missing value")?;
        let t = Tensor::from_values(port.shape().clone(), v, G)?;
        all.push((port.name().to_owned(), t.clone()));
        if constant.contains(&port.name()) {
            constants.insert(port.name().to_owned(), v.clone());
        } else {
            runtime.push((port.name().to_owned(), t));
        }
    }
    let scalar = ScalarExecutor::run(graph, &all, ExecBudget::unlimited(), &cx)?;
    let prepared = OptimizedGraph::prepare(graph, &constants, &cx)?;
    let optimized = prepared.run(&runtime, ExecBudget::unlimited(), &cx)?;
    assert_eq!(scalar.executed_macs(), optimized.executed_macs());
    assert_eq!(scalar.allocated_bytes(), optimized.allocated_bytes());
    assert_eq!(scalar.nodes_executed(), optimized.nodes_executed());
    assert_eq!(scalar.outputs().len(), optimized.outputs().len());
    for (name, s) in scalar.outputs() {
        let o = optimized
            .get_output(name)
            .ok_or("missing optimized output")?;
        assert_eq!(s.shape(), o.shape());
        assert_eq!(s.generation(), o.generation());
        same_bits(&o.to_vec::<f32>()?, &s.to_vec::<f32>()?).map_err(|e| format!("{name}: {e}"))?;
    }
    Ok(prepared.kernel_counts().into_keys().collect())
}

#[test]
fn silu_lanes_match_the_scalar_activation_bit_for_bit() {
    let mut rng = Rng(0x5117_0001);
    let mut values: Vec<f32> = (0..200_000)
        .map(|_| f32::from_bits(rng.next() as u32))
        .collect();
    values.extend((0..50_000).map(|_| rng.value(true)));
    values.extend([
        0.0,
        -0.0,
        f32::MIN_POSITIVE,
        -f32::MIN_POSITIVE,
        f32::MAX,
        f32::MIN,
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::NAN,
        -700.0,
        -700.000_06,
        -699.999_94,
        88.7,
        -88.7,
        1.0e-45,
    ]);
    // Offsets exercise every remainder length of the lane loop.
    for offset in 0..9 {
        let mut fast = values[offset..].to_vec();
        silu_in_place(&mut fast);
        let reference: Vec<f32> = values[offset..]
            .iter()
            .map(|v| activation_silu(*v))
            .collect();
        for (i, (f, r)) in fast.iter().zip(&reference).enumerate() {
            // The reference returns the canonical quiet NaN; so must the lanes (exact bits).
            assert_eq!(
                f.to_bits(),
                r.to_bits(),
                "offset {offset} index {i} input {:e}",
                values[offset + i]
            );
        }
    }
}

#[test]
fn conv2d_kernels_are_bit_identical_over_random_geometry() -> TestResult {
    let mut rng = Rng(0xC0_4E_2D);
    let mut checked = 0;
    let mut labels = BTreeMap::new();
    for case in 0..400 {
        let kind = case % 4;
        let groups_choice = rng.below(3);
        let base = rng.range(1, 4);
        let (c_in, c_out, groups) = match groups_choice {
            0 => (rng.range(1, 9), rng.range(1, 11), 1),
            1 => (base * 2, base * 2, base * 2), // depthwise
            _ => {
                let g = rng.range(2, 3);
                (g * rng.range(1, 3), g * rng.range(1, 4), g)
            }
        };
        let (k_h, k_w) = if kind == 0 {
            (1, 1)
        } else {
            (rng.range(1, 5), rng.range(1, 5))
        };
        let (s_h, s_w) = if kind == 0 {
            (1, 1)
        } else {
            (rng.range(1, 3), rng.range(1, 3))
        };
        let (d_h, d_w) = if kind == 3 {
            (rng.range(1, 3), rng.range(1, 3))
        } else {
            (1, 1)
        };
        let pads = if kind == 0 {
            [0, 0, 0, 0]
        } else {
            [rng.below(3), rng.below(3), rng.below(3), rng.below(3)]
        };
        let batch = rng.range(1, 2);
        let (h, w) = (rng.range(1, 14), rng.range(1, 21));
        let bias = rng.below(3) != 0;
        let special = case % 5 == 0;
        let mut attrs = AttributeMap::new();
        attrs.insert("strides".into(), ints(&[s_h, s_w]));
        attrs.insert("padding".into(), ints(&pads));
        attrs.insert("dilations".into(), ints(&[d_h, d_w]));
        if groups != 1 || rng.below(2) == 0 {
            attrs.insert("groups".into(), AttrValue::Int(groups as i64));
        }
        let mut inputs = vec![
            ("x", vec![batch, c_in, h, w]),
            ("w", vec![c_out, c_in / groups, k_h, k_w]),
        ];
        if bias {
            inputs.push(("b", vec![c_out]));
        }
        let Some(graph) = one_node(OpCode::Conv2d, &inputs, attrs)? else {
            continue;
        };
        let mut values = BTreeMap::new();
        for (name, dims) in &inputs {
            let n = dims.iter().product();
            values.insert((*name).to_owned(), rng.values(n, special));
        }
        let chosen =
            differential(&graph, &values, &["w", "b"]).map_err(|e| format!("case {case}: {e}"))?;
        for label in chosen {
            *labels.entry(label).or_insert(0) += 1;
        }
        checked += 1;
    }
    assert!(checked >= 300, "only {checked} valid random convolutions");
    // Every specialized convolution kernel was exercised, and nothing fell back silently.
    for label in [
        "conv2d.depthwise-row.v1",
        "conv2d.pointwise-gemm-mr4-nr8.v1",
        "conv2d.row-gemm-mr4-nr8.v1",
    ] {
        assert!(
            labels.contains_key(label),
            "{label} never exercised: {labels:?}"
        );
    }
    assert!(
        !labels.contains_key("scalar-reference-node.v1"),
        "{labels:?}"
    );
    Ok(())
}

#[test]
fn conv2d_with_runtime_weights_uses_the_recorded_reference_kernel() -> TestResult {
    let mut attrs = AttributeMap::new();
    attrs.insert("padding".into(), ints(&[1, 1, 1, 1]));
    let inputs = [("x", vec![1, 2, 5, 5]), ("w", vec![3, 2, 3, 3])];
    let graph = one_node(OpCode::Conv2d, &inputs, attrs)?.ok_or("valid conv")?;
    let mut rng = Rng(7);
    let values: BTreeMap<String, Vec<f32>> = inputs
        .iter()
        .map(|(n, d)| ((*n).to_owned(), rng.values(d.iter().product(), false)))
        .collect();
    // Weights supplied per run cannot be prepacked: the plan records the reference kernel.
    let chosen = differential(&graph, &values, &[])?;
    assert_eq!(chosen, vec!["scalar-reference-node.v1"]);
    Ok(())
}

fn conv_silu_graph(consumers: usize, bias: bool) -> TestResult<ModelIrGraph> {
    let port = |n: &str, d: Vec<usize>| TensorPort::new(n, DType::F32, Shape::new(d)?, G);
    let mut attrs = AttributeMap::new();
    attrs.insert("padding".into(), ints(&[1, 1, 1, 1]));
    attrs.insert("strides".into(), ints(&[2, 1]));
    let mut conv_inputs = vec!["x".to_owned(), "w".to_owned()];
    let mut inputs = vec![port("x", vec![1, 3, 9, 11])?, port("w", vec![6, 3, 3, 3])?];
    if bias {
        conv_inputs.push("b".to_owned());
        inputs.push(port("b", vec![6])?);
    }
    let mut nodes = vec![
        GraphNode::new(
            "c",
            OpCode::Conv2d,
            "c",
            conv_inputs,
            vec!["t".into()],
            attrs,
        )?,
        GraphNode::new(
            "s",
            OpCode::Silu,
            "s",
            vec!["t".into()],
            vec!["y".into()],
            AttributeMap::new(),
        )?,
    ];
    let mut outputs = vec![port("y", vec![1, 6, 5, 11])?];
    if consumers > 1 {
        nodes.push(GraphNode::new(
            "a",
            OpCode::Add,
            "a",
            vec!["t".into(), "y".into()],
            vec!["z".into()],
            AttributeMap::new(),
        )?);
        outputs.push(port("z", vec![1, 6, 5, 11])?);
    }
    Ok(ModelIrGraph::new_validated(
        "fuse",
        ModelIrVersion::V1,
        G,
        inputs,
        outputs,
        nodes,
    )?)
}

#[test]
fn fused_bias_silu_is_bit_identical_and_only_fuses_a_sole_consumer() -> TestResult {
    let mut rng = Rng(0xF05E);
    for (consumers, bias, fused) in [(1, true, true), (1, false, true), (2, true, false)] {
        let graph = conv_silu_graph(consumers, bias)?;
        let mut values = BTreeMap::new();
        values.insert("x".to_owned(), rng.values(3 * 9 * 11, true));
        values.insert("w".to_owned(), rng.values(6 * 27, false));
        values.insert("b".to_owned(), rng.values(6, false));
        let chosen = differential(&graph, &values, &["w", "b"])?;
        assert_eq!(
            chosen.contains(&"conv2d.row-gemm-mr4-nr8+silu.v1"),
            fused,
            "{chosen:?}"
        );
        assert_eq!(chosen.contains(&"silu.lanes8.v1"), !fused, "{chosen:?}");
    }
    Ok(())
}

#[test]
fn elementwise_and_broadcast_kernels_are_bit_identical() -> TestResult {
    let mut rng = Rng(0xB0AD);
    for case in 0..120 {
        let rank = rng.range(1, 4);
        let out: Vec<usize> = (0..rank).map(|_| rng.range(1, 6)).collect();
        // Each operand drops leading axes and/or collapses axes to 1 (numpy broadcasting).
        let operand = |rng: &mut Rng| -> Vec<usize> {
            let keep = rng.range(1, rank);
            out[rank - keep..]
                .iter()
                .map(|&d| if rng.below(3) == 0 { 1 } else { d })
                .collect()
        };
        let a = operand(&mut rng);
        let b = if case % 3 == 0 {
            out.clone()
        } else {
            operand(&mut rng)
        };
        let a = if case % 3 == 0 { out.clone() } else { a };
        for op in [OpCode::Add, OpCode::Sub, OpCode::Mul, OpCode::Div] {
            let inputs = [("a", a.clone()), ("b", b.clone())];
            let Some(graph) = one_node(op, &inputs, AttributeMap::new())? else {
                continue;
            };
            let mut values = BTreeMap::new();
            values.insert("a".to_owned(), rng.values(a.iter().product(), true));
            values.insert("b".to_owned(), rng.values(b.iter().product(), true));
            // Once with a constant operand (head-decode style), once fully runtime.
            differential(&graph, &values, &["b"])?;
            let chosen = differential(&graph, &values, &[])?;
            assert!(!chosen.contains(&"scalar-reference-node.v1"));
        }
        for op in [OpCode::Silu, OpCode::Sigmoid, OpCode::Relu] {
            let graph = one_node(op, &[("a", out.clone())], AttributeMap::new())?.ok_or("unary")?;
            let mut values = BTreeMap::new();
            values.insert("a".to_owned(), rng.values(out.iter().product(), true));
            let chosen = differential(&graph, &values, &[])?;
            assert!(!chosen.contains(&"scalar-reference-node.v1"));
        }
    }
    Ok(())
}

#[test]
fn maxpool_kernel_is_bit_identical_over_random_geometry() -> TestResult {
    let mut rng = Rng(0x9001);
    let mut checked = 0;
    for _ in 0..150 {
        let k = [rng.range(1, 5), rng.range(1, 5)];
        let mut attrs = AttributeMap::new();
        attrs.insert("kernel_size".into(), ints(&k));
        attrs.insert("strides".into(), ints(&[rng.range(1, 3), rng.range(1, 3)]));
        attrs.insert(
            "padding".into(),
            ints(&[
                rng.below(k[0]),
                rng.below(k[1]),
                rng.below(k[0]),
                rng.below(k[1]),
            ]),
        );
        let dims = vec![
            rng.range(1, 2),
            rng.range(1, 4),
            rng.range(1, 13),
            rng.range(1, 13),
        ];
        let Some(graph) = one_node(OpCode::MaxPool2d, &[("x", dims.clone())], attrs)? else {
            continue;
        };
        let mut values = BTreeMap::new();
        values.insert("x".to_owned(), rng.values(dims.iter().product(), true));
        let chosen = differential(&graph, &values, &[])?;
        assert_eq!(chosen, vec!["maxpool2d.direct.v1"]);
        checked += 1;
    }
    assert!(checked >= 100, "only {checked} valid pools");
    Ok(())
}

#[test]
fn layout_kernels_copy_exactly_the_reference_values() -> TestResult {
    let mut rng = Rng(0x1A70);
    let mut checked = 0;
    for case in 0..150 {
        let rank = rng.range(1, 4);
        let dims: Vec<usize> = (0..rank).map(|_| rng.range(1, 7)).collect();
        let n: usize = dims.iter().product();
        let mut values = BTreeMap::new();
        values.insert("x".to_owned(), rng.values(n, true));
        // Transpose with a random permutation.
        let mut perm: Vec<usize> = (0..rank).collect();
        for i in (1..rank).rev() {
            perm.swap(i, rng.below(i + 1));
        }
        let mut attrs = AttributeMap::new();
        if case % 4 != 0 {
            attrs.insert("permutation".into(), ints(&perm));
        }
        if let Some(graph) = one_node(OpCode::Transpose, &[("x", dims.clone())], attrs)? {
            assert_eq!(
                differential(&graph, &values, &[])?,
                vec!["gather.strided-runs.v1"]
            );
            checked += 1;
        }
        // Slice on a random axis subset with random starts/ends/steps.
        let axis = rng.below(rank);
        let start = rng.below(dims[axis]);
        let end = rng.range(start + 1, dims[axis]);
        let mut attrs = AttributeMap::new();
        attrs.insert("axes".into(), ints(&[axis]));
        attrs.insert("starts".into(), ints(&[start]));
        attrs.insert("ends".into(), ints(&[end]));
        attrs.insert("steps".into(), ints(&[rng.range(1, 2)]));
        if let Some(graph) = one_node(OpCode::Slice, &[("x", dims.clone())], attrs)? {
            assert_eq!(
                differential(&graph, &values, &[])?,
                vec!["gather.strided-runs.v1"]
            );
            checked += 1;
        }
        // Concat of two tensors along a random axis.
        let mut other = dims.clone();
        other[axis] = rng.range(1, 4);
        values.insert("z".to_owned(), rng.values(other.iter().product(), true));
        let mut attrs = AttributeMap::new();
        attrs.insert(
            "axis".into(),
            AttrValue::Int(axis as i64 - if case % 2 == 0 { rank as i64 } else { 0 }),
        );
        if let Some(graph) = one_node(OpCode::Concat, &[("x", dims.clone()), ("z", other)], attrs)?
        {
            assert_eq!(
                differential(&graph, &values, &[])?,
                vec!["concat.blocks.v1"]
            );
            checked += 1;
        }
        // Reshape to the flattened shape.
        let mut attrs = AttributeMap::new();
        attrs.insert("shape".into(), ints(&[n]));
        if let Some(graph) = one_node(OpCode::Reshape, &[("x", dims.clone())], attrs)? {
            assert_eq!(differential(&graph, &values, &[])?, vec!["reshape.copy.v1"]);
            checked += 1;
        }
    }
    assert!(checked >= 400, "only {checked} layout cases");
    Ok(())
}

#[test]
fn admission_refusals_match_the_scalar_reference() -> TestResult {
    let mut attrs = AttributeMap::new();
    attrs.insert("padding".into(), ints(&[1, 1, 1, 1]));
    let graph = one_node(
        OpCode::Conv2d,
        &[("x", vec![1, 2, 6, 6]), ("w", vec![4, 2, 3, 3])],
        attrs,
    )?
    .ok_or("valid conv")?;
    let cx = ScalarExecCx::new();
    let mut constants = BTreeMap::new();
    constants.insert("w".to_owned(), vec![0.5_f32; 72]);
    let prepared = OptimizedGraph::prepare(&graph, &constants, &cx)?;
    let x = Tensor::from_values(Shape::new(vec![1, 2, 6, 6])?, &[1.0_f32; 72], G)?;
    let w = Tensor::from_values(Shape::new(vec![4, 2, 3, 3])?, &[0.5_f32; 72], G)?;
    let scalar_budget = ScalarExecutor::run(
        &graph,
        &[("x", x.clone()), ("w", w)],
        ExecBudget::new(10, usize::MAX),
        &cx,
    );
    let optimized_budget = prepared.run(&[("x", x.clone())], ExecBudget::new(10, usize::MAX), &cx);
    assert!(matches!(
        scalar_budget,
        Err(ExecError::BudgetExceeded { .. })
    ));
    assert_eq!(scalar_budget.err(), optimized_budget.err());
    assert!(matches!(
        prepared.run(&[("w", x.clone())], ExecBudget::unlimited(), &cx),
        Err(ExecError::ShapeMismatch { .. })
    ));
    assert!(matches!(
        prepared.run::<&str>(&[], ExecBudget::unlimited(), &cx),
        Err(ExecError::MissingInputPort { .. })
    ));
    let other = Tensor::from_values(Shape::new(vec![1, 2, 6, 6])?, &[1.0_f32; 72], Generation(2))?;
    assert!(matches!(
        prepared.run(&[("x", other)], ExecBudget::unlimited(), &cx),
        Err(ExecError::GenerationMismatch { .. })
    ));
    let cancelled = ScalarExecCx::new();
    cancelled.request_cancellation();
    assert!(matches!(
        prepared.run(&[("x", x)], ExecBudget::unlimited(), &cancelled),
        Err(ExecError::CancellationRequested { .. })
    ));
    assert!(cancelled.is_drain_completed());
    Ok(())
}

#[test]
fn identities_bind_the_kernel_generation_and_constants() -> TestResult {
    assert_ne!(optimized_kernel_generation(), scalar_kernel_generation());
    assert_eq!(
        KernelBackend::OptimizedCpuV1.generation(),
        optimized_kernel_generation()
    );
    assert_eq!(
        KernelBackend::ScalarReference.generation(),
        scalar_kernel_generation()
    );
    assert_ne!(
        KernelBackend::OptimizedCpuV1.stable_id(),
        KernelBackend::ScalarReference.stable_id()
    );
    let graph = one_node(
        OpCode::Conv2d,
        &[("x", vec![1, 1, 3, 3]), ("w", vec![1, 1, 1, 1])],
        AttributeMap::new(),
    )?
    .ok_or("valid conv")?;
    let cx = ScalarExecCx::new();
    let digest = |w: f32| -> TestResult<_> {
        let mut c = BTreeMap::new();
        c.insert("w".to_owned(), vec![w]);
        let p = OptimizedGraph::prepare(&graph, &c, &cx)?;
        assert_eq!(p.kernel_generation(), optimized_kernel_generation());
        Ok(p.digest())
    };
    assert_eq!(digest(1.0)?, digest(1.0)?);
    assert_ne!(digest(1.0)?, digest(-1.0)?);
    // Repeated runs are bit-identical (no hidden state across invocations).
    let mut c = BTreeMap::new();
    c.insert("w".to_owned(), vec![0.3_f32]);
    let p = OptimizedGraph::prepare(&graph, &c, &cx)?;
    let x = Tensor::from_values(
        Shape::new(vec![1, 1, 3, 3])?,
        &[0.1_f32, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9],
        G,
    )?;
    let first = p.run(&[("x", x.clone())], ExecBudget::unlimited(), &cx)?;
    let second = p.run(&[("x", x)], ExecBudget::unlimited(), &cx)?;
    assert_eq!(
        first.get_output("y").ok_or("y")?.to_vec::<f32>()?,
        second.get_output("y").ok_or("y")?.to_vec::<f32>()?
    );
    Ok(())
}
