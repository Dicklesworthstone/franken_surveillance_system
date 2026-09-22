#![forbid(unsafe_code)]
//! Public execution, whole-graph admission and unchanged-kernel parity contracts.
use fss_core::Generation;
use fss_model_ir::{AttrValue, AttributeMap, GraphNode, MemoryPlanLimits, ModelIrGraph,
    ModelIrVersion, OpCode, TensorPort};
use fss_reference::{ExecBudget, ExecError, ScalarExecCx, ScalarExecutor};
use fss_reference::planned_scalar::{CompiledScalarPlan, PeakExecBudget, PlannedExecError};
use fss_tensor::{DType, Shape, Tensor};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const GEN: Generation = Generation(3);
fn port(name: &str, dims: &[usize]) -> Test<TensorPort> {
    Ok(TensorPort::new(name, DType::F32, Shape::new(dims)?, GEN)?)
}
fn tensor(dims: &[usize], values: &[f32]) -> Test<Tensor> {
    Ok(Tensor::from_values(Shape::new(dims)?, values, GEN)?)
}
fn node(id: &str, op: OpCode, inputs: &[&str], output: &str, attrs: AttributeMap) -> Test<GraphNode> {
    Ok(GraphNode::new(id, op, id, inputs.iter().map(|s| (*s).to_owned()).collect(), vec![output.into()], attrs)?)
}
fn attrs(entries: &[(&str, AttrValue)]) -> AttributeMap {
    entries.iter().map(|(name, value)| ((*name).into(), value.clone())).collect()
}
fn plan(graph: &ModelIrGraph) -> Test<CompiledScalarPlan> {
    Ok(CompiledScalarPlan::compile(graph, MemoryPlanLimits::default(), &ScalarExecCx::new())?)
}
fn exact(plan: &CompiledScalarPlan) -> PeakExecBudget {
    let r = plan.minimum_requirements(); PeakExecBudget::new(r.macs, r.peak_bytes, r.scratch_bytes)
}
fn generous() -> PeakExecBudget { PeakExecBudget::new(100_000_000, 100_000_000, 100_000_000) }
fn chain(n: usize) -> Test<ModelIrGraph> {
    let mut nodes = Vec::new(); let mut input = "x".to_owned();
    for i in 0..n {
        let output = format!("v{i:04}");
        nodes.push(node(&format!("n{i:04}"), OpCode::Relu, &[&input], &output, AttributeMap::new())?);
        input = output;
    }
    Ok(ModelIrGraph::new_validated("graph:planned-chain", ModelIrVersion::V1, GEN,
        vec![port("x", &[4])?], vec![port(&input, &[4])?], nodes)?)
}
fn bits(tensor: &Tensor) -> Test<Vec<u32>> {
    Ok(tensor.to_vec::<f32>()?.into_iter().map(f32::to_bits).collect())
}
fn parity<S: AsRef<str>>(graph: &ModelIrGraph, inputs: &[(S, Tensor)]) -> Test {
    let p = plan(graph)?;
    let legacy = ScalarExecutor::run(graph, inputs, ExecBudget::unlimited(), &ScalarExecCx::new())?;
    let planned = p.run(inputs, generous(), &ScalarExecCx::new())?;
    assert_eq!(legacy.executed_macs(), planned.execution().executed_macs());
    assert_eq!(legacy.allocated_bytes(), planned.execution().allocated_bytes());
    assert_eq!(legacy.nodes_executed(), planned.execution().nodes_executed());
    assert_eq!(legacy.outputs().len(), planned.execution().outputs().len());
    for (name, old) in legacy.outputs() {
        let new = planned.execution().get_output(name).ok_or("missing planned output")?;
        assert_eq!(old.shape(), new.shape()); assert_eq!(old.generation(), new.generation());
        assert_eq!(bits(old)?, bits(new)?, "output {name}");
    }
    assert_eq!(planned.receipt().graph(), graph.content_digest()?);
    assert_eq!(planned.receipt().plan(), p.digest());
    Ok(())
}

#[test]
fn deep_graph_executes_below_the_legacy_cumulative_memory_limit() -> Test {
    let g = chain(100)?; let p = plan(&g)?;
    let input = [("x", tensor(&[4], &[-2., -0., 3., 8.])?)];
    assert_eq!(p.memory().cumulative_bytes(), 1616);
    assert_eq!(p.minimum_requirements().peak_bytes, 80);
    assert_eq!(p.minimum_requirements().scratch_bytes, 32);
    assert!(matches!(ScalarExecutor::run(&g, &input, ExecBudget::new(400, 80), &ScalarExecCx::new()),
        Err(ExecError::BudgetExceeded { .. })));
    let result = ScalarExecutor::run_peak(&g, &input, exact(&p), &ScalarExecCx::new())?;
    assert_eq!(result.execution().get_output("v0099").ok_or("missing output")?.to_vec::<f32>()?, vec![0., 0., 3., 8.]);
    assert_eq!(result.execution().allocated_bytes(), 1616);
    assert_eq!(result.execution().executed_macs(), 400);
    assert_eq!(result.receipt().peak_live_tensor_bytes(), 48);
    assert_eq!(result.receipt().released_values(), 99);
    parity(&g, &input)
}

#[test]
fn each_resource_boundary_refuses_one_below_and_accepts_exact() -> Test {
    let g = chain(8)?; let p = plan(&g)?; let input = [("x", tensor(&[4], &[1., 2., 3., 4.])?)];
    let b = exact(&p);
    for below in [PeakExecBudget { max_macs: b.max_macs - 1, ..b },
        PeakExecBudget { max_peak_bytes: b.max_peak_bytes - 1, ..b },
        PeakExecBudget { max_scratch_bytes: b.max_scratch_bytes - 1, ..b }] {
        assert!(matches!(p.run(&input, below, &ScalarExecCx::new()), Err(PlannedExecError::BudgetExceeded { .. })));
    }
    let a = p.run(&input, b, &ScalarExecCx::new())?;
    let again = p.run(&input, b, &ScalarExecCx::new())?;
    assert_eq!(a.receipt(), again.receipt());
    Ok(())
}

#[test]
fn branch_inputs_repeated_uses_and_intermediate_outputs_survive_correctly() -> Test {
    let g = ModelIrGraph::new_validated("graph:branches", ModelIrVersion::V1, GEN,
        vec![port("x", &[4])?], vec![port("a", &[4])?, port("d", &[4])?], vec![
            node("1", OpCode::Relu, &["x"], "a", AttributeMap::new())?,
            node("2", OpCode::Add, &["a", "a"], "b", AttributeMap::new())?,
            node("3", OpCode::Mul, &["a", "b"], "c", AttributeMap::new())?,
            node("4", OpCode::Sub, &["c", "b"], "d", AttributeMap::new())?,
        ])?;
    let input = [("x", tensor(&[4], &[-1., 2., 3., 4.])?)];
    let p = plan(&g)?; let result = p.run(&input, exact(&p), &ScalarExecCx::new())?;
    assert_eq!(result.receipt().released_values(), 2);
    assert_eq!(result.execution().outputs().len(), 2);
    parity(&g, &input)
}

#[test]
fn full_backing_storage_is_charged_for_narrow_and_overlapping_views() -> Test {
    let g = chain(4)?; let p = plan(&g)?;
    let whole = tensor(&[100], &[2.; 100])?;
    let narrow = whole.slice(0, 10, 14, 1)?;
    let input = [("x", narrow)];
    match p.run(&input, exact(&p), &ScalarExecCx::new()) {
        Err(PlannedExecError::BudgetExceeded { required, .. }) => {
            assert_eq!(required.input_backing_bytes, 400);
            assert_eq!(required.peak_bytes, 464);
        }
        other => return Err(format!("expected backing-storage refusal, got {other:?}").into()),
    }
    let result = p.run(&input, PeakExecBudget::new(16, 464, 32), &ScalarExecCx::new())?;
    assert_eq!(result.receipt().peak_live_tensor_bytes(), 432);
    parity(&g, &input)
}

#[test]
fn actual_strides_and_offsets_are_not_replaced_by_contiguous_assumptions() -> Test {
    let g = ModelIrGraph::new_validated("graph:strided", ModelIrVersion::V1, GEN,
        vec![port("x", &[3, 2])?], vec![port("y", &[3, 2])?],
        vec![node("relu", OpCode::Relu, &["x"], "y", AttributeMap::new())?])?;
    let input = tensor(&[2, 4], &[-3., 1., 2., 0., 4., -5., 6., 0.])?.slice(1, 0, 3, 1)?.transpose(0, 1)?;
    assert!(!input.is_c_contiguous());
    parity(&g, &[("x", input)])
}

#[test]
fn missing_duplicate_extra_and_wrong_generation_bindings_fail_closed() -> Test {
    let g = chain(2)?; let p = plan(&g)?; let x = tensor(&[4], &[1.; 4])?;
    for bindings in [vec![], vec![("wrong", x.clone())], vec![("x", x.clone()), ("x", x.clone())],
        vec![("x", x.clone()), ("extra", x.clone())]] {
        assert!(matches!(p.run(&bindings, generous(), &ScalarExecCx::new()), Err(PlannedExecError::InputSet)));
    }
    let stale = Tensor::from_values(Shape::new([4])?, &[1_f32; 4], Generation(4))?;
    let wrong_shape = tensor(&[2, 2], &[1.; 4])?;
    let wrong_dtype = Tensor::from_values(Shape::new([4])?, &[1_i32; 4], GEN)?;
    for wrong in [stale, wrong_shape, wrong_dtype] {
        assert!(matches!(p.run(&[("x", wrong)], generous(), &ScalarExecCx::new()), Err(PlannedExecError::InputContract)));
    }
    p.run(&[("x", x)], exact(&p), &ScalarExecCx::new())?;
    Ok(())
}

#[test]
fn cancellation_drains_and_does_not_poison_reusable_plan() -> Test {
    let g = chain(8)?; let cx = ScalarExecCx::new(); cx.request_cancellation();
    assert!(matches!(CompiledScalarPlan::compile(&g, MemoryPlanLimits::default(), &cx),
        Err(PlannedExecError::Execution(ExecError::CancellationRequested { .. }))));
    assert!(cx.is_drain_completed());
    let p = plan(&g)?;
    let input = [("x", tensor(&[4], &[2.; 4])?)];
    let cx = ScalarExecCx::new(); cx.request_cancellation();
    assert!(matches!(p.run(&input, exact(&p), &cx),
        Err(PlannedExecError::Execution(ExecError::CancellationRequested { .. }))));
    assert!(cx.is_drain_completed());
    p.run(&input, exact(&p), &ScalarExecCx::new())?;
    Ok(())
}

#[test]
fn unused_nodes_execute_and_pass_through_outputs_remain_exact() -> Test {
    let g = ModelIrGraph::new_validated("graph:unused", ModelIrVersion::V1, GEN,
        vec![port("x", &[4])?, port("spare", &[2])?], vec![port("x", &[4])?],
        vec![node("unused", OpCode::Relu, &["x"], "dead", AttributeMap::new())?])?;
    let inputs = [("x", tensor(&[4], &[-2., -0., f32::from_bits(0x7fc01234), 8.])?),
        ("spare", tensor(&[2], &[1., 2.])?)];
    let p = plan(&g)?; let result = p.run(&inputs, exact(&p), &ScalarExecCx::new())?;
    assert_eq!(result.execution().nodes_executed(), 1); assert_eq!(result.receipt().released_values(), 1);
    assert_eq!(bits(result.execution().get_output("x").ok_or("missing passthrough")?)?, bits(&inputs[0].1)?);
    parity(&g, &inputs)
}

#[test]
fn zero_sized_softmax_still_reserves_its_axis_scratch() -> Test {
    let g = ModelIrGraph::new_validated("graph:empty-softmax", ModelIrVersion::V1, GEN,
        vec![port("x", &[0, 1024])?], vec![port("y", &[0, 1024])?],
        vec![node("softmax", OpCode::Softmax, &["x"], "y", AttributeMap::new())?])?;
    let p = plan(&g)?;
    assert_eq!(p.minimum_requirements().peak_bytes, 4096);
    assert_eq!(p.minimum_requirements().scratch_bytes, 4096);
    let input = [("x", tensor(&[0, 1024], &[])?)];
    assert!(matches!(p.run(&input, PeakExecBudget::new(0, 0, 0), &ScalarExecCx::new()),
        Err(PlannedExecError::BudgetExceeded { .. })));
    let result = p.run(&input, exact(&p), &ScalarExecCx::new())?;
    assert_eq!(result.execution().get_output("y").ok_or("empty output")?.num_elements()?, 0);
    assert_eq!(result.execution().allocated_bytes(), 0);
    Ok(())
}

#[test]
fn late_invalid_embedding_index_cannot_publish_an_earlier_graph_output() -> Test {
    let ids = TensorPort::new("ids", DType::I64, Shape::new([1])?, GEN)?;
    let g = ModelIrGraph::new_validated("graph:late-refusal", ModelIrVersion::V1, GEN,
        vec![port("x", &[2, 2])?, ids], vec![port("a", &[2, 2])?, port("z", &[1, 2])?],
        vec![node("a", OpCode::Relu, &["x"], "a", AttributeMap::new())?,
            node("z", OpCode::Embedding, &["ids", "a"], "z", AttributeMap::new())?])?;
    let p = plan(&g)?;
    let inputs = [("x", tensor(&[2, 2], &[1., 2., 3., 4.])?),
        ("ids", Tensor::from_values(Shape::new([1])?, &[2_i64], GEN)?)];
    assert!(matches!(p.run(&inputs, exact(&p), &ScalarExecCx::new()),
        Err(PlannedExecError::Execution(ExecError::ShapeMismatch { .. }))));
    let valid = [("x", inputs[0].1.clone()), ("ids", Tensor::from_values(Shape::new([1])?, &[1_i64], GEN)?)];
    parity(&g, &valid)
}

#[test]
fn compiled_identity_binds_graph_and_is_independent_of_construction_order() -> Test {
    let g = chain(4)?; let mut nodes = g.nodes().to_vec(); nodes.reverse();
    let reordered = ModelIrGraph::new_validated(g.id(), g.version(), g.generation(),
        g.inputs().to_vec(), g.outputs().to_vec(), nodes)?;
    assert_eq!(plan(&g)?.digest(), plan(&reordered)?.digest());
    let changed = ModelIrGraph::new_validated("graph:different", g.version(), g.generation(),
        g.inputs().to_vec(), g.outputs().to_vec(), g.nodes().to_vec())?;
    assert_ne!(plan(&g)?.digest(), plan(&changed)?.digest());
    Ok(())
}

#[test]
fn convolution_residual_pooling_pipeline_matches_existing_kernels_bit_for_bit() -> Test {
    let g = ModelIrGraph::new_validated("graph:vision", ModelIrVersion::V1, GEN,
        vec![port("x", &[1, 1, 4, 4])?, port("w", &[1, 1, 1, 1])?],
        vec![port("y", &[1, 1, 2, 2])?], vec![
            node("a", OpCode::Conv2d, &["x", "w"], "conv", AttributeMap::new())?,
            node("b", OpCode::Relu, &["conv"], "relu", AttributeMap::new())?,
            node("c", OpCode::Add, &["conv", "relu"], "residual", AttributeMap::new())?,
            node("d", OpCode::MaxPool2d, &["residual"], "y", attrs(&[
                ("kernel_size", AttrValue::IntList(vec![2, 2])), ("strides", AttrValue::IntList(vec![2, 2]))]))?,
        ])?;
    parity(&g, &[("x", tensor(&[1, 1, 4, 4], &[-8., -7., -6., -5., -4., -3., -2., -1., 0., 1., 2., 3., 4., 5., 6., 7.])?),
        ("w", tensor(&[1, 1, 1, 1], &[2.])?)])
}

#[test]
fn every_f32_operator_family_matches_backend_work_and_payload_bits() -> Test {
    let cases = vec![
        (OpCode::Add, vec![vec![2, 2], vec![2, 2]], vec![2, 2], AttributeMap::new()),
        (OpCode::Sub, vec![vec![2, 2], vec![2, 2]], vec![2, 2], AttributeMap::new()),
        (OpCode::Mul, vec![vec![2, 2], vec![2, 2]], vec![2, 2], AttributeMap::new()),
        (OpCode::Div, vec![vec![2, 2], vec![2, 2]], vec![2, 2], AttributeMap::new()),
        (OpCode::Relu, vec![vec![2, 2]], vec![2, 2], AttributeMap::new()),
        (OpCode::Sigmoid, vec![vec![2, 2]], vec![2, 2], AttributeMap::new()),
        (OpCode::Gelu, vec![vec![2, 2]], vec![2, 2], AttributeMap::new()),
        (OpCode::Silu, vec![vec![2, 2]], vec![2, 2], AttributeMap::new()),
        (OpCode::Tanh, vec![vec![2, 2]], vec![2, 2], AttributeMap::new()),
        (OpCode::Softmax, vec![vec![2, 2]], vec![2, 2], AttributeMap::new()),
        (OpCode::MatMul, vec![vec![2, 2], vec![2, 2]], vec![2, 2], AttributeMap::new()),
        (OpCode::Reshape, vec![vec![2, 2]], vec![4], attrs(&[("shape", AttrValue::IntList(vec![4]))])),
        (OpCode::Transpose, vec![vec![2, 2]], vec![2, 2], AttributeMap::new()),
        (OpCode::Squeeze, vec![vec![1, 4, 1]], vec![4], AttributeMap::new()),
        (OpCode::Unsqueeze, vec![vec![4]], vec![1, 4], attrs(&[("axes", AttrValue::IntList(vec![0]))])),
        (OpCode::Concat, vec![vec![2], vec![2]], vec![4], attrs(&[("axis", AttrValue::Int(0))])),
        (OpCode::Slice, vec![vec![4]], vec![2], attrs(&[("starts", AttrValue::IntList(vec![1])), ("ends", AttrValue::IntList(vec![3]))])),
        (OpCode::LayerNorm, vec![vec![2, 2]], vec![2, 2], AttributeMap::new()),
        (OpCode::RMSNorm, vec![vec![2, 2]], vec![2, 2], AttributeMap::new()),
    ];
    for (op, shapes, out, attributes) in cases {
        let ports = shapes.iter().enumerate().map(|(i, s)| port(&format!("x{i}"), s)).collect::<Test<Vec<_>>>()?;
        let names: Vec<_> = ports.iter().map(|p| p.name()).collect();
        let n = node("op", op, &names, "y", attributes)?;
        let inputs = shapes.iter().enumerate().map(|(i, s)| {
            let count: usize = s.iter().product();
            let values: Vec<_> = (0..count).map(|v| v as f32 * 0.3 - 0.45).collect();
            Ok((format!("x{i}"), tensor(s, &values)?))
        }).collect::<Test<Vec<_>>>()?;
        let g = ModelIrGraph::new_validated("graph:operator-parity", ModelIrVersion::V1, GEN,
            ports, vec![port("y", &out)?], vec![n])?;
        parity(&g, &inputs)?;
    }
    Ok(())
}

#[test]
fn integer_embedding_transfer_and_zero_width_validation_match_backend() -> Test {
    for width in [0, 2] {
        let indices = TensorPort::new("ids", DType::I64, Shape::new([3])?, GEN)?;
        let g = ModelIrGraph::new_validated("graph:embedding", ModelIrVersion::V1, GEN,
            vec![indices, port("table", &[3, width])?], vec![port("y", &[3, width])?],
            vec![node("lookup", OpCode::Embedding, &["ids", "table"], "y", AttributeMap::new())?])?;
        let values: Vec<_> = (0..3 * width).map(|n| n as f32 - 1.).collect();
        let inputs = [("ids", Tensor::from_values(Shape::new([3])?, &[2_i64, 0, 2], GEN)?),
            ("table", tensor(&[3, width], &values)?)];
        let p = plan(&g)?; assert_eq!(p.minimum_requirements().scratch_bytes, 0);
        parity(&g, &inputs)?;
    }
    Ok(())
}

#[test]
fn duplicate_declared_outputs_are_refused_by_the_original_ir_contract() -> Test {
    let original = chain(3)?;
    let mut outputs = original.outputs().to_vec(); outputs.extend(original.outputs().iter().cloned());
    let g = ModelIrGraph::new(original.id(), original.version(), GEN,
        original.inputs().to_vec(), outputs, original.nodes().to_vec())?;
    assert!(matches!(CompiledScalarPlan::compile(&g, MemoryPlanLimits::default(), &ScalarExecCx::new()),
        Err(PlannedExecError::Planning(fss_model_ir::MemoryPlanError::Ir(
            fss_model_ir::ModelIrError::DuplicateTensorOutput { .. })))));
    Ok(())
}

#[test]
fn reshape_work_can_be_zero_without_bypassing_payload_admission() -> Test {
    let g = ModelIrGraph::new_validated("graph:zero-work", ModelIrVersion::V1, GEN,
        vec![port("x", &[2, 2])?], vec![port("y", &[4])?],
        vec![node("reshape", OpCode::Reshape, &["x"], "y", attrs(&[("shape", AttrValue::IntList(vec![4]))]))?])?;
    let p = plan(&g)?; let input = [("x", tensor(&[2, 2], &[1., -0., 3., 4.])?)];
    assert_eq!(p.minimum_requirements().macs, 0);
    assert!(matches!(p.run(&input, PeakExecBudget::new(0, 0, 0), &ScalarExecCx::new()),
        Err(PlannedExecError::BudgetExceeded { .. })));
    p.run(&input, exact(&p), &ScalarExecCx::new())?;
    parity(&g, &input)
}

#[test]
fn unused_integer_input_is_not_hidden_by_node_partitioning() -> Test {
    let g = ModelIrGraph::new_validated("graph:unused-integer", ModelIrVersion::V1, GEN,
        vec![port("x", &[4])?, TensorPort::new("ids", DType::I64, Shape::new([1])?, GEN)?],
        vec![port("y", &[4])?], vec![node("relu", OpCode::Relu, &["x"], "y", AttributeMap::new())?])?;
    assert!(matches!(CompiledScalarPlan::compile(&g, MemoryPlanLimits::default(), &ScalarExecCx::new()),
        Err(PlannedExecError::Execution(ExecError::UnsupportedDType { .. }))));
    Ok(())
}

#[test]
fn generated_branched_graphs_reproduce_full_execution_after_retirement() -> Test {
    let mut seed = 0x1357_2468_9876_u64;
    for case in 0..512 {
        let mut names = vec!["x".to_owned()]; let mut nodes = Vec::new();
        for i in 0..12 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let a = (seed >> 32) as usize % names.len();
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let b = (seed >> 32) as usize % names.len();
            let output = format!("v{i:02}");
            let op = if i % 3 == 0 { OpCode::Sub } else { OpCode::Add };
            nodes.push(node(&format!("n{i:02}"), op, &[&names[a], &names[b]], &output, AttributeMap::new())?);
            names.push(output);
        }
        let retained = (seed as usize % 11) + 1;
        let g = ModelIrGraph::new_validated(format!("graph:generated:{case}"), ModelIrVersion::V1, GEN,
            vec![port("x", &[4])?], vec![port(&names[12], &[4])?, port(&names[retained], &[4])?], nodes)?;
        parity(&g, &[("x", tensor(&[4], &[-1.5, -0., 0.25, 2.])?)])?;
    }
    Ok(())
}
