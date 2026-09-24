#![forbid(unsafe_code)]
//! Numerical and admission regressions for layout operators in the existing scalar executor.

use fss_core::Generation;
use fss_model_ir::{
    AttrValue, AttributeMap, GraphNode, ModelIrGraph, ModelIrVersion, OpCode, TensorPort,
};
use fss_reference::{ExecBudget, ExecError, ExecOutcome, ScalarExecCx, ScalarExecutor};
use fss_tensor::{DType, Shape, Tensor};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const GEN: Generation = Generation(3);

fn attrs(entries: &[(&str, AttrValue)]) -> AttributeMap {
    entries
        .iter()
        .map(|(name, value)| ((*name).to_owned(), value.clone()))
        .collect()
}
fn port(name: &str, dims: &[usize]) -> TestResult<TensorPort> {
    Ok(TensorPort::new(name, DType::F32, Shape::new(dims)?, GEN)?)
}
fn graph(
    op: OpCode,
    shapes: &[&[usize]],
    output: &[usize],
    attributes: AttributeMap,
) -> TestResult<ModelIrGraph> {
    let inputs: Vec<_> = shapes
        .iter()
        .enumerate()
        .map(|(i, dims)| port(&format!("x{i}"), dims))
        .collect::<TestResult<_>>()?;
    let names = inputs.iter().map(|p| p.name().to_owned()).collect();
    Ok(ModelIrGraph::new_validated(
        "graph:layout",
        ModelIrVersion::V1,
        GEN,
        inputs,
        vec![port("y", output)?],
        vec![GraphNode::new(
            "node:layout",
            op,
            "layout under frozen IR semantics",
            names,
            vec!["y".to_owned()],
            attributes,
        )?],
    )?)
}
fn run(
    op: OpCode,
    shapes: &[&[usize]],
    values: &[&[f32]],
    output: &[usize],
    attributes: AttributeMap,
    budget: ExecBudget,
) -> TestResult<ExecOutcome> {
    assert_eq!(shapes.len(), values.len());
    let graph = graph(op, shapes, output, attributes)?;
    let inputs = shapes
        .iter()
        .zip(values)
        .enumerate()
        .map(|(i, (shape, values))| {
            Ok((
                format!("x{i}"),
                Tensor::from_values(Shape::new(*shape)?, values, GEN)?,
            ))
        })
        .collect::<TestResult<Vec<_>>>()?;
    Ok(ScalarExecutor::run(
        &graph,
        &inputs,
        budget,
        &ScalarExecCx::new(),
    )?)
}
fn result(outcome: &ExecOutcome) -> TestResult<Vec<f32>> {
    Ok(outcome
        .get_output("y")
        .ok_or_else(|| std::io::Error::other("missing output"))?
        .to_vec::<f32>()?)
}
fn generous() -> ExecBudget {
    ExecBudget::new(1_000_000, 1_000_000)
}

#[test]
fn transpose_default_reverses_axes_not_linear_storage() -> TestResult {
    let outcome = run(
        OpCode::Transpose,
        &[&[2, 3]],
        &[&[0., 1., 2., 3., 4., 5.]],
        &[3, 2],
        AttributeMap::new(),
        generous(),
    )?;
    assert_eq!(result(&outcome)?, vec![0., 3., 1., 4., 2., 5.]);
    assert_eq!(outcome.executed_macs(), 18);
    assert_eq!(outcome.allocated_bytes(), 48);
    Ok(())
}

#[test]
fn all_rank_three_permutations_match_independent_forward_scatter() -> TestResult {
    let dimensions = [2, 3, 4];
    let input: Vec<f32> = (0..24).map(|i| i as f32 - 7.0).collect();
    for permutation in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let output_dims: Vec<usize> = permutation.iter().map(|&p| dimensions[p]).collect();
        let mut expected = vec![0.0; 24];
        // Independent direction: scatter each source element to its permuted destination.
        for (index, &value) in input.iter().enumerate() {
            let coordinates = [index / 12, (index / 4) % 3, index % 4];
            let mut target = 0;
            for (axis, &source_axis) in permutation.iter().enumerate() {
                target = target * output_dims[axis] + coordinates[source_axis];
            }
            expected[target] = value;
        }
        let outcome = run(
            OpCode::Transpose,
            &[&dimensions],
            &[&input],
            &output_dims,
            attrs(&[(
                "permutation",
                AttrValue::IntList(permutation.iter().map(|&p| p as i64).collect()),
            )]),
            generous(),
        )?;
        assert_eq!(result(&outcome)?, expected, "permutation {permutation:?}");
    }
    Ok(())
}

#[test]
fn scalar_transpose_preserves_negative_zero() -> TestResult {
    let outcome = run(
        OpCode::Transpose,
        &[&[]],
        &[&[-0.0]],
        &[],
        AttributeMap::new(),
        generous(),
    )?;
    assert_eq!(result(&outcome)?[0].to_bits(), (-0.0_f32).to_bits());
    Ok(())
}

#[test]
fn squeeze_and_unsqueeze_preserve_value_bits() -> TestResult {
    let input = [
        1.0,
        -0.0,
        f32::from_bits(0x7fc1_2345),
        f32::INFINITY,
        -2.5,
        7.0,
    ];
    let squeezed = run(
        OpCode::Squeeze,
        &[&[1, 2, 1, 3]],
        &[&input],
        &[2, 3],
        AttributeMap::new(),
        generous(),
    )?;
    let values = result(&squeezed)?;
    let expanded = run(
        OpCode::Unsqueeze,
        &[&[2, 3]],
        &[&values],
        &[1, 2, 1, 3],
        attrs(&[("axes", AttrValue::IntList(vec![2, 0]))]),
        generous(),
    )?;
    let bits = |values: &[f32]| values.iter().map(|v| v.to_bits()).collect::<Vec<_>>();
    assert_eq!(bits(&result(&expanded)?), bits(&input));
    Ok(())
}

#[test]
fn explicit_empty_squeeze_axes_preserve_ones() -> TestResult {
    let outcome = run(
        OpCode::Squeeze,
        &[&[1, 2, 1]],
        &[&[4., 5.]],
        &[1, 2, 1],
        attrs(&[("axes", AttrValue::IntList(vec![]))]),
        generous(),
    )?;
    assert_eq!(result(&outcome)?, vec![4., 5.]);
    Ok(())
}

#[test]
fn concat_inner_axis_interleaves_blocks_and_resolves_negative_axis() -> TestResult {
    for axis in [1, -1] {
        let outcome = run(
            OpCode::Concat,
            &[&[2, 2], &[2, 1]],
            &[&[1., 2., 3., 4.], &[5., 6.]],
            &[2, 3],
            attrs(&[("axis", AttrValue::Int(axis))]),
            generous(),
        )?;
        assert_eq!(result(&outcome)?, vec![1., 2., 5., 3., 4., 6.]);
    }
    Ok(())
}

#[test]
fn concat_repeated_input_is_not_deduplicated() -> TestResult {
    let graph = ModelIrGraph::new_validated(
        "graph:duplicate-input",
        ModelIrVersion::V1,
        GEN,
        vec![port("x", &[2, 1])?],
        vec![port("y", &[2, 2])?],
        vec![GraphNode::new(
            "node:concat",
            OpCode::Concat,
            "repeat columns",
            vec!["x".to_owned(), "x".to_owned()],
            vec!["y".to_owned()],
            attrs(&[("axis", AttrValue::Int(1))]),
        )?],
    )?;
    let tensor = Tensor::from_values(Shape::new([2, 1])?, &[1.0_f32, 2.0], GEN)?;
    let outcome = ScalarExecutor::run(&graph, &[("x", tensor)], generous(), &ScalarExecCx::new())?;
    assert_eq!(result(&outcome)?, vec![1., 1., 2., 2.]);
    Ok(())
}

#[test]
fn concat_default_axis_and_empty_inputs_follow_declared_order() -> TestResult {
    let a = run(
        OpCode::Concat,
        &[&[1, 2], &[2, 2]],
        &[&[1., 2.], &[3., 4., 5., 6.]],
        &[3, 2],
        AttributeMap::new(),
        generous(),
    )?;
    assert_eq!(result(&a)?, vec![1., 2., 3., 4., 5., 6.]);
    let b = run(
        OpCode::Concat,
        &[&[2, 0], &[2, 1]],
        &[&[], &[7., 8.]],
        &[2, 1],
        attrs(&[("axis", AttrValue::Int(1))]),
        generous(),
    )?;
    assert_eq!(result(&b)?, vec![7., 8.]);
    Ok(())
}

#[test]
fn slice_multiple_axes_with_strides_matches_hand_computed_values() -> TestResult {
    let input: Vec<f32> = (0..15).map(|v| v as f32).collect();
    let outcome = run(
        OpCode::Slice,
        &[&[3, 5]],
        &[&input],
        &[2, 2],
        attrs(&[
            ("starts", AttrValue::IntList(vec![1, 1])),
            ("ends", AttrValue::IntList(vec![5, 3])),
            ("axes", AttrValue::IntList(vec![1, 0])),
            ("steps", AttrValue::IntList(vec![2, 1])),
        ]),
        generous(),
    )?;
    assert_eq!(result(&outcome)?, vec![6., 8., 11., 13.]);
    Ok(())
}

#[test]
fn slice_defaults_and_huge_singleton_step_do_not_overflow() -> TestResult {
    let input: Vec<f32> = (0..8).map(|v| v as f32).collect();
    let a = run(
        OpCode::Slice,
        &[&[2, 4]],
        &[&input],
        &[1, 4],
        attrs(&[
            ("starts", AttrValue::IntList(vec![1])),
            ("ends", AttrValue::IntList(vec![2])),
        ]),
        generous(),
    )?;
    assert_eq!(result(&a)?, vec![4., 5., 6., 7.]);
    let b = run(
        OpCode::Slice,
        &[&[2, 4]],
        &[&input],
        &[1, 4],
        attrs(&[
            ("starts", AttrValue::IntList(vec![0])),
            ("ends", AttrValue::IntList(vec![2])),
            ("steps", AttrValue::IntList(vec![i64::MAX])),
        ]),
        generous(),
    )?;
    assert_eq!(result(&b)?, vec![0., 1., 2., 3.]);
    Ok(())
}

#[test]
fn empty_layouts_do_not_attempt_to_gather_data() -> TestResult {
    let transpose = run(
        OpCode::Transpose,
        &[&[2, 0, 3]],
        &[&[]],
        &[3, 0, 2],
        AttributeMap::new(),
        ExecBudget::new(0, 0),
    )?;
    assert!(result(&transpose)?.is_empty());
    let slice = run(
        OpCode::Slice,
        &[&[2, 2]],
        &[&[1., 2., 3., 4.]],
        &[0, 2],
        attrs(&[
            ("starts", AttrValue::IntList(vec![2])),
            ("ends", AttrValue::IntList(vec![2])),
        ]),
        ExecBudget::new(0, 16),
    )?;
    assert!(result(&slice)?.is_empty());
    Ok(())
}

#[test]
fn malformed_layouts_remain_frozen_ir_errors() {
    for (op, attributes) in [
        (
            OpCode::Transpose,
            attrs(&[("permutation", AttrValue::IntList(vec![0, 0]))]),
        ),
        (
            OpCode::Transpose,
            attrs(&[("permutation", AttrValue::IntList(vec![0, 2]))]),
        ),
        (
            OpCode::Squeeze,
            attrs(&[("axes", AttrValue::IntList(vec![1]))]),
        ),
        (
            OpCode::Unsqueeze,
            attrs(&[("axes", AttrValue::IntList(vec![0, 0]))]),
        ),
        (OpCode::Concat, attrs(&[("axis", AttrValue::Int(-3))])),
        (
            OpCode::Slice,
            attrs(&[
                ("starts", AttrValue::IntList(vec![-1])),
                ("ends", AttrValue::IntList(vec![2])),
            ]),
        ),
        (
            OpCode::Slice,
            attrs(&[
                ("starts", AttrValue::IntList(vec![0])),
                ("ends", AttrValue::IntList(vec![2])),
                ("steps", AttrValue::IntList(vec![0])),
            ]),
        ),
        (
            OpCode::Slice,
            attrs(&[
                ("starts", AttrValue::IntList(vec![2])),
                ("ends", AttrValue::IntList(vec![1])),
            ]),
        ),
    ] {
        assert!(
            graph(op, &[&[2, 3]], &[2, 3], attributes).is_err(),
            "invalid {op:?} accepted"
        );
    }
}

#[test]
fn layout_work_and_allocation_budgets_are_checked_before_execution() -> TestResult {
    let graph = graph(OpCode::Transpose, &[&[2, 3]], &[3, 2], AttributeMap::new())?;
    let inputs = [(
        "x0",
        Tensor::from_values(Shape::new([2, 3])?, &[1.0_f32; 6], GEN)?,
    )];
    for budget in [ExecBudget::new(17, 48), ExecBudget::new(18, 47)] {
        assert!(matches!(
            ScalarExecutor::run(&graph, &inputs, budget, &ScalarExecCx::new()),
            Err(ExecError::BudgetExceeded {
                macs: 18,
                bytes: 48,
                ..
            })
        ));
    }
    let outcome = ScalarExecutor::run(
        &graph,
        &inputs,
        ExecBudget::new(18, 48),
        &ScalarExecCx::new(),
    )?;
    assert_eq!(result(&outcome)?, vec![1.0; 6]);
    Ok(())
}

#[test]
fn cancelled_layout_request_returns_no_output_and_drains() -> TestResult {
    let graph = graph(OpCode::Transpose, &[&[2, 3]], &[3, 2], AttributeMap::new())?;
    let inputs = [(
        "x0",
        Tensor::from_values(Shape::new([2, 3])?, &[1.0_f32; 6], GEN)?,
    )];
    let cx = ScalarExecCx::new();
    cx.request_cancellation();
    assert!(matches!(
        ScalarExecutor::run(&graph, &inputs, generous(), &cx),
        Err(ExecError::CancellationRequested { .. })
    ));
    assert!(cx.is_drain_completed());
    Ok(())
}

#[test]
fn layout_admission_does_not_relax_dtype_or_generation() -> TestResult {
    let graph = graph(OpCode::Transpose, &[&[2, 3]], &[3, 2], AttributeMap::new())?;
    let wrong_generation = [(
        "x0",
        Tensor::from_values(Shape::new([2, 3])?, &[1.0_f32; 6], Generation(4))?,
    )];
    assert!(matches!(
        ScalarExecutor::run(&graph, &wrong_generation, generous(), &ScalarExecCx::new()),
        Err(ExecError::GenerationMismatch { .. })
    ));
    let wrong_dtype = [(
        "x0",
        Tensor::from_values(Shape::new([2, 3])?, &[1_i32; 6], GEN)?,
    )];
    assert!(matches!(
        ScalarExecutor::run(&graph, &wrong_dtype, generous(), &ScalarExecCx::new()),
        Err(ExecError::UnsupportedDType { .. })
    ));
    Ok(())
}

#[test]
fn five_layout_operators_compose_with_existing_matmul() -> TestResult {
    let node = |id: &str, op, inputs: &[&str], output: &str, attributes| {
        GraphNode::new(
            id,
            op,
            id,
            inputs.iter().map(|v| (*v).to_owned()).collect(),
            vec![output.to_owned()],
            attributes,
        )
    };
    let graph = ModelIrGraph::new_validated(
        "graph:layout-pipeline",
        ModelIrVersion::V1,
        GEN,
        vec![port("image", &[2, 3])?, port("weights", &[2, 1])?],
        vec![port("y", &[4, 1])?],
        vec![
            node("t", OpCode::Transpose, &["image"], "t", AttributeMap::new())?,
            node(
                "s",
                OpCode::Slice,
                &["t"],
                "s",
                attrs(&[
                    ("starts", AttrValue::IntList(vec![1])),
                    ("ends", AttrValue::IntList(vec![3])),
                ]),
            )?,
            node("c", OpCode::Concat, &["s", "s"], "c", AttributeMap::new())?,
            node(
                "u",
                OpCode::Unsqueeze,
                &["c"],
                "u",
                attrs(&[("axes", AttrValue::IntList(vec![0]))]),
            )?,
            node("q", OpCode::Squeeze, &["u"], "q", AttributeMap::new())?,
            node(
                "m",
                OpCode::MatMul,
                &["q", "weights"],
                "y",
                AttributeMap::new(),
            )?,
        ],
    )?;
    let inputs = [
        (
            "image",
            Tensor::from_values(Shape::new([2, 3])?, &[0.0_f32, 1., 2., 3., 4., 5.], GEN)?,
        ),
        (
            "weights",
            Tensor::from_values(Shape::new([2, 1])?, &[2.0_f32, -1.], GEN)?,
        ),
    ];
    let first = ScalarExecutor::run(&graph, &inputs, generous(), &ScalarExecCx::new())?;
    let second = ScalarExecutor::run(&graph, &inputs, generous(), &ScalarExecCx::new())?;
    assert_eq!(result(&first)?, vec![-2., -1., -2., -1.]);
    assert_eq!(result(&first)?, result(&second)?);
    assert_eq!(first.nodes_executed(), 6);
    Ok(())
}
