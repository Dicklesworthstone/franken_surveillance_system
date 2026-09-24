#![forbid(unsafe_code)]
//! Frozen-IR normalization through the public executor, not a separate test kernel.

use fss_core::Generation;
use fss_model_ir::{
    AttrValue, AttributeMap, GraphNode, ModelIrGraph, ModelIrVersion, OpCode, TensorPort,
};
use fss_reference::{ExecBudget, ExecError, ExecOutcome, ScalarExecCx, ScalarExecutor};
use fss_tensor::{DType, Shape, Tensor};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const GEN: Generation = Generation(7);

/// Affine parameter dimensions, scale, and optional bias.
type Affine<'a> = (&'a [usize], &'a [f32], Option<&'a [f32]>);

fn run(
    op: OpCode,
    dims: &[usize],
    data: &[f32],
    affine: Option<Affine<'_>>,
    attrs: AttributeMap,
    budget: ExecBudget,
    cx: &ScalarExecCx,
) -> Result<ExecOutcome, ExecError> {
    let shape = Shape::new(dims.to_vec())?;
    let mut ports = vec![TensorPort::new("x", DType::F32, shape.clone(), GEN)?];
    let mut inputs = vec![(
        "x".to_owned(),
        Tensor::from_values(shape.clone(), data, GEN)?,
    )];
    let mut names = vec!["x".to_owned()];
    if let Some((dims, weight, bias)) = affine {
        let shape = Shape::new(dims.to_vec())?;
        ports.push(TensorPort::new("weight", DType::F32, shape.clone(), GEN)?);
        inputs.push((
            "weight".to_owned(),
            Tensor::from_values(shape.clone(), weight, GEN)?,
        ));
        names.push("weight".to_owned());
        if let Some(bias) = bias {
            ports.push(TensorPort::new("bias", DType::F32, shape.clone(), GEN)?);
            inputs.push(("bias".to_owned(), Tensor::from_values(shape, bias, GEN)?));
            names.push("bias".to_owned());
        }
    }
    let node = GraphNode::new(
        "norm",
        op,
        "normalization contract",
        names,
        vec!["out".into()],
        attrs,
    )?;
    let graph = ModelIrGraph::new_validated(
        "normalization",
        ModelIrVersion::V1,
        GEN,
        ports,
        vec![TensorPort::new("out", DType::F32, shape, GEN)?],
        vec![node],
    )?;
    ScalarExecutor::run(&graph, &inputs, budget, cx)
}

fn values(result: &ExecOutcome) -> Result<Vec<f32>, Box<dyn std::error::Error>> {
    Ok(result
        .get_output("out")
        .ok_or("missing output")?
        .to_vec::<f32>()?)
}
fn close(actual: &[f32], expected: &[f64]) {
    assert_eq!(actual.len(), expected.len());
    for (&a, &e) in actual.iter().zip(expected) {
        assert!(
            (f64::from(a) - e).abs() <= 2e-6 * e.abs().max(1.0),
            "{a} != {e}"
        );
    }
}
fn epsilon(e: f64) -> AttributeMap {
    AttributeMap::from([("epsilon".into(), AttrValue::Float(e))])
}

#[test]
fn layer_norm_uses_population_variance_and_independent_rows() -> TestResult {
    let r = run(
        OpCode::LayerNorm,
        &[2, 4],
        &[1., 2., 3., 4., 11., 12., 13., 14.],
        None,
        AttributeMap::new(),
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;
    let s = (1.25_f64 + 1e-5).sqrt();
    close(
        &values(&r)?,
        &[
            -1.5 / s,
            -0.5 / s,
            0.5 / s,
            1.5 / s,
            -1.5 / s,
            -0.5 / s,
            0.5 / s,
            1.5 / s,
        ],
    );
    assert_eq!(r.get_output("out").ok_or("output")?.generation(), GEN);
    Ok(())
}

#[test]
fn rms_norm_does_not_subtract_mean_and_places_epsilon_inside_root() -> TestResult {
    let r = run(
        OpCode::RMSNorm,
        &[2, 2],
        &[3., 4., 6., 8.],
        None,
        epsilon(0.5),
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;
    close(
        &values(&r)?,
        &[
            3. / 13_f64.sqrt(),
            4. / 13_f64.sqrt(),
            6. / 50.5_f64.sqrt(),
            8. / 50.5_f64.sqrt(),
        ],
    );
    Ok(())
}

#[test]
fn affine_parameters_and_inferred_multiaxis_shape_are_per_element() -> TestResult {
    let r = run(
        OpCode::LayerNorm,
        &[2, 2, 2],
        &[1., 2., 3., 4., 5., 6., 7., 8.],
        Some((&[2, 2], &[1., 2., 3., 4.], Some(&[1., -1., 2., -2.]))),
        epsilon(0.75),
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;
    let s = 2_f64.sqrt();
    let row = [-1.5 / s + 1., -1. / s - 1., 1.5 / s + 2., 6. / s - 2.];
    close(&values(&r)?, &[row, row].concat());
    Ok(())
}

#[test]
fn explicit_shape_forms_agree_and_override_last_axis_default() -> TestResult {
    let data = [1., 2., 3., 4.];
    let mut outputs = Vec::new();
    for shape in [
        AttrValue::IntList(vec![2, 2]),
        AttrValue::Shape(Shape::new(vec![2, 2])?),
    ] {
        let attrs = AttributeMap::from([("normalized_shape".into(), shape)]);
        outputs.push(values(&run(
            OpCode::LayerNorm,
            &[1, 2, 2],
            &data,
            None,
            attrs,
            ExecBudget::unlimited(),
            &ScalarExecCx::new(),
        )?)?);
    }
    assert_eq!(outputs[0], outputs[1]);
    let default = values(&run(
        OpCode::LayerNorm,
        &[1, 2, 2],
        &data,
        None,
        AttributeMap::new(),
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?)?;
    assert_ne!(outputs[0], default);
    Ok(())
}

#[test]
fn no_affine_and_weight_only_paths_preserve_the_ir_contract() -> TestResult {
    let attrs = AttributeMap::from([("elementwise_affine".into(), AttrValue::Bool(false))]);
    let plain = run(
        OpCode::LayerNorm,
        &[2],
        &[1., 3.],
        None,
        attrs,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;
    let weighted = run(
        OpCode::RMSNorm,
        &[2],
        &[1., 3.],
        Some((&[2], &[2., -2.], None)),
        epsilon(1.),
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;
    close(
        &values(&plain)?,
        &[-1. / 1.00001_f64.sqrt(), 1. / 1.00001_f64.sqrt()],
    );
    close(
        &values(&weighted)?,
        &[2. / 6_f64.sqrt(), -6. / 6_f64.sqrt()],
    );
    Ok(())
}

#[test]
fn constant_and_singleton_rows_have_defined_zero_variance() -> TestResult {
    for dims in [&[2, 3][..], &[6, 1][..]] {
        let r = run(
            OpCode::LayerNorm,
            dims,
            &[4.; 6],
            None,
            AttributeMap::new(),
            ExecBudget::unlimited(),
            &ScalarExecCx::new(),
        )?;
        assert_eq!(values(&r)?, vec![0.; 6]);
    }
    Ok(())
}

#[test]
fn wide_statistics_handle_extreme_finite_values_without_false_overflow() -> TestResult {
    let r = run(
        OpCode::LayerNorm,
        &[2],
        &[f32::MAX, -f32::MAX],
        None,
        epsilon(1e-300),
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;
    close(&values(&r)?, &[1., -1.]);
    let r = run(
        OpCode::RMSNorm,
        &[2],
        &[f32::MAX, f32::MAX],
        None,
        epsilon(1e-300),
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;
    close(&values(&r)?, &[1., 1.]);
    Ok(())
}

#[test]
fn epsilon_is_not_narrowed_to_f32_or_silently_defaulted() -> TestResult {
    for e in [f64::from_bits(1), 1e-300, f64::MAX] {
        let r = run(
            OpCode::LayerNorm,
            &[2],
            &[0., 0.],
            None,
            epsilon(e),
            ExecBudget::unlimited(),
            &ScalarExecCx::new(),
        )?;
        assert_eq!(values(&r)?, vec![0., 0.]);
    }
    let tiny = f32::from_bits(1);
    let r = run(
        OpCode::LayerNorm,
        &[2],
        &[tiny, -tiny],
        None,
        epsilon(1e-300),
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;
    close(&values(&r)?, &[1., -1.]);
    Ok(())
}

#[test]
fn nonfinite_rows_propagate_canonical_nan_without_poisoning_other_rows() -> TestResult {
    for op in [OpCode::LayerNorm, OpCode::RMSNorm] {
        for bad in [
            f32::INFINITY,
            f32::NEG_INFINITY,
            f32::from_bits(0xffc0_0123),
        ] {
            let r = run(
                op,
                &[2, 2],
                &[bad, 1., 1., 2.],
                None,
                AttributeMap::new(),
                ExecBudget::unlimited(),
                &ScalarExecCx::new(),
            )?;
            let v = values(&r)?;
            assert_eq!(v[0].to_bits(), 0x7fc0_0000);
            assert_eq!(v[1].to_bits(), 0x7fc0_0000);
            assert!(v[2].is_finite() && v[3].is_finite());
        }
    }
    Ok(())
}

#[test]
fn invalid_epsilon_shapes_and_affine_flags_are_rejected_before_execution() {
    for e in [0., -1., f64::NAN, f64::INFINITY] {
        assert!(matches!(
            run(
                OpCode::LayerNorm,
                &[2],
                &[1., 2.],
                None,
                epsilon(e),
                ExecBudget::unlimited(),
                &ScalarExecCx::new()
            ),
            Err(ExecError::Ir(_))
        ));
    }
    for normalized in [vec![], vec![3], vec![1, 2]] {
        let attrs =
            AttributeMap::from([("normalized_shape".into(), AttrValue::IntList(normalized))]);
        assert!(
            run(
                OpCode::RMSNorm,
                &[2],
                &[1., 2.],
                None,
                attrs,
                ExecBudget::unlimited(),
                &ScalarExecCx::new()
            )
            .is_err()
        );
    }
    for flag in ["elementwise_affine", "scale", "bias"] {
        let attrs = AttributeMap::from([(flag.into(), AttrValue::Bool(false))]);
        assert!(
            run(
                OpCode::LayerNorm,
                &[2],
                &[1., 2.],
                Some((&[2], &[1., 1.], Some(&[0., 0.]))),
                attrs,
                ExecBudget::unlimited(),
                &ScalarExecCx::new()
            )
            .is_err()
        );
    }
    assert!(
        run(
            OpCode::RMSNorm,
            &[],
            &[1.],
            None,
            AttributeMap::new(),
            ExecBudget::unlimited(),
            &ScalarExecCx::new()
        )
        .is_err()
    );
}

#[test]
fn empty_tensors_do_no_reduction_work_even_with_empty_normalized_axes() -> TestResult {
    for op in [OpCode::LayerNorm, OpCode::RMSNorm] {
        for dims in [&[0, 3][..], &[2, 0][..], &[0, 2, 3][..]] {
            let r = run(
                op,
                dims,
                &[],
                None,
                AttributeMap::new(),
                ExecBudget::new(0, 0),
                &ScalarExecCx::new(),
            )?;
            assert!(values(&r)?.is_empty());
            assert_eq!(r.executed_macs(), 0);
        }
    }
    Ok(())
}

#[test]
fn exact_work_and_tensor_byte_budgets_are_enforced() -> TestResult {
    let data = [1., 2., 3., 4., 5., 6., 7., 8.];
    for op in [OpCode::LayerNorm, OpCode::RMSNorm] {
        let r = run(
            op,
            &[2, 4],
            &data,
            None,
            AttributeMap::new(),
            ExecBudget::new(72, 64),
            &ScalarExecCx::new(),
        )?;
        assert_eq!(r.executed_macs(), 72);
        assert_eq!(r.allocated_bytes(), 64);
        for b in [ExecBudget::new(71, 64), ExecBudget::new(72, 63)] {
            assert!(matches!(
                run(
                    op,
                    &[2, 4],
                    &data,
                    None,
                    AttributeMap::new(),
                    b,
                    &ScalarExecCx::new()
                ),
                Err(ExecError::BudgetExceeded { .. })
            ));
        }
    }
    Ok(())
}

#[test]
fn cancelled_execution_returns_no_tensor_and_completes_drain() {
    let cx = ScalarExecCx::new();
    cx.request_cancellation();
    assert!(matches!(
        run(
            OpCode::LayerNorm,
            &[2],
            &[1., 2.],
            None,
            AttributeMap::new(),
            ExecBudget::unlimited(),
            &cx
        ),
        Err(ExecError::CancellationRequested { .. })
    ));
    assert!(cx.is_drain_completed());
}

#[test]
fn normalization_composes_with_matmul_and_reports_full_graph_cost() -> TestResult {
    let p =
        |name: &str, dims: Vec<usize>| TensorPort::new(name, DType::F32, Shape::new(dims)?, GEN);
    let graph = ModelIrGraph::new_validated(
        "normalized-block",
        ModelIrVersion::V1,
        GEN,
        vec![p("x", vec![2, 3])?, p("w", vec![3, 2])?],
        vec![p("out", vec![2, 2])?],
        vec![
            GraphNode::new(
                "a",
                OpCode::LayerNorm,
                "pre norm",
                vec!["x".into()],
                vec!["n".into()],
                AttributeMap::new(),
            )?,
            GraphNode::new(
                "b",
                OpCode::MatMul,
                "projection",
                vec!["n".into(), "w".into()],
                vec!["m".into()],
                AttributeMap::new(),
            )?,
            GraphNode::new(
                "c",
                OpCode::RMSNorm,
                "post norm",
                vec!["m".into()],
                vec!["out".into()],
                AttributeMap::new(),
            )?,
        ],
    )?;
    let inputs = [
        (
            "x",
            Tensor::from_values(Shape::new(vec![2, 3])?, &[1_f32, 2., 3., 3., 2., 1.], GEN)?,
        ),
        (
            "w",
            Tensor::from_values(Shape::new(vec![3, 2])?, &[1_f32, 0., 0., 1., 1., 1.], GEN)?,
        ),
    ];
    let r = ScalarExecutor::run(
        &graph,
        &inputs,
        ExecBudget::new(108, 104),
        &ScalarExecCx::new(),
    )?;
    assert_eq!(r.nodes_executed(), 3);
    assert_eq!(r.executed_macs(), 108);
    assert_eq!(r.allocated_bytes(), 104);
    let v = values(&r)?;
    close(&v, &[0., 1.414204134, 0., -1.414204134]);
    let repeated = ScalarExecutor::run(
        &graph,
        &inputs,
        ExecBudget::new(108, 104),
        &ScalarExecCx::new(),
    )?;
    assert_eq!(
        v.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
        values(&repeated)?
            .iter()
            .map(|v| v.to_bits())
            .collect::<Vec<_>>()
    );
    Ok(())
}
