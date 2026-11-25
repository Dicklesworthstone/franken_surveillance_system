#![forbid(unsafe_code)]
//! Included-padding ceil windows through both production executors and artifact
//! replay, complementing the independent coordinate sweep in pooling_execution.

use super::*;

fn attrs(kernel: &[i64], strides: &[i64], pads: &[i64]) -> Vec<u8> {
    [
        ints_attr("kernel_shape", kernel),
        ints_attr("strides", strides),
        ints_attr("pads", pads),
        int_attr("ceil_mode", 1),
        int_attr("count_include_pad", 1),
    ]
    .concat()
}

fn source(opset: i64, input: &[usize], output: &[usize], attributes: &[u8]) -> Vec<u8> {
    let graph = [
        node("AveragePool", &["input"], &["output"], attributes),
        bytes(11, &info("input", input, 1)),
        bytes(12, &info("output", output, 1)),
    ]
    .concat();
    [
        integer(1, 8),
        bytes(8, &integer(2, opset)),
        bytes(7, &graph),
    ]
    .concat()
}

#[test]
fn included_padding_ceil_profiles_keep_partial_means_in_both_executors() -> Test {
    for opset in [13, 17, 18] {
        for (input, output, attributes, values, expected) in [
            (
                vec![1, 1, 2, 4],
                vec![1, 1, 1, 3],
                attrs(&[2, 2], &[2, 2], &[0, 1, 0, 0]),
                vec![1.; 8],
                // The left explicit pad counts; the right ceil-only pad does not.
                vec![0.5, 1., 1.],
            ),
            (
                vec![2, 2, 5],
                vec![2, 2, 3],
                attrs(&[3], &[2], &[1, 0]),
                (1..=20).map(|n| n as f32).collect::<Vec<_>>(),
                vec![
                    1.,
                    3.,
                    4.5,
                    13_f32 / 3.,
                    8.,
                    9.5,
                    23_f32 / 3.,
                    13.,
                    14.5,
                    11.,
                    18.,
                    19.5,
                ],
            ),
            (
                vec![1, 1, 4, 4],
                vec![1, 1, 2, 2],
                attrs(&[3, 3], &[2, 2], &[0; 4]),
                (1..=16).map(|n| n as f32).collect::<Vec<_>>(),
                vec![6., 7.5, 12., 13.5],
            ),
            (
                vec![1, 1, 1, 2],
                vec![1, 1, 1, 1],
                attrs(&[1, 3], &[1, i64::MAX], &[0; 4]),
                vec![1., 2.],
                vec![1.5],
            ),
        ] {
            let source = source(opset, &input, &output, &attributes);
            let imported = import(&source)?;
            assert_eq!(imported.graph().version(), fss_model_ir::ModelIrVersion::V1);
            let actual = roundtrip(&source, &[("input", data(&input, &values)?)])?;
            assert_eq!(bits(&actual["output"]), bits(&expected));
        }
    }
    Ok(())
}

#[test]
fn included_padding_ceil_context_and_dense_head_replay_exactly() -> Test {
    let source = model(
        &[
            node(
                "AveragePool",
                &["input"],
                &["pooled"],
                &attrs(&[2, 2], &[2, 2], &[0, 1, 0, 0]),
            ),
            node("GlobalAveragePool", &["pooled"], &["context"], &[]),
            node(
                "Flatten",
                &["context"],
                &["embedding"],
                &int_attr("axis", 1),
            ),
            node("MatMul", &["embedding", "head_weights"], &["head"], &[]),
            weight("head_weights", &[2, 3], &[1., 0.5, -1., -0.25, 2., 1.]),
            bytes(11, &info("input", &[1, 2, 2, 4], 1)),
            bytes(12, &info("pooled", &[1, 2, 1, 3], 1)),
            bytes(12, &info("context", &[1, 2, 1, 1], 1)),
            bytes(12, &info("head", &[1, 3], 1)),
        ]
        .concat(),
    );
    let input = data(
        &[1, 2, 2, 4],
        &[
            1., 2., 3., 4., 5., 6., 7., 8., -1., -2., -3., -4., -5., -6., -7., -8.,
        ],
    )?;
    let actual = roundtrip(&source, &[("input", input)])?;
    assert_eq!(
        bits(&actual["pooled"]),
        bits(&[1.5, 4.5, 6., -1.5, -4.5, -6.])
    );
    assert_eq!(bits(&actual["context"]), bits(&[4., -4.]));
    assert_eq!(bits(&actual["head"]), bits(&[5., -6., -8.]));
    Ok(())
}

#[test]
fn included_padding_ceil_preserves_execution_budgets_and_cancellation() -> Test {
    let source = source(
        13,
        &[1, 2, 4, 4],
        &[1, 2, 2, 2],
        &attrs(&[3, 3], &[2, 2], &[0; 4]),
    );
    let imported = import(&source)?;
    let divisors = imported
        .parameters()
        .get("onnx-node-0000-pool-divisors")
        .ok_or("missing ceil divisors")?;
    assert_eq!(divisors.shape().dims(), &[1, 1, 2, 2]);
    assert_eq!(divisors.to_vec::<f32>()?, [9., 6., 6., 4.]);
    let tensor = data(&[1, 2, 4, 4], &[1.; 32])?;
    let input = [("input", tensor.clone())];
    let constants = imported
        .parameters()
        .iter()
        .map(|(name, tensor)| Ok((name.clone(), tensor.to_vec::<f32>()?)))
        .collect::<Result<BTreeMap<_, _>, fss_tensor::TensorError>>()?;
    let prepared = optimized_executor::OptimizedGraph::prepare(
        imported.graph(),
        &constants,
        &ScalarExecCx::new(),
    )?;
    let mut bindings = imported.parameters().clone();
    bindings.insert("input".into(), tensor);
    let bindings = bindings.into_iter().collect::<Vec<_>>();
    let scalar = ScalarExecutor::run(
        imported.graph(),
        &bindings,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;
    for budget in [
        ExecBudget::new(scalar.executed_macs() - 1, usize::MAX),
        ExecBudget::new(u64::MAX, scalar.allocated_bytes() - 1),
    ] {
        assert!(matches!(
            ScalarExecutor::run(imported.graph(), &bindings, budget, &ScalarExecCx::new()),
            Err(ExecError::BudgetExceeded { .. })
        ));
        assert!(matches!(
            prepared.run(&input, budget, &ScalarExecCx::new()),
            Err(ExecError::BudgetExceeded { .. })
        ));
    }
    let cx = ScalarExecCx::new();
    cx.request_cancellation();
    assert!(matches!(
        ScalarExecutor::run(imported.graph(), &bindings, ExecBudget::unlimited(), &cx),
        Err(ExecError::CancellationRequested { .. })
    ));
    assert!(cx.is_drain_completed());
    let cx = ScalarExecCx::new();
    cx.request_cancellation();
    assert!(matches!(
        prepared.run(&input, ExecBudget::unlimited(), &cx),
        Err(ExecError::CancellationRequested { .. })
    ));
    assert!(cx.is_drain_completed());
    Ok(())
}
