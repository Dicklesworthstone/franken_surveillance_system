#![forbid(unsafe_code)]
//! Ceil-mode MaxPool through the actual importer, frozen graph format, weight
//! parser and both production executors. The oracle enumerates padded extents
//! and original input coordinates independently of native shape inference.

use super::*;
use fss_model_ir::{AttrValue, AttributeMap, ModelIrError, ModelIrVersion, OpCode, TensorPort};
use fss_tensor::DType;

fn text_attr(name: &str, value: &str) -> Vec<u8> {
    attribute(name, 3, &bytes(4, value.as_bytes()))
}

fn pool_source(input: [usize; 4], output: [usize; 4], attrs: &[u8]) -> Vec<u8> {
    model(
        &[
            node("MaxPool", &["input"], &["output"], attrs),
            bytes(11, &info("input", &input, 1)),
            bytes(12, &info("output", &output, 1)),
        ]
        .concat(),
    )
}

fn pool_attrs(kernel: [usize; 2], stride: [usize; 2], pads: [usize; 4]) -> Vec<u8> {
    [
        ints_attr("kernel_shape", &kernel.map(|n| n as i64)),
        ints_attr("strides", &stride.map(|n| n as i64)),
        ints_attr("pads", &pads.map(|n| n as i64)),
    ]
    .concat()
}

// Round the padded extent up by less than one stride, then enumerate complete
// windows. This also handles a kernel larger than the original padded input.
// Discard anchors at/beyond the real input's end before gathering any values.
fn starts(input: usize, kernel: usize, stride: usize, before: usize, after: usize) -> Vec<isize> {
    let padded = input + before + after;
    let Some(extent) = (padded..padded + stride)
        .find(|&extent| extent >= kernel && (extent - kernel).is_multiple_of(stride))
    else {
        return Vec::new();
    };
    (0..extent)
        .step_by(stride)
        .filter(|&start| start + kernel <= extent && start < input + before)
        .map(|start| start as isize - before as isize)
        .collect()
}

fn oracle(
    values: &[f32],
    input: [usize; 4],
    kernel: [usize; 2],
    stride: [usize; 2],
    pads: [usize; 4],
) -> Test<([usize; 4], Vec<f32>)> {
    let ys = starts(input[2], kernel[0], stride[0], pads[0], pads[2]);
    let xs = starts(input[3], kernel[1], stride[1], pads[1], pads[3]);
    let output = [input[0], input[1], ys.len(), xs.len()];
    let mut result = Vec::new();
    for plane in 0..input[0] * input[1] {
        for &y in &ys {
            for &x in &xs {
                let mut maximum = None;
                for row in 0..input[2] {
                    for col in 0..input[3] {
                        if (row as isize) < y
                            || (row as isize) >= y + kernel[0] as isize
                            || (col as isize) < x
                            || (col as isize) >= x + kernel[1] as isize
                        {
                            continue;
                        }
                        let value = values[(plane * input[2] + row) * input[3] + col];
                        maximum = Some(match maximum {
                            Some(previous) if previous >= value => previous,
                            _ => value,
                        });
                    }
                }
                result.push(maximum.ok_or("oracle window has no real input sample")?);
            }
        }
    }
    Ok((output, result))
}

#[test]
fn ceil_pooling_executes_partial_windows_and_negative_shape_numerators() -> Test {
    for (input, kernel, stride, pads, values, output, expected) in [
        (
            [1, 1, 4, 4],
            [3, 3],
            [2, 2],
            [0; 4],
            (1..=16).map(|n| n as f32).collect::<Vec<_>>(),
            [1, 1, 2, 2],
            vec![11., 12., 15., 16.],
        ),
        (
            [1, 1, 2, 2],
            [3, 3],
            [2, 2],
            [0; 4],
            vec![-4., -3., -2., -1.],
            [1, 1, 1, 1],
            vec![-1.],
        ),
        (
            [1, 1, 1, 1],
            [7, 7],
            [8, 8],
            [0; 4],
            vec![-0.0],
            [1, 1, 1, 1],
            vec![-0.0],
        ),
        (
            [1, 1, 2, 2],
            [1, 1],
            [2, 2],
            [0; 4],
            vec![-1., -2., -3., -4.],
            [1, 1, 1, 1],
            vec![-1.],
        ),
        (
            [1, 1, 2, 2],
            [2, 2],
            [2, 2],
            [0, 0, 1, 1],
            vec![-4., -3., -2., -1.],
            [1, 1, 1, 1],
            vec![-1.],
        ),
    ] {
        let attrs = [pool_attrs(kernel, stride, pads), int_attr("ceil_mode", 1)].concat();
        let source = pool_source(input, output, &attrs);
        let tensor = data(&input, &values)?;
        let actual = roundtrip(&source, &[("input", tensor)])?;
        assert_eq!(bits(&actual["output"]), bits(&expected));
    }
    Ok(())
}

#[test]
fn ceil_pooling_matches_coordinate_oracle_for_asymmetric_pads_and_wide_strides() -> Test {
    let mut executed = 0;
    let mut short_input_cases = 0;
    for input in [[1, 1, 1, 2], [2, 3, 3, 4], [1, 2, 5, 6]] {
        let values = (0..input.iter().product::<usize>())
            .map(|n| -((n % 29 + 1) as f32) * 0.25)
            .collect::<Vec<_>>();
        let tensor = data(&input, &values)?;
        for kernel in [[1, 1], [2, 3], [5, 7]] {
            for stride in [[1, 1], [2, 2], [7, 8]] {
                for pads in [
                    [0; 4],
                    [kernel[0] - 1, 0, 0, kernel[1] - 1],
                    [0, kernel[1] - 1, kernel[0] - 1, 0],
                    [kernel[0] - 1, kernel[1] - 1, kernel[0] - 1, kernel[1] - 1],
                ] {
                    let (output, expected) = oracle(&values, input, kernel, stride, pads)?;
                    if output[2] == 0 || output[3] == 0 {
                        continue;
                    }
                    let attrs =
                        [pool_attrs(kernel, stride, pads), int_attr("ceil_mode", 1)].concat();
                    let source = pool_source(input, output, &attrs);
                    let actual = roundtrip(&source, &[("input", tensor.clone())])?;
                    assert_eq!(
                        bits(&actual["output"]),
                        bits(&expected),
                        "input={input:?} kernel={kernel:?} stride={stride:?} pads={pads:?}",
                    );
                    executed += 1;
                    if input[2] + pads[0] + pads[2] < kernel[0]
                        || input[3] + pads[1] + pads[3] < kernel[1]
                    {
                        short_input_cases += 1;
                    }
                }
            }
        }
    }
    assert!(executed > 80);
    assert!(short_input_cases > 0);
    Ok(())
}

#[test]
fn ceil_import_preserves_frozen_v1_and_legacy_default_graph_bytes() -> Test {
    let attrs = pool_attrs([2, 2], [2, 2], [0; 4]);
    let absent = pool_source([1, 1, 3, 3], [1, 1, 1, 1], &attrs);
    let zero = pool_source(
        [1, 1, 3, 3],
        [1, 1, 1, 1],
        &[attrs.clone(), int_attr("ceil_mode", 0)].concat(),
    );
    let absent = import(&absent)?;
    let zero = import(&zero)?;
    assert_eq!(export(&absent)?.graph_bytes(), export(&zero)?.graph_bytes());

    let attrs = [attrs, int_attr("ceil_mode", 1)].concat();
    let source = pool_source([1, 1, 3, 3], [1, 1, 2, 2], &attrs);
    let notset = pool_source(
        [1, 1, 3, 3],
        [1, 1, 2, 2],
        &[attrs, text_attr("auto_pad", "NOTSET")].concat(),
    );
    let imported = import(&source)?;
    let notset = import(&notset)?;
    assert_eq!(imported.graph().version(), ModelIrVersion::V1);
    assert_eq!(imported.graph().nodes().len(), 1);
    assert_eq!(
        export(&imported)?.graph_bytes(),
        export(&notset)?.graph_bytes()
    );
    assert_ne!(
        export(&imported)?.graph_bytes(),
        export(&absent)?.graph_bytes()
    );
    Ok(())
}

#[test]
fn ceil_pooling_accounts_for_all_partial_windows_and_enforces_execution_budgets() -> Test {
    let source = pool_source(
        [1, 1, 4, 4],
        [1, 1, 2, 2],
        &[pool_attrs([3, 3], [2, 2], [0; 4]), int_attr("ceil_mode", 1)].concat(),
    );
    let imported = import(&source)?;
    let tensor = data(&[1, 1, 4, 4], &[-1.; 16])?;
    let input = [("input", tensor.clone())];
    let owned = [("input".to_owned(), tensor)];
    let prepared = optimized_executor::OptimizedGraph::prepare(
        imported.graph(),
        &BTreeMap::new(),
        &ScalarExecCx::new(),
    )?;
    let scalar = ScalarExecutor::run(
        imported.graph(),
        &owned,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;
    let fast = prepared.run(&input, ExecBudget::unlimited(), &ScalarExecCx::new())?;
    assert_eq!(scalar.executed_macs(), 36);
    assert_eq!(fast.executed_macs(), 36);
    assert_eq!(scalar.allocated_bytes(), fast.allocated_bytes());
    assert!(scalar.allocated_bytes() > 0);
    for budget in [
        ExecBudget::new(35, usize::MAX),
        ExecBudget::new(u64::MAX, scalar.allocated_bytes() - 1),
    ] {
        assert!(
            ScalarExecutor::run(imported.graph(), &owned, budget, &ScalarExecCx::new()).is_err()
        );
        assert!(prepared.run(&input, budget, &ScalarExecCx::new()).is_err());
    }
    let cx = ScalarExecCx::new();
    cx.request_cancellation();
    assert!(matches!(
        ScalarExecutor::run(imported.graph(), &owned, ExecBudget::unlimited(), &cx),
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

#[test]
fn ceil_pooling_refuses_malformed_flags_and_unrepresented_profiles() {
    for extra in [
        int_attr("ceil_mode", -1),
        int_attr("ceil_mode", 2),
        ints_attr("ceil_mode", &[1]),
        text_attr("ceil_mode", "1"),
        [int_attr("ceil_mode", 1), ints_attr("dilations", &[2, 1])].concat(),
        [int_attr("ceil_mode", 1), int_attr("storage_order", 1)].concat(),
    ] {
        let source = pool_source(
            [1, 1, 4, 4],
            [1, 1, 2, 2],
            &[pool_attrs([3, 3], [2, 2], [0; 4]), extra].concat(),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Unsupported));
    }
    for mode in ["VALID", "SAME_UPPER", "SAME_LOWER"] {
        let source = pool_source(
            [1, 1, 4, 4],
            [1, 1, 2, 2],
            &[
                ints_attr("kernel_shape", &[3, 3]),
                ints_attr("strides", &[2, 2]),
                int_attr("ceil_mode", 1),
                text_attr("auto_pad", mode),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Unsupported), "{mode}");
    }
    for extra in [int_attr("dilations", 1), ints_attr("dilations", &[0, 1])] {
        let source = pool_source(
            [1, 1, 4, 4],
            [1, 1, 2, 2],
            &[
                pool_attrs([3, 3], [2, 2], [0; 4]),
                int_attr("ceil_mode", 1),
                extra,
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Graph));
    }
    for (input, kernel, stride, output) in [
        ([1, 1, 2, 2], [4, 3], [2, 2], [1, 1, 1, 1]),
        ([1, 1, 2, 2], [3, 4], [2, 2], [1, 1, 1, 1]),
        ([1, 1, 4, 4], [3, 3], [2, 2], [1, 1, 1, 1]),
    ] {
        let source = pool_source(
            input,
            output,
            &[pool_attrs(kernel, stride, [0; 4]), int_attr("ceil_mode", 1)].concat(),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Graph));
    }
}

#[test]
fn native_ceil_geometry_refuses_empty_inputs_and_checks_full_width_arithmetic() -> Test {
    let mut attrs = AttributeMap::new();
    attrs.insert("kernel_size".into(), AttrValue::IntList(vec![2, 2]));
    attrs.insert("padding".into(), AttrValue::IntList(vec![1; 4]));
    attrs.insert("ceil_mode".into(), AttrValue::Bool(true));
    for shape in [[1, 1, 0, 2], [1, 1, 2, 0]] {
        let input = TensorPort::new(
            "input",
            DType::F32,
            Shape::new(shape.to_vec())?,
            GENERATION,
        )?;
        assert!(matches!(
            fss_model_ir::infer_operator_outputs(
                "pool",
                OpCode::MaxPool2d,
                &[&input],
                &["output".to_owned()],
                &attrs,
                GENERATION,
            ),
            Err(ModelIrError::ShapeMismatch { .. })
        ));
    }
    let input = TensorPort::new(
        "input",
        DType::F32,
        Shape::new(vec![1, 1, 1, 1])?,
        GENERATION,
    )?;
    attrs.insert("kernel_size".into(), AttrValue::IntList(vec![i64::MAX; 2]));
    attrs.insert("strides".into(), AttrValue::IntList(vec![i64::MAX; 2]));
    attrs.insert("padding".into(), AttrValue::IntList(vec![0; 4]));
    let output = fss_model_ir::infer_operator_outputs(
        "pool",
        OpCode::MaxPool2d,
        &[&input],
        &["output".to_owned()],
        &attrs,
        GENERATION,
    )?;
    assert_eq!(output[0].shape().dims(), &[1, 1, 1, 1]);

    let input = TensorPort::new(
        "input",
        DType::F32,
        Shape::new(vec![1, 1, i64::MAX as usize, 1])?,
        GENERATION,
    )?;
    attrs.insert(
        "padding".into(),
        AttrValue::IntList(vec![i64::MAX - 1, 0, i64::MAX - 1, 0]),
    );
    assert!(matches!(
        fss_model_ir::infer_operator_outputs(
            "pool",
            OpCode::MaxPool2d,
            &[&input],
            &["output".to_owned()],
            &attrs,
            GENERATION,
        ),
        Err(ModelIrError::ArithmeticOverflow { .. })
    ));
    Ok(())
}
