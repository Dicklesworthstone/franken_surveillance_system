#![forbid(unsafe_code)]
//! Real protobuf import and execution through the unchanged production scalar
//! executor. This target does not qualify the full asynchronous reference crate.

use std::cell::Cell;

use fss_core::{ContentDigest, Generation};
use fss_model_ir::{
    ImportedOnnx, OnnxError, OnnxExportLimits, OnnxLimits, decode_canonical_model_ir,
    encode_canonical_model_ir, export_onnx_artifacts, import_onnx,
};
use fss_tensor::{Shape, Tensor};

#[path = "../../fss-reference/src/scalar_executor.rs"]
pub mod scalar_executor;
use scalar_executor::{ExecBudget, ScalarExecCx, ScalarExecutor};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const GENERATION: Generation = Generation(7);
const HEAD: &[u8] = include_bytes!("fixtures/onnx/static_conv_head.onnx");

fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let low = (value & 127) as u8;
        value >>= 7;
        out.push(low | if value == 0 { 0 } else { 128 });
        if value == 0 {
            return out;
        }
    }
}
fn integer(tag: u64, value: i64) -> Vec<u8> {
    [varint(tag * 8), varint(value as u64)].concat()
}
fn bytes(tag: u64, value: &[u8]) -> Vec<u8> {
    [
        varint(tag * 8 + 2),
        varint(value.len() as u64),
        value.to_vec(),
    ]
    .concat()
}
fn fixed(tag: u64, value: f32) -> Vec<u8> {
    [varint(tag * 8 + 5), value.to_le_bytes().to_vec()].concat()
}
fn info(name: &str, dims: &[i64], dtype: i64) -> Vec<u8> {
    let shape: Vec<_> = dims
        .iter()
        .flat_map(|&n| bytes(1, &integer(1, n)))
        .collect();
    let tensor = [integer(1, dtype), bytes(2, &shape)].concat();
    [bytes(1, name.as_bytes()), bytes(2, &bytes(1, &tensor))].concat()
}
fn tensor(name: &str, dims: &[i64], dtype: i64, data: &[u8]) -> Vec<u8> {
    [
        dims.iter().flat_map(|&n| integer(1, n)).collect(),
        integer(2, dtype),
        bytes(8, name.as_bytes()),
        data.to_vec(),
    ]
    .concat()
}
fn i64_tensor(name: &str, values: &[i64], encoding: u8) -> Vec<u8> {
    let data = match encoding {
        0 => bytes(
            9,
            &values
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>(),
        ),
        1 => bytes(
            7,
            &values
                .iter()
                .flat_map(|n| varint(*n as u64))
                .collect::<Vec<_>>(),
        ),
        _ => values.iter().flat_map(|&n| integer(7, n)).collect(),
    };
    tensor(name, &[values.len() as i64], 7, &data)
}
fn attribute(name: &str, dtype: i64, data: &[u8]) -> Vec<u8> {
    bytes(
        5,
        &[bytes(1, name.as_bytes()), integer(20, dtype), data.to_vec()].concat(),
    )
}
fn node(op: &str, inputs: &[&str], output: &str, attrs: &[u8]) -> Vec<u8> {
    bytes(
        1,
        &[
            inputs.iter().flat_map(|n| bytes(1, n.as_bytes())).collect(),
            bytes(2, output.as_bytes()),
            bytes(4, op.as_bytes()),
            attrs.to_vec(),
        ]
        .concat(),
    )
}
fn constant(output: &str, tensor: &[u8]) -> Vec<u8> {
    node(
        "Constant",
        &[],
        output,
        &attribute("value", 4, &bytes(5, tensor)),
    )
}
fn int_constant(output: &str, values: &[i64]) -> Vec<u8> {
    node(
        "Constant",
        &[],
        output,
        &attribute(
            "value_ints",
            7,
            &bytes(
                8,
                &values
                    .iter()
                    .flat_map(|n| varint(*n as u64))
                    .collect::<Vec<_>>(),
            ),
        ),
    )
}
fn model(graph: &[u8]) -> Vec<u8> {
    [integer(1, 8), bytes(8, &integer(2, 13)), bytes(7, graph)].concat()
}
fn graph(input: &[i64], output: &[i64], body: &[u8]) -> Vec<u8> {
    model(
        &[
            bytes(11, &info("x", input, 1)),
            bytes(12, &info("y", output, 1)),
            body.to_vec(),
        ]
        .concat(),
    )
}
fn import(source: &[u8]) -> Test<ImportedOnnx<'_>> {
    Ok(import_onnx(
        source,
        ContentDigest::sha256(source),
        GENERATION,
        OnnxLimits::default(),
        &|| false,
    )?)
}
fn execute(
    imported: &ImportedOnnx<'_>,
    input_name: &str,
    dims: &[usize],
    values: &[f32],
    output: &str,
) -> Test<Vec<f32>> {
    let mut bindings: Vec<_> = imported
        .parameters()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    bindings.push((
        input_name.into(),
        Tensor::from_values(Shape::new(dims.to_vec())?, values, GENERATION)?,
    ));
    let result = ScalarExecutor::run(
        imported.graph(),
        &bindings,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;
    Ok(result
        .get_output(output)
        .ok_or("missing output")?
        .to_vec::<f32>()?)
}
fn refuses(source: &[u8], expected: OnnxError) {
    assert_eq!(
        import_onnx(
            source,
            ContentDigest::sha256(source),
            GENERATION,
            OnnxLimits::default(),
            &|| false
        )
        .err(),
        Some(expected)
    );
}
fn layout(op: &str, input: &[i64], output: &[i64], controls: &[i64]) -> Vec<u8> {
    graph(
        input,
        output,
        &[
            int_constant("control", controls),
            node(op, &["x", "control"], "y", &[]),
        ]
        .concat(),
    )
}

#[test]
fn convolution_head_round_trip_executes_and_exports_only_f32_parameters() -> Test {
    assert_eq!(HEAD.len(), 1075);
    assert_eq!(
        ContentDigest::sha256(HEAD).to_string(),
        "sha256:a6b486241551c8a3ce5032b42da918f332b4b3c00140d2956c151307e3c13f8a"
    );
    let imported = import(HEAD)?;
    assert_eq!(imported.source(), HEAD);
    assert_eq!(imported.runtime_inputs(), &["rgb"]);
    assert_eq!(
        imported
            .parameters()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["bias", "weights"]
    );
    assert_eq!(imported.graph().input_count(), 3);
    assert_eq!(imported.graph().node_count(), 6);
    let expected = [
        2.25, 6.5, 10.75, 9., 17.25, -4.5, 4.25, 8.5, 12.75, 13., 21.25, -2.5,
    ];
    let values: Vec<_> = (1..=12).map(|n| n as f32).collect();
    assert_eq!(
        execute(&imported, "rgb", &[1, 3, 2, 2], &values, "head")?,
        expected
    );
    let canonical = encode_canonical_model_ir(imported.graph())?;
    let decoded = decode_canonical_model_ir(&canonical, ContentDigest::sha256(&canonical))?;
    assert_eq!(encode_canonical_model_ir(&decoded)?, canonical);
    let exported = export_onnx_artifacts(&imported, OnnxExportLimits::default(), &|| false)?;
    assert_eq!(exported.source(), HEAD);
    assert_eq!(exported.graph_bytes(), canonical);
    assert_eq!(exported.source_digest(), ContentDigest::sha256(HEAD));
    assert_eq!(
        exported.weights_digest(),
        ContentDigest::sha256(exported.weights_bytes())
    );
    Ok(())
}

#[test]
fn raw_packed_and_unpacked_i64_initializers_are_shape_controls_only() -> Test {
    for encoding in 0..3 {
        let source = graph(
            &[2, 3],
            &[3, 2],
            &[
                bytes(5, &i64_tensor("shape", &[3, 2], encoding)),
                node("Reshape", &["x", "shape"], "y", &[]),
                bytes(13, &info("shape", &[2], 7)),
            ]
            .concat(),
        );
        let imported = import(&source)?;
        assert_eq!(imported.parameters().len(), 0);
        assert_eq!(imported.graph().input_count(), 1);
        assert_eq!(
            execute(&imported, "x", &[2, 3], &[1., 2., 3., 4., 5., 6.], "y")?,
            [1., 2., 3., 4., 5., 6.]
        );
    }
    Ok(())
}

#[test]
fn constant_tensor_name_is_not_a_graph_binding_and_preserves_f32_bits() -> Test {
    for data in [
        bytes(
            9,
            &[-0.0_f32, f32::from_bits(1), 2.]
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>(),
        ),
        bytes(
            4,
            &[-0.0_f32, f32::from_bits(1), 2.]
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>(),
        ),
        [-0.0_f32, f32::from_bits(1), 2.]
            .iter()
            .flat_map(|n| fixed(4, *n))
            .collect(),
    ] {
        let source = graph(
            &[3],
            &[3],
            &[
                constant("constant", &tensor("internal-name", &[3], 1, &data)),
                node("Add", &["x", "constant"], "y", &[]),
            ]
            .concat(),
        );
        let imported = import(&source)?;
        let values = imported.parameters()["constant"].to_vec::<f32>()?;
        assert_eq!(
            values.iter().map(|n| n.to_bits()).collect::<Vec<_>>(),
            [0x8000_0000, 1, 2.0_f32.to_bits()]
        );
        assert!(!imported.parameters().contains_key("internal-name"));
        assert_eq!(
            execute(&imported, "x", &[3], &[1., 2., 3.], "y")?,
            [1., 2., 5.]
        );
    }
    Ok(())
}

#[test]
fn f32_constant_scalar_and_list_attributes_execute() -> Test {
    for (name, ty, payload, expected) in [
        ("value_float", 1, fixed(2, 0.5), vec![1.5, 2.5]),
        (
            "value_floats",
            6,
            bytes(
                7,
                &[0.5_f32, 1.5]
                    .iter()
                    .flat_map(|n| n.to_le_bytes())
                    .collect::<Vec<_>>(),
            ),
            vec![1.5, 3.5],
        ),
    ] {
        let source = graph(
            &[2],
            &[2],
            &[
                node("Constant", &[], "c", &attribute(name, ty, &payload)),
                node("Add", &["x", "c"], "y", &[]),
            ]
            .concat(),
        );
        assert_eq!(
            execute(&import(&source)?, "x", &[2], &[1., 2.], "y")?,
            expected
        );
    }
    Ok(())
}

#[test]
fn f32_constant_can_be_a_declared_model_output_without_being_consumed() -> Test {
    let source = model(
        &[
            bytes(11, &info("x", &[1], 1)),
            bytes(12, &info("y", &[1], 1)),
            bytes(12, &info("constant_output", &[], 1)),
            node("Identity", &["x"], "y", &[]),
            node(
                "Constant",
                &[],
                "constant_output",
                &attribute("value_float", 1, &fixed(2, -0.0)),
            ),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    let values = execute(&imported, "x", &[1], &[4.], "constant_output")?;
    assert_eq!(values[0].to_bits(), (-0.0_f32).to_bits());
    assert_eq!(imported.runtime_inputs(), &["x"]);
    assert!(imported.parameters().contains_key("constant_output"));
    let artifacts = export_onnx_artifacts(&imported, OnnxExportLimits::default(), &|| false)?;
    assert_eq!(artifacts.source(), source);
    Ok(())
}

#[test]
fn empty_control_initializer_and_annotation_allow_scalar_reshape() -> Test {
    let source = graph(
        &[1],
        &[],
        &[
            bytes(5, &i64_tensor("shape", &[], 0)),
            bytes(13, &info("shape", &[0], 7)),
            node("Reshape", &["x", "shape"], "y", &[]),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    assert_eq!(execute(&imported, "x", &[1], &[7.], "y")?, [7.]);
    assert!(imported.parameters().is_empty());
    Ok(())
}

#[test]
fn reshape_supports_zero_copy_inference_and_empty_shape_scalar() -> Test {
    for (input, shape, output) in [
        (vec![2, 3, 4], vec![0, -1], vec![2, 12]),
        (vec![1], Vec::new(), Vec::new()),
    ] {
        let source = layout("Reshape", &input, &output, &shape);
        let imported = import(&source)?;
        let values: Vec<_> = (0..input.iter().product::<i64>())
            .map(|n| n as f32)
            .collect();
        let dims: Vec<_> = input.iter().map(|n| *n as usize).collect();
        assert_eq!(execute(&imported, "x", &dims, &values, "y")?, values);
    }
    Ok(())
}

#[test]
fn squeeze_omitted_empty_optional_and_explicit_empty_axes_are_distinct() -> Test {
    for inputs in [vec!["x"], vec!["x", ""]] {
        let source = graph(&[1, 2, 1], &[2], &node("Squeeze", &inputs, "y", &[]));
        assert_eq!(
            execute(&import(&source)?, "x", &[1, 2, 1], &[3., 4.], "y")?,
            [3., 4.]
        );
    }
    let source = layout("Squeeze", &[1, 2, 1], &[1, 2, 1], &[]);
    assert_eq!(
        execute(&import(&source)?, "x", &[1, 2, 1], &[3., 4.], "y")?,
        [3., 4.]
    );
    Ok(())
}

#[test]
fn negative_unsorted_axes_use_output_rank_for_unsqueeze() -> Test {
    let source = layout("Unsqueeze", &[2, 3], &[1, 2, 3, 1], &[-1, -4]);
    assert_eq!(
        execute(
            &import(&source)?,
            "x",
            &[2, 3],
            &[1., 2., 3., 4., 5., 6.],
            "y"
        )?,
        [1., 2., 3., 4., 5., 6.]
    );
    let source = layout("Squeeze", &[1, 2, 3, 1], &[2, 3], &[-1, -4]);
    assert_eq!(
        execute(
            &import(&source)?,
            "x",
            &[1, 2, 3, 1],
            &[1., 2., 3., 4., 5., 6.],
            "y"
        )?,
        [1., 2., 3., 4., 5., 6.]
    );
    Ok(())
}

fn slice(
    starts: &[i64],
    ends: &[i64],
    axes: Option<&[i64]>,
    steps: Option<&[i64]>,
    output: &[i64],
) -> Vec<u8> {
    slice_for_shape(&[3, 4], starts, ends, axes, steps, output)
}

fn slice_for_shape(
    input: &[i64],
    starts: &[i64],
    ends: &[i64],
    axes: Option<&[i64]>,
    steps: Option<&[i64]>,
    output: &[i64],
) -> Vec<u8> {
    let mut body = [int_constant("starts", starts), int_constant("ends", ends)].concat();
    let mut inputs = vec!["x", "starts", "ends"];
    if let Some(values) = axes {
        body.extend(int_constant("axes", values));
        inputs.push("axes");
    } else if steps.is_some() {
        inputs.push("");
    }
    if let Some(values) = steps {
        body.extend(int_constant("steps", values));
        inputs.push("steps");
    }
    body.extend(node("Slice", &inputs, "y", &[]));
    graph(input, output, &body)
}

#[test]
fn slice_normalizes_negative_bounds_axes_and_clamps_extreme_endpoints() -> Test {
    let input: Vec<_> = (0..12).map(|n| n as f32).collect();
    for (source, expected) in [
        (
            slice(&[-3, -3], &[i64::MAX, -1], None, None, &[3, 2]),
            vec![1., 2., 5., 6., 9., 10.],
        ),
        (
            slice(&[1], &[i64::MAX], Some(&[-1]), Some(&[2]), &[3, 2]),
            vec![1., 3., 5., 7., 9., 11.],
        ),
        (
            slice(&[i64::MIN], &[2], Some(&[-2]), None, &[2, 4]),
            vec![0., 1., 2., 3., 4., 5., 6., 7.],
        ),
        (
            slice(&[0], &[i64::MAX], None, Some(&[i64::MAX]), &[1, 4]),
            vec![0., 1., 2., 3.],
        ),
    ] {
        assert_eq!(
            execute(&import(&source)?, "x", &[3, 4], &input, "y")?,
            expected
        );
    }
    Ok(())
}

#[test]
fn reverse_slice_executes_mixed_strides_and_unsorted_negative_axes() -> Test {
    let input: Vec<_> = (0..12).map(|n| n as f32).collect();
    for (source, expected) in [
        (
            slice(&[2], &[-4], None, Some(&[-1]), &[3, 4]),
            vec![8., 9., 10., 11., 4., 5., 6., 7., 0., 1., 2., 3.],
        ),
        (
            slice(&[-1], &[i64::MIN], Some(&[-1]), Some(&[-2]), &[3, 2]),
            vec![3., 1., 7., 5., 11., 9.],
        ),
        (
            slice(
                &[i64::MAX, i64::MAX],
                &[i64::MIN, i64::MIN],
                Some(&[-1, -2]),
                Some(&[-1, -1]),
                &[3, 4],
            ),
            (0..12).rev().map(|n| n as f32).collect(),
        ),
        (
            slice(&[2, 0], &[i64::MIN, 4], None, Some(&[-2, 2]), &[2, 2]),
            vec![8., 10., 0., 2.],
        ),
        (
            slice(&[0, 3], &[3, i64::MIN], None, Some(&[2, -2]), &[2, 2]),
            vec![3., 1., 11., 9.],
        ),
        (
            slice(&[2], &[i64::MIN], None, Some(&[i64::MIN]), &[1, 4]),
            vec![8., 9., 10., 11.],
        ),
    ] {
        assert_eq!(
            execute(&import(&source)?, "x", &[3, 4], &input, "y")?,
            expected
        );
    }
    Ok(())
}

#[test]
fn reverse_slice_preserves_runtime_bits_and_reloaded_graphs_through_rank_eight() -> Test {
    let samples = [
        0_u32,
        0x8000_0000,
        1,
        0x8000_0001,
        0x7f7f_ffff,
        0xff7f_ffff,
        0x7f80_0000,
        0xff80_0000,
        0x7fc0_1234,
        0xffc0_4321,
    ];
    for rank in 1..=8 {
        let dims = vec![2; rank];
        let axes: Vec<_> = (1..=rank).map(|n| -(n as i64)).collect();
        let source = slice_for_shape(
            &dims,
            &vec![i64::MAX; rank],
            &vec![i64::MIN; rank],
            Some(&axes),
            Some(&vec![-1; rank]),
            &dims,
        );
        let input: Vec<_> = (0..(1 << rank))
            .map(|n| f32::from_bits(samples[n % samples.len()]))
            .collect();
        let expected: Vec<_> = input.iter().rev().map(|n| n.to_bits()).collect();
        let imported = import(&source)?;
        assert!(imported.parameters().is_empty());
        assert_eq!(imported.runtime_inputs(), ["x"]);
        assert_eq!(
            execute(&imported, "x", &vec![2; rank], &input, "y")?
                .iter()
                .map(|n| n.to_bits())
                .collect::<Vec<_>>(),
            expected,
        );
        let artifacts = export_onnx_artifacts(&imported, OnnxExportLimits::default(), &|| false)?;
        assert_eq!(artifacts.source(), source);
        let graph = decode_canonical_model_ir(artifacts.graph_bytes(), artifacts.graph_digest())?;
        assert_eq!(encode_canonical_model_ir(&graph)?, artifacts.graph_bytes());
        let result = ScalarExecutor::run(
            &graph,
            &[(
                "x".to_owned(),
                Tensor::from_values(Shape::new(vec![2; rank])?, &input, GENERATION)?,
            )],
            ExecBudget::unlimited(),
            &ScalarExecCx::new(),
        )?;
        assert_eq!(
            result
                .get_output("y")
                .ok_or("missing output")?
                .to_vec::<f32>()?
                .iter()
                .map(|n| n.to_bits())
                .collect::<Vec<_>>(),
            expected,
        );
    }
    Ok(())
}

#[test]
fn reverse_slice_matches_independent_index_walk_at_extreme_bounds() -> Test {
    for length in [1_i64, 2, 3, 6, 9] {
        let endpoints = [
            i64::MIN,
            -length - 1,
            -length,
            -1,
            0,
            1,
            length - 1,
            length,
            i64::MAX,
        ];
        let input: Vec<_> = (0..length).map(|n| (n + 1) as f32).collect();
        for start in endpoints {
            for end in endpoints {
                for step in [i64::MIN, -10, -2, -1] {
                    // Walk the source coordinates directly, without computing
                    // an output count or constructing a forward Slice.
                    let adjusted = |value: i64| {
                        i128::from(value) + if value < 0 { i128::from(length) } else { 0 }
                    };
                    let mut position = adjusted(start).clamp(0, i128::from(length - 1));
                    let stop = adjusted(end).clamp(-1, i128::from(length - 1));
                    let mut expected = Vec::new();
                    while position > stop {
                        expected.push(input[position as usize]);
                        position += i128::from(step);
                    }
                    let source = slice_for_shape(
                        &[length],
                        &[start],
                        &[end],
                        None,
                        Some(&[step]),
                        &[expected.len().max(1) as i64],
                    );
                    if expected.is_empty() {
                        refuses(&source, OnnxError::Unsupported);
                    } else {
                        assert_eq!(
                            execute(&import(&source)?, "x", &[length as usize], &input, "y")?,
                            expected,
                            "length={length} start={start} end={end} step={step}",
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn reverse_slice_preflights_expansion_and_honors_exact_resource_boundaries() -> Test {
    let source = slice_for_shape(&[4], &[3], &[i64::MIN], None, Some(&[-1]), &[4]);
    // Three control values plus x; five helpers plus the original output.
    // One preselection, four unit slices and one concatenation.
    let exact = OnnxLimits {
        nodes: 6,
        tensors: 10,
        parameter_bytes: 24,
        tensor_bytes: 16,
        ..OnnxLimits::default()
    };
    let run = |limits| {
        import_onnx(
            &source,
            ContentDigest::sha256(&source),
            GENERATION,
            limits,
            &|| false,
        )
    };
    let imported = run(exact)?;
    assert_eq!(imported.graph().node_count(), 6);
    assert!(imported.parameters().is_empty());
    for limits in [
        OnnxLimits { nodes: 5, ..exact },
        OnnxLimits {
            tensors: 9,
            ..exact
        },
        OnnxLimits {
            parameter_bytes: 23,
            ..exact
        },
        OnnxLimits {
            tensor_bytes: 15,
            ..exact
        },
    ] {
        assert_eq!(run(limits).err(), Some(OnnxError::Limit));
    }
    run(OnnxLimits {
        work_units: imported.work_units(),
        ..exact
    })?;
    assert_eq!(
        run(OnnxLimits {
            work_units: imported.work_units() - 1,
            ..exact
        })
        .err(),
        Some(OnnxError::WorkBudget),
    );
    let huge = slice_for_shape(
        &[1_000_000],
        &[i64::MAX],
        &[i64::MIN],
        None,
        Some(&[-1]),
        &[1_000_000],
    );
    refuses(&huge, OnnxError::Limit);
    // The source axis length is irrelevant when the selected output is small.
    let sparse = slice_for_shape(
        &[1_000_000],
        &[999_999],
        &[i64::MIN],
        None,
        Some(&[-999_999]),
        &[2],
    );
    assert_eq!(import(&sparse)?.graph().node_count(), 4);
    for source in [
        slice(&[2, 0], &[i64::MIN, 3], None, Some(&[-1, 0]), &[3, 4]),
        slice(
            &[2, 2],
            &[i64::MIN, i64::MIN],
            Some(&[0, -2]),
            Some(&[-1, -1]),
            &[3, 4],
        ),
        slice(&[2], &[i64::MIN], None, Some(&[-1]), &[2, 4]),
    ] {
        refuses(&source, OnnxError::Graph);
    }
    Ok(())
}

#[test]
fn reverse_slice_checks_cancellation_at_every_checkpoint() -> Test {
    let source = slice(
        &[2, 3],
        &[i64::MIN, i64::MIN],
        None,
        Some(&[-1, -1]),
        &[3, 4],
    );
    let total = Cell::new(0);
    import_onnx(
        &source,
        ContentDigest::sha256(&source),
        GENERATION,
        OnnxLimits::default(),
        &|| {
            total.set(total.get() + 1);
            false
        },
    )?;
    for after in 0..total.get() {
        let calls = Cell::new(0);
        assert_eq!(
            import_onnx(
                &source,
                ContentDigest::sha256(&source),
                GENERATION,
                OnnxLimits::default(),
                &|| {
                    let n = calls.get();
                    calls.set(n + 1);
                    n >= after
                }
            )
            .err(),
            Some(OnnxError::Cancelled),
            "checkpoint {after}",
        );
    }
    Ok(())
}

#[test]
fn reverse_slice_helpers_cannot_alias_a_source_output_or_satisfy_missing_values() -> Test {
    let name = "onnx-node-0003-slice-6";
    let controls = [
        int_constant("starts", &[3]),
        int_constant("ends", &[i64::MIN]),
        int_constant("steps", &[-1]),
    ]
    .concat();
    let source = model(
        &[
            bytes(11, &info("x", &[4], 1)),
            bytes(12, &info(name, &[4], 1)),
            controls.clone(),
            node("Slice", &["x", "starts", "ends", "", "steps"], name, &[]),
        ]
        .concat(),
    );
    assert_eq!(
        execute(&import(&source)?, "x", &[4], &[1., 2., 3., 4.], name)?,
        [4., 3., 2., 1.]
    );
    let missing = model(
        &[
            bytes(11, &info("x", &[4], 1)),
            bytes(12, &info("y", &[4], 1)),
            bytes(12, &info(name, &[4], 1)),
            controls,
            node("Slice", &["x", "starts", "ends", "", "steps"], "y", &[]),
        ]
        .concat(),
    );
    refuses(&missing, OnnxError::Graph);
    Ok(())
}

#[test]
fn illegal_axes_shapes_and_slice_steps_refuse() {
    for source in [
        layout("Reshape", &[2, 3], &[6], &[-1, -1]),
        layout("Reshape", &[2, 3], &[6], &[4]),
        layout("Reshape", &[2, 3], &[6], &[0, 0, 0]),
        layout("Squeeze", &[2, 1], &[2], &[0]),
        layout("Squeeze", &[1, 2, 1], &[2], &[0, -3]),
        layout("Unsqueeze", &[2], &[1, 2, 1], &[0, -3]),
        layout("Unsqueeze", &[2], &[1, 2], &[2]),
        slice(&[0, 0], &[2, 3], Some(&[1, -1]), None, &[3, 2]),
        slice(&[0], &[2], None, Some(&[0]), &[2, 4]),
        slice(&[0], &[2, 3], None, None, &[2, 4]),
    ] {
        refuses(&source, OnnxError::Graph);
    }
    refuses(
        &slice(&[2], &[-1], None, Some(&[-1]), &[3, 4]),
        OnnxError::Unsupported,
    );
    refuses(
        &slice(&[4], &[0], Some(&[1]), None, &[3, 4]),
        OnnxError::Unsupported,
    );
}

#[test]
fn integer_runtime_ports_or_data_paths_and_dynamic_controls_refuse() {
    let body = node("Identity", &["x"], "y", &[]);
    for (input_type, output_type) in [(7, 1), (1, 7)] {
        refuses(
            &model(
                &[
                    bytes(11, &info("x", &[1], input_type)),
                    bytes(12, &info("y", &[1], output_type)),
                    body.clone(),
                ]
                .concat(),
            ),
            OnnxError::Unsupported,
        );
    }
    refuses(
        &graph(
            &[1],
            &[1],
            &[int_constant("c", &[1]), node("Add", &["x", "c"], "y", &[])].concat(),
        ),
        OnnxError::Unsupported,
    );
    refuses(
        &model(
            &[
                bytes(11, &info("x", &[1], 1)),
                bytes(11, &info("shape", &[1], 1)),
                bytes(12, &info("y", &[1], 1)),
                node("Reshape", &["x", "shape"], "y", &[]),
            ]
            .concat(),
        ),
        OnnxError::Unsupported,
    );
    refuses(
        &graph(&[0], &[1], &node("Identity", &["x"], "y", &[])),
        OnnxError::Unsupported,
    );
    refuses(
        &graph(
            &[1],
            &[1],
            &[
                constant("empty", &tensor("", &[0], 1, &bytes(9, &[]))),
                node("Add", &["x", "empty"], "y", &[]),
            ]
            .concat(),
        ),
        OnnxError::Unsupported,
    );
}

#[test]
fn duplicates_forward_controls_and_unused_annotations_cannot_create_bindings() {
    let shape = int_constant("shape", &[1]);
    refuses(
        &graph(
            &[1],
            &[1],
            &[
                shape.clone(),
                shape.clone(),
                node("Reshape", &["x", "shape"], "y", &[]),
            ]
            .concat(),
        ),
        OnnxError::Graph,
    );
    refuses(
        &graph(
            &[1],
            &[1],
            &[node("Reshape", &["x", "shape"], "y", &[]), shape.clone()].concat(),
        ),
        OnnxError::Unsupported,
    );
    refuses(
        &graph(
            &[1],
            &[1],
            &[
                shape,
                node("Identity", &["x"], "y", &[]),
                bytes(13, &info("shape", &[1], 7)),
            ]
            .concat(),
        ),
        OnnxError::Graph,
    );
    refuses(
        &graph(
            &[1],
            &[1],
            &[int_constant("x", &[1]), node("Identity", &["x"], "y", &[])].concat(),
        ),
        OnnxError::Graph,
    );
    refuses(
        &graph(
            &[1],
            &[1],
            &[
                int_constant("shape", &[1]),
                node("Reshape", &["x", "shape"], "y", &[]),
                bytes(13, &info("shape", &[2], 7)),
            ]
            .concat(),
        ),
        OnnxError::Graph,
    );
}

#[test]
fn constant_wire_types_mixed_payloads_and_nonfinite_data_refuse() {
    let use_constant = |attrs: Vec<u8>| {
        graph(
            &[1],
            &[1],
            &[
                node("Constant", &[], "c", &attrs),
                node("Add", &["x", "c"], "y", &[]),
            ]
            .concat(),
        )
    };
    for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        refuses(
            &use_constant(attribute("value_float", 1, &fixed(2, value))),
            OnnxError::NonFinite,
        );
    }
    refuses(
        &use_constant(
            [
                attribute("value_float", 1, &fixed(2, 1.)),
                attribute("value_int", 2, &integer(3, 1)),
            ]
            .concat(),
        ),
        OnnxError::Malformed,
    );
    refuses(
        &use_constant(attribute(
            "value_float",
            1,
            &[fixed(2, 1.), integer(3, 1)].concat(),
        )),
        OnnxError::Malformed,
    );
    refuses(
        &use_constant(attribute(
            "value",
            4,
            &bytes(
                5,
                &tensor(
                    "",
                    &[1],
                    1,
                    &[fixed(4, 1.), bytes(9, &1.0_f32.to_le_bytes())].concat(),
                ),
            ),
        )),
        OnnxError::Malformed,
    );
    refuses(
        &use_constant(attribute(
            "value",
            4,
            &bytes(5, &tensor("", &[1], 1, &integer(7, 1))),
        )),
        OnnxError::Malformed,
    );
    refuses(
        &use_constant(attribute("value_string", 3, &bytes(4, b"no"))),
        OnnxError::Unsupported,
    );
    refuses(
        &use_constant(attribute(
            "value",
            4,
            &bytes(5, &tensor("", &[1], 7, &bytes(9, &[1, 2, 3]))),
        )),
        OnnxError::Malformed,
    );
}

#[test]
fn control_and_parameter_bytes_share_one_aggregate_quota() -> Test {
    let source = graph(
        &[2],
        &[2],
        &[
            int_constant("shape", &[2]),
            node(
                "Constant",
                &[],
                "bias",
                &attribute("value_float", 1, &fixed(2, 1.)),
            ),
            node("Reshape", &["x", "shape"], "shaped", &[]),
            node("Add", &["shaped", "bias"], "y", &[]),
        ]
        .concat(),
    );
    let run = |parameter_bytes| {
        import_onnx(
            &source,
            ContentDigest::sha256(&source),
            GENERATION,
            OnnxLimits {
                parameter_bytes,
                ..OnnxLimits::default()
            },
            &|| false,
        )
    };
    assert_eq!(run(11).err(), Some(OnnxError::Limit));
    let imported = run(12)?;
    assert_eq!(imported.parameters().len(), 1);
    assert_eq!(execute(&imported, "x", &[2], &[3., 4.], "y")?, [4., 5.]);
    Ok(())
}

#[test]
fn controls_count_towards_tensor_source_node_and_work_limits() -> Test {
    let imported = import(HEAD)?;
    for limits in [
        OnnxLimits {
            nodes: 11,
            ..OnnxLimits::default()
        },
        OnnxLimits {
            tensors: 8,
            ..OnnxLimits::default()
        },
        OnnxLimits {
            parameter_bytes: 80,
            ..OnnxLimits::default()
        },
        OnnxLimits {
            tensor_bytes: 16,
            ..OnnxLimits::default()
        },
    ] {
        assert_eq!(
            import_onnx(
                HEAD,
                ContentDigest::sha256(HEAD),
                GENERATION,
                limits,
                &|| false
            )
            .err(),
            Some(OnnxError::Limit)
        );
    }
    assert_eq!(
        import_onnx(
            HEAD,
            ContentDigest::sha256(HEAD),
            GENERATION,
            OnnxLimits {
                work_units: imported.work_units() - 1,
                ..OnnxLimits::default()
            },
            &|| false
        )
        .err(),
        Some(OnnxError::WorkBudget)
    );
    Ok(())
}

#[test]
fn every_truncated_prefix_and_cancellation_refuse_without_partial_graph() -> Test {
    for length in 0..HEAD.len() {
        let source = &HEAD[..length];
        assert!(
            import_onnx(
                source,
                ContentDigest::sha256(source),
                GENERATION,
                OnnxLimits::default(),
                &|| false
            )
            .is_err(),
            "prefix {length}"
        );
    }
    let total = Cell::new(0);
    import_onnx(
        HEAD,
        ContentDigest::sha256(HEAD),
        GENERATION,
        OnnxLimits::default(),
        &|| {
            total.set(total.get() + 1);
            false
        },
    )?;
    for after in [0, 1, total.get() / 2, total.get() - 1] {
        let calls = Cell::new(0);
        let cancelled = || {
            let n = calls.get();
            calls.set(n + 1);
            n >= after
        };
        assert_eq!(
            import_onnx(
                HEAD,
                ContentDigest::sha256(HEAD),
                GENERATION,
                OnnxLimits::default(),
                &cancelled
            )
            .err(),
            Some(OnnxError::Cancelled)
        );
    }
    Ok(())
}
