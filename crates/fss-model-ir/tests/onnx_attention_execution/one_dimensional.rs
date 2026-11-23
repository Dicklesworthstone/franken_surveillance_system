#![forbid(unsafe_code)]
//! NCW source graphs execute through real scalar/optimized engines and durable
//! artifacts. Coordinate oracles do not call production padding or shape code.

use super::*;
use fss_model_ir::{AttrValue, AttributeMap, GraphNode, ModelIrVersion, OpCode, TensorPort};
use fss_tensor::DType;

fn source(graph: &[u8], opset: i64) -> Vec<u8> {
    [integer(1, 8), bytes(8, &integer(2, opset)), bytes(7, graph)].concat()
}

fn spatial_dims(dims: &[usize], rank4: bool) -> Vec<usize> {
    let mut dims = dims.to_vec();
    if rank4 {
        dims.push(1);
    }
    dims
}

fn spatial_attr(name: &str, value: usize, rank4: bool) -> Vec<u8> {
    let values = if rank4 {
        vec![value as i64, 1]
    } else {
        vec![value as i64]
    };
    ints_attr(name, &values)
}

fn pad_attr(pads: [usize; 2], rank4: bool) -> Vec<u8> {
    let values = if rank4 {
        vec![pads[0] as i64, 0, pads[1] as i64, 0]
    } else {
        pads.map(|n| n as i64).to_vec()
    };
    ints_attr("pads", &values)
}

fn text_attr(name: &str, value: &str) -> Vec<u8> {
    attribute(name, 3, &bytes(4, value.as_bytes()))
}

fn pool_source(op: &str, input: &[usize], output: &[usize], attrs: &[u8], opset: i64) -> Vec<u8> {
    source(
        &[
            node(op, &["input"], &["output"], attrs),
            bytes(11, &info("input", input, 1)),
            bytes(12, &info("output", output, 1)),
        ]
        .concat(),
        opset,
    )
}

#[derive(Clone, Copy, Debug)]
struct Conv {
    input: [usize; 3],
    channels: usize,
    groups: usize,
    kernel: usize,
    stride: usize,
    dilation: usize,
    pads: [usize; 2],
}

impl Conv {
    fn output(self) -> [usize; 3] {
        let length = (self.input[2] + self.pads[0] + self.pads[1]
            - ((self.kernel - 1) * self.dilation + 1))
            / self.stride
            + 1;
        [self.input[0], self.channels, length]
    }

    fn weight_dims(self) -> [usize; 3] {
        [self.channels, self.input[1] / self.groups, self.kernel]
    }

    fn attrs(self, rank4: bool, automatic: Option<&str>) -> Vec<u8> {
        [
            int_attr("group", self.groups as i64),
            spatial_attr("kernel_shape", self.kernel, rank4),
            spatial_attr("strides", self.stride, rank4),
            spatial_attr("dilations", self.dilation, rank4),
            automatic.map_or_else(
                || pad_attr(self.pads, rank4),
                |mode| text_attr("auto_pad", mode),
            ),
        ]
        .concat()
    }

    fn source(
        self,
        weights: &[f32],
        bias: Option<&[f32]>,
        rank4: bool,
        automatic: Option<&str>,
        opset: i64,
    ) -> Vec<u8> {
        let inputs = if bias.is_some() {
            vec!["input", "weights", "bias"]
        } else {
            vec!["input", "weights"]
        };
        source(
            &[
                node("Conv", &inputs, &["output"], &self.attrs(rank4, automatic)),
                weight(
                    "weights",
                    &spatial_dims(&self.weight_dims(), rank4),
                    weights,
                ),
                bias.map_or_else(Vec::new, |values| weight("bias", &[self.channels], values)),
                bytes(11, &info("input", &spatial_dims(&self.input, rank4), 1)),
                bytes(12, &info("output", &spatial_dims(&self.output(), rank4), 1)),
            ]
            .concat(),
            opset,
        )
    }

    fn oracle(self, input: &[f32], weights: &[f32], bias: Option<&[f32]>) -> Vec<f32> {
        let mut output = Vec::new();
        let channels_per_group = self.input[1] / self.groups;
        for batch in 0..self.input[0] {
            for channel in 0..self.channels {
                let group = channel / (self.channels / self.groups);
                for position in 0..self.output()[2] {
                    let mut sum = 0.0_f32;
                    for within in 0..channels_per_group {
                        for tap in 0..self.kernel {
                            let coordinate = (position * self.stride + tap * self.dilation)
                                as isize
                                - self.pads[0] as isize;
                            if !(0..self.input[2] as isize).contains(&coordinate) {
                                continue;
                            }
                            let input_index =
                                (batch * self.input[1] + group * channels_per_group + within)
                                    * self.input[2]
                                    + coordinate as usize;
                            let weight_index =
                                (channel * channels_per_group + within) * self.kernel + tap;
                            sum += input[input_index] * weights[weight_index];
                        }
                    }
                    output.push(sum + bias.map_or(0.0, |values| values[channel]));
                }
            }
        }
        output
    }
}

#[test]
fn grouped_depthwise_and_dilated_convolution_match_coordinates_and_rank4() -> Test {
    for opset in [13, 17] {
        for groups in [1, 2, 4] {
            for (length, kernel, stride, dilation, pads) in [
                (1, 1, 1, 1, [0, 0]),
                (7, 3, 1, 1, [2, 0]),
                (8, 3, 2, 2, [0, 1]),
            ] {
                let conv = Conv {
                    input: [2, 4, length],
                    channels: 8,
                    groups,
                    kernel,
                    stride,
                    dilation,
                    pads,
                };
                let input = (0..conv.input.iter().product::<usize>())
                    .map(|n| ((n % 23) as f32 - 11.) * 0.25)
                    .collect::<Vec<_>>();
                let weights = (0..conv.weight_dims().iter().product::<usize>())
                    .map(|n| ((n % 7) as f32 - 3.) * 0.125)
                    .collect::<Vec<_>>();
                let bias = (0..conv.channels)
                    .map(|n| (n as f32 - 2.) * 0.25)
                    .collect::<Vec<_>>();
                for bias in [None, Some(bias.as_slice())] {
                    let source = conv.source(&weights, bias, false, None, opset);
                    let imported = import(&source)?;
                    assert_eq!(imported.graph().node_count(), 4);
                    assert_eq!(imported.graph().version(), ModelIrVersion::V1);
                    assert_eq!(imported.parameters().len(), 1 + usize::from(bias.is_some()));
                    assert_eq!(
                        imported.parameters()["weights"].shape().dims(),
                        conv.weight_dims()
                    );
                    assert_eq!(
                        bits(&imported.parameters()["weights"].to_vec::<f32>()?),
                        bits(&weights)
                    );
                    let actual = roundtrip(&source, &[("input", data(&conv.input, &input)?)])?;
                    assert_eq!(
                        bits(&actual["output"]),
                        bits(&conv.oracle(&input, &weights, bias)),
                        "{conv:?}, opset={opset}"
                    );
                    let rank4 = conv.source(&weights, bias, true, None, opset);
                    let equivalent = roundtrip(
                        &rank4,
                        &[("input", data(&spatial_dims(&conv.input, true), &input)?)],
                    )?;
                    assert_eq!(bits(&actual["output"]), bits(&equivalent["output"]));
                }
            }
        }
    }
    Ok(())
}

fn automatic_pads(
    length: usize,
    kernel: usize,
    stride: usize,
    dilation: usize,
    mode: &str,
) -> [usize; 2] {
    if mode == "VALID" {
        return [0, 0];
    }
    let output = length.div_ceil(stride);
    let total = ((output - 1) * stride + (kernel - 1) * dilation + 1).saturating_sub(length);
    let before = if mode == "SAME_LOWER" {
        total.div_ceil(2)
    } else {
        total / 2
    };
    [before, total - before]
}

// Enumerate complete windows in the source padded extent; ceil mode extends it
// only as far as the next stride and discards anchors outside the real input.
fn starts(length: usize, kernel: usize, stride: usize, pads: [usize; 2], ceil: bool) -> Vec<isize> {
    let padded = length + pads[0] + pads[1];
    let extent = if ceil {
        (padded..padded + stride)
            .find(|&n| n >= kernel && (n - kernel).is_multiple_of(stride))
            .unwrap_or(0)
    } else {
        padded
    };
    (0..extent)
        .step_by(stride)
        .filter(|&start| start + kernel <= extent && (!ceil || start < length + pads[0]))
        .map(|start| start as isize - pads[0] as isize)
        .collect()
}

fn pool_oracle(
    values: &[f32],
    input: [usize; 3],
    kernel: usize,
    windows: &[isize],
    average: bool,
    include_pad: bool,
) -> Test<Vec<f32>> {
    let mut output = Vec::new();
    for plane in 0..input[0] * input[1] {
        for &start in windows {
            let samples = (0..input[2])
                .filter(|&i| i as isize >= start && (i as isize) < start + kernel as isize)
                .map(|i| values[plane * input[2] + i])
                .collect::<Vec<_>>();
            if average {
                let sum = samples.iter().fold(0.0_f32, |sum, &value| sum + value);
                let divisor = if include_pad { kernel } else { samples.len() };
                if divisor == 0 {
                    return Err("empty mean window".into());
                }
                output.push(sum / divisor as f32);
            } else {
                output.push(
                    samples
                        .iter()
                        .copied()
                        .reduce(|a, b| if a >= b { a } else { b })
                        .ok_or("empty max window")?,
                );
            }
        }
    }
    Ok(output)
}

#[test]
fn pooling_keeps_partial_windows_padding_divisors_and_signed_zero() -> Test {
    for opset in [13, 17] {
        for (op, ceil, include_pad) in [
            ("MaxPool", false, false),
            ("MaxPool", true, false),
            ("AveragePool", false, false),
            ("AveragePool", false, true),
        ] {
            for (length, kernel, stride, pads) in [
                (1, 1, 1, [0, 0]),
                (4, 3, 2, [0, 0]),
                (5, 3, 2, [2, 1]),
                (2, 2, 2, [0, 1]),
                (1, 7, 8, [0, 0]),
            ] {
                let windows = starts(length, kernel, stride, pads, ceil);
                if windows.is_empty() {
                    continue;
                }
                let input = [2, 3, length];
                let output = [2, 3, windows.len()];
                let values = (0..input.iter().product::<usize>())
                    .map(|n| -((n % 17) as f32) * 0.25)
                    .collect::<Vec<_>>();
                let expected = pool_oracle(
                    &values,
                    input,
                    kernel,
                    &windows,
                    op == "AveragePool",
                    include_pad,
                )?;
                let mut outputs = Vec::new();
                for rank4 in [false, true] {
                    let attrs = [
                        spatial_attr("kernel_shape", kernel, rank4),
                        spatial_attr("strides", stride, rank4),
                        pad_attr(pads, rank4),
                        int_attr("ceil_mode", i64::from(ceil)),
                        if op == "AveragePool" {
                            int_attr("count_include_pad", i64::from(include_pad))
                        } else {
                            spatial_attr("dilations", 1, rank4)
                        },
                    ]
                    .concat();
                    let dims = spatial_dims(&input, rank4);
                    let source =
                        pool_source(op, &dims, &spatial_dims(&output, rank4), &attrs, opset);
                    let actual = roundtrip(&source, &[("input", data(&dims, &values)?)])?;
                    assert_eq!(
                        bits(&actual["output"]),
                        bits(&expected),
                        "{op}, length={length}, ceil={ceil}, pads={pads:?}, include_pad={include_pad}"
                    );
                    outputs.push(bits(&actual["output"]));
                }
                assert_eq!(outputs[0], outputs[1]);
            }
        }
    }
    let source = pool_source(
        "MaxPool",
        &[1, 1, 2],
        &[1, 1, 1],
        &ints_attr("kernel_shape", &[2]),
        13,
    );
    assert_eq!(
        bits(&roundtrip(&source, &[("input", data(&[1, 1, 2], &[-0., 0.])?)])?["output"]),
        bits(&[-0.])
    );
    Ok(())
}

#[test]
fn automatic_padding_preserves_one_dimensional_sampling_for_all_spatial_operators() -> Test {
    for opset in [13, 17] {
        for mode in ["VALID", "SAME_UPPER", "SAME_LOWER"] {
            let conv = Conv {
                input: [1, 2, 6],
                channels: 2,
                groups: 2,
                kernel: 3,
                stride: 2,
                dilation: 2,
                pads: automatic_pads(6, 3, 2, 2, mode),
            };
            let values = (0..12).map(|n| n as f32 - 6.).collect::<Vec<_>>();
            let weights = [1., -2., 3., -1., 2., -3.];
            let source = conv.source(&weights, None, false, Some(mode), opset);
            assert_eq!(
                bits(&roundtrip(&source, &[("input", data(&conv.input, &values)?)])?["output"]),
                bits(&conv.oracle(&values, &weights, None))
            );
            for op in ["MaxPool", "AveragePool"] {
                let pads = automatic_pads(6, 3, 2, 1, mode);
                let windows = starts(6, 3, 2, pads, false);
                let attrs = [
                    ints_attr("kernel_shape", &[3]),
                    ints_attr("strides", &[2]),
                    text_attr("auto_pad", mode),
                ]
                .concat();
                let source = pool_source(op, &[1, 2, 6], &[1, 2, windows.len()], &attrs, opset);
                let actual = roundtrip(&source, &[("input", data(&[1, 2, 6], &values)?)])?;
                assert_eq!(
                    bits(&actual["output"]),
                    bits(&pool_oracle(
                        &values,
                        [1, 2, 6],
                        3,
                        &windows,
                        op == "AveragePool",
                        false
                    )?),
                    "{op}, {mode}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn runtime_weights_and_composed_temporal_block_roundtrip() -> Test {
    let source = model(
        &[
            node("Conv", &["input", "weights"], &["features"], &[]),
            node("Relu", &["features"], &["positive"], &[]),
            node(
                "MaxPool",
                &["positive"],
                &["maximum"],
                &[ints_attr("kernel_shape", &[2]), ints_attr("strides", &[2])].concat(),
            ),
            node(
                "AveragePool",
                &["maximum"],
                &["mean"],
                &ints_attr("kernel_shape", &[2]),
            ),
            node("GlobalAveragePool", &["mean"], &["output"], &[]),
            bytes(11, &info("input", &[1, 1, 8], 1)),
            bytes(11, &info("weights", &[1, 1, 2], 1)),
            bytes(13, &info("features", &[1, 1, 7], 1)),
            bytes(13, &info("maximum", &[1, 1, 3], 1)),
            bytes(12, &info("output", &[1, 1, 1], 1)),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    assert_eq!(imported.runtime_inputs(), &["input", "weights"]);
    let actual = roundtrip(
        &source,
        &[
            (
                "input",
                data(&[1, 1, 8], &[-1., 2., -3., 4., -5., 6., -7., 8.])?,
            ),
            ("weights", data(&[1, 1, 2], &[1., 2.])?),
        ],
    )?;
    // Conv [3,-4,5,-6,7,-8,9], ReLU [3,0,5,0,7,0,9],
    // MaxPool [3,5,7], AveragePool [4,6], GlobalAveragePool [5].
    assert_eq!(bits(&actual["output"]), bits(&[5.]));
    Ok(())
}

#[test]
fn malformed_dimensions_attributes_and_unsupported_profiles_refuse() {
    let pool = |op: &str, attrs: Vec<u8>| pool_source(op, &[1, 1, 3], &[1, 1, 3], &attrs, 13);
    for op in ["MaxPool", "AveragePool"] {
        for attrs in [
            vec![],
            int_attr("kernel_shape", 1),
            ints_attr("kernel_shape", &[]),
            ints_attr("kernel_shape", &[1, 1]),
            ints_attr("kernel_shape", &[0]),
            ints_attr("kernel_shape", &[-1]),
            [ints_attr("kernel_shape", &[1]), ints_attr("strides", &[0])].concat(),
            [
                ints_attr("kernel_shape", &[1]),
                ints_attr("strides", &[1, 1]),
            ]
            .concat(),
            [
                ints_attr("kernel_shape", &[1]),
                ints_attr("pads", &[0, 0, 0, 0]),
            ]
            .concat(),
            [ints_attr("kernel_shape", &[1]), ints_attr("pads", &[-1, 0])].concat(),
            [ints_attr("kernel_shape", &[1]), ints_attr("pads", &[0, 1])].concat(),
            [ints_attr("kernel_shape", &[1]), int_attr("unrecognized", 0)].concat(),
            [
                ints_attr("kernel_shape", &[1]),
                text_attr("auto_pad", "SAME_UPPER"),
                ints_attr("pads", &[0, 0]),
            ]
            .concat(),
        ] {
            assert!(refusal(&pool(op, attrs)).is_some(), "{op}");
        }
        for dims in [
            vec![1, 1, 0],
            vec![0, 1, 3],
            vec![1, 0, 3],
            vec![1, 1, 1, 1, 3],
        ] {
            assert!(
                refusal(&pool_source(
                    op,
                    &dims,
                    &dims,
                    &ints_attr("kernel_shape", &[1]),
                    13
                ))
                .is_some()
            );
        }
    }
    for (op, attrs) in [
        (
            "MaxPool",
            [
                ints_attr("kernel_shape", &[1]),
                ints_attr("dilations", &[2]),
            ]
            .concat(),
        ),
        (
            "MaxPool",
            [
                ints_attr("kernel_shape", &[1]),
                int_attr("ceil_mode", 1),
                text_attr("auto_pad", "SAME_UPPER"),
            ]
            .concat(),
        ),
        (
            "AveragePool",
            [ints_attr("kernel_shape", &[1]), int_attr("ceil_mode", 1)].concat(),
        ),
        (
            "AveragePool",
            [
                ints_attr("kernel_shape", &[1]),
                ints_attr("dilations", &[1]),
            ]
            .concat(),
        ),
        (
            "AveragePool",
            [
                ints_attr("kernel_shape", &[1]),
                int_attr("count_include_pad", 2),
            ]
            .concat(),
        ),
    ] {
        assert!(refusal(&pool(op, attrs)).is_some());
    }
    for (weight_shape, attrs) in [
        (vec![1, 1, 1, 1], vec![]),
        (vec![1, 2, 1], vec![]),
        (vec![1, 1, 1], int_attr("group", 2)),
        (vec![1, 1, 1], ints_attr("kernel_shape", &[2])),
        (vec![1, 1, 1], ints_attr("dilations", &[0])),
        (vec![1, 1, 1], ints_attr("strides", &[-1])),
    ] {
        let source = model(
            &[
                node("Conv", &["input", "weights"], &["output"], &attrs),
                weight(
                    "weights",
                    &weight_shape,
                    &vec![1.; weight_shape.iter().product::<usize>()],
                ),
                bytes(11, &info("input", &[1, 1, 3], 1)),
                bytes(12, &info("output", &[1, 1, 3], 1)),
            ]
            .concat(),
        );
        assert!(refusal(&source).is_some());
    }
    for (op, inputs, outputs) in [
        ("Conv", vec!["input"], vec!["output"]),
        ("MaxPool", vec!["input", "input"], vec!["output"]),
        ("MaxPool", vec!["input"], vec!["output", "indices"]),
    ] {
        let source = model(
            &[
                node(op, &inputs, &outputs, &ints_attr("kernel_shape", &[1])),
                bytes(11, &info("input", &[1, 1, 3], 1)),
                bytes(12, &info("output", &[1, 1, 3], 1)),
            ]
            .concat(),
        );
        assert!(refusal(&source).is_some());
    }
}

#[test]
fn helpers_cannot_capture_source_names_or_missing_future_inputs() -> Test {
    let name = "onnx-node-0000-oned-input-0";
    let source = model(
        &[
            node(
                "MaxPool",
                &["input"],
                &[name],
                &ints_attr("kernel_shape", &[1]),
            ),
            bytes(11, &info("input", &[1, 1, 1], 1)),
            bytes(12, &info(name, &[1, 1, 1], 1)),
        ]
        .concat(),
    );
    assert_eq!(
        bits(&roundtrip(&source, &[("input", data(&[1, 1, 1], &[7.])?)])?[name]),
        bits(&[7.])
    );
    let source = model(
        &[
            node(
                "MaxPool",
                &["input"],
                &["pooled"],
                &ints_attr("kernel_shape", &[1]),
            ),
            node("Relu", &["onnx-node-0000-oned-spatial"], &["output"], &[]),
            bytes(11, &info("input", &[1, 1, 1], 1)),
            bytes(12, &info("output", &[1, 1, 1], 1)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&source), Some(OnnxError::Graph));
    Ok(())
}

#[test]
fn exact_import_bounds_include_all_helpers_and_cancellation_checkpoints() -> Test {
    let conv = Conv {
        input: [1, 1, 3],
        channels: 1,
        groups: 1,
        kernel: 1,
        stride: 1,
        dilation: 1,
        pads: [0, 0],
    };
    for (source, nodes, tensors, parameter_bytes) in [
        (conv.source(&[2.], None, false, None, 13), 4, 6, 4),
        (
            pool_source(
                "MaxPool",
                &[1, 1, 3],
                &[1, 1, 3],
                &ints_attr("kernel_shape", &[1]),
                13,
            ),
            3,
            4,
            0,
        ),
        (
            pool_source(
                "AveragePool",
                &[1, 1, 3],
                &[1, 1, 3],
                &ints_attr("kernel_shape", &[1]),
                13,
            ),
            4,
            7,
            8,
        ),
    ] {
        let imported = import(&source)?;
        let digest = ContentDigest::sha256(&source);
        let exact = OnnxLimits {
            source_bytes: source.len(),
            nodes,
            tensors,
            parameter_bytes,
            tensor_bytes: 12,
            work_units: imported.work_units(),
        };
        import_onnx(&source, digest, GENERATION, exact, &|| false)?;
        for limits in [
            OnnxLimits {
                source_bytes: exact.source_bytes - 1,
                ..exact
            },
            OnnxLimits {
                nodes: nodes - 1,
                ..exact
            },
            OnnxLimits {
                tensors: tensors - 1,
                ..exact
            },
            OnnxLimits {
                tensor_bytes: 11,
                ..exact
            },
        ] {
            assert_eq!(
                import_onnx(&source, digest, GENERATION, limits, &|| false).err(),
                Some(OnnxError::Limit)
            );
        }
        if parameter_bytes > 0 {
            assert_eq!(
                import_onnx(
                    &source,
                    digest,
                    GENERATION,
                    OnnxLimits {
                        parameter_bytes: parameter_bytes - 1,
                        ..exact
                    },
                    &|| false
                )
                .err(),
                Some(OnnxError::Limit)
            );
        }
        assert_eq!(
            import_onnx(
                &source,
                digest,
                GENERATION,
                OnnxLimits {
                    work_units: exact.work_units - 1,
                    ..exact
                },
                &|| false
            )
            .err(),
            Some(OnnxError::WorkBudget)
        );
        let calls = Cell::new(0);
        import_onnx(&source, digest, GENERATION, exact, &|| {
            calls.set(calls.get() + 1);
            false
        })?;
        for stop in 1..=calls.get() {
            let seen = Cell::new(0);
            assert_eq!(
                import_onnx(&source, digest, GENERATION, exact, &|| {
                    seen.set(seen.get() + 1);
                    seen.get() == stop
                })
                .err(),
                Some(OnnxError::Cancelled)
            );
        }
        assert_eq!(
            import_onnx(
                &source,
                ContentDigest::sha256(b"different source"),
                GENERATION,
                exact,
                &|| false
            )
            .err(),
            Some(OnnxError::Digest)
        );
    }
    Ok(())
}

#[test]
fn existing_rank4_conv_and_pool_canonical_graphs_are_unchanged() -> Test {
    let port = |name: &str, dims: &[usize]| -> Test<TensorPort> {
        Ok(TensorPort::new(
            name,
            DType::F32,
            Shape::new(dims.to_vec())?,
            GENERATION,
        )?)
    };
    for op in ["Conv", "MaxPool", "AveragePool"] {
        let (inputs, weights, attrs) = if op == "Conv" {
            (
                vec!["input", "weights"],
                weight("weights", &[1, 1, 2, 1], &[2., 3.]),
                vec![],
            )
        } else {
            (vec!["input"], vec![], ints_attr("kernel_shape", &[2, 1]))
        };
        let source = model(
            &[
                node(op, &inputs, &["output"], &attrs),
                weights,
                bytes(11, &info("input", &[1, 1, 4, 1], 1)),
                bytes(12, &info("output", &[1, 1, 3, 1], 1)),
            ]
            .concat(),
        );
        let actual = import(&source)?;
        let mut ports = vec![port("input", &[1, 1, 4, 1])?];
        let id = "onnx-node-0000";
        let nodes = match op {
            "Conv" => {
                ports.push(port("weights", &[1, 1, 2, 1])?);
                vec![GraphNode::new(
                    id,
                    OpCode::Conv2d,
                    id,
                    vec!["input".into(), "weights".into()],
                    vec!["output".into()],
                    AttributeMap::new(),
                )?]
            }
            "MaxPool" => vec![GraphNode::new(
                id,
                OpCode::MaxPool2d,
                id,
                vec!["input".into()],
                vec!["output".into()],
                AttributeMap::from([("kernel_size".into(), AttrValue::IntList(vec![2, 1]))]),
            )?],
            _ => {
                ports.push(port("onnx-node-0000-pool-ones", &[1, 1, 2, 1])?);
                ports.push(port("onnx-node-0000-pool-divisors", &[])?);
                vec![
                    GraphNode::new(
                        "onnx-node-0000-pool-sum",
                        OpCode::Conv2d,
                        id,
                        vec!["input".into(), "onnx-node-0000-pool-ones".into()],
                        vec!["onnx-node-0000-pool-sum".into()],
                        AttributeMap::from([
                            ("groups".into(), AttrValue::Int(1)),
                            ("padding".into(), AttrValue::IntList(vec![0; 4])),
                            ("strides".into(), AttrValue::IntList(vec![1, 1])),
                        ]),
                    )?,
                    GraphNode::new(
                        id,
                        OpCode::Div,
                        id,
                        vec![
                            "onnx-node-0000-pool-sum".into(),
                            "onnx-node-0000-pool-divisors".into(),
                        ],
                        vec!["output".into()],
                        AttributeMap::new(),
                    )?,
                ]
            }
        };
        let expected = ModelIrGraph::new_validated(
            "onnx-graph",
            ModelIrVersion::V1,
            GENERATION,
            ports,
            vec![port("output", &[1, 1, 3, 1])?],
            nodes,
        )?;
        assert_eq!(actual.graph(), &expected, "{op}");
        let expected_bytes = encode_canonical_model_ir(&expected)?;
        let artifacts = export(&actual)?;
        assert_eq!(artifacts.graph_bytes(), expected_bytes);
        assert_eq!(
            artifacts.graph_digest(),
            ContentDigest::sha256(&expected_bytes)
        );
    }
    Ok(())
}
