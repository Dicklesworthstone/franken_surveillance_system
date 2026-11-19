#![forbid(unsafe_code)]
//! Larger and multidimensional constant Gather indices retain exact data layout.

use super::*;
use fss_model_ir::{AttrValue, AttributeMap, GraphNode, ModelIrVersion, OpCode, TensorPort};
use fss_tensor::DType;

fn gathered_shape(data_dims: &[usize], axis: usize, index_dims: &[usize]) -> Vec<usize> {
    [
        &data_dims[..axis],
        index_dims,
        &data_dims[axis + 1..],
    ]
    .concat()
}

fn index_tensor(name: &str, dims: &[usize], indices: &[i64], packed: bool) -> Vec<u8> {
    let payload = if packed {
        bytes(
            7,
            &indices
                .iter()
                .flat_map(|&value| varint(value as u64))
                .collect::<Vec<_>>(),
        )
    } else {
        indices.iter().flat_map(|&value| integer(7, value)).collect()
    };
    [
        dims.iter()
            .flat_map(|&dim| integer(1, dim as i64))
            .collect(),
        integer(2, 7),
        bytes(8, name.as_bytes()),
        payload,
    ]
    .concat()
}

#[test]
fn multidimensional_indices_cover_all_admitted_result_ranks_and_data_axes() -> Test {
    let special = [
        -0.0_f32,
        0.0,
        f32::from_bits(1),
        -f32::from_bits(1),
        f32::MIN,
        f32::MAX,
        f32::MIN_POSITIVE,
        -3.25,
    ];
    for data_rank in 1..=7 {
        let dims = vec![2; data_rank];
        let values = (0..dims.iter().product::<usize>())
            .map(|index| special[index % special.len()])
            .collect::<Vec<_>>();
        for index_rank in 2..=9 - data_rank {
            let mut index_dims = vec![1; index_rank];
            index_dims[index_rank - 1] = 2;
            for axis in 0..data_rank {
                let output = gathered_shape(&dims, axis, &index_dims);
                let source = gather_model(
                    &dims,
                    &index_dims,
                    &[-1, 0],
                    axis as i64 - data_rank as i64,
                    &output,
                );
                let imported = import(&source)?;
                assert!(imported.parameters().is_empty());
                assert_eq!(imported.runtime_inputs(), &["input"]);
                assert_eq!(imported.graph().outputs()[0].shape().dims(), output);
                assert_eq!(
                    bits(&roundtrip(&source, &[("input", data(&dims, &values)?)])?["output"]),
                    bits(&gather_oracle(&values, &dims, axis, &[-1, 0])),
                    "data_rank={data_rank} index_rank={index_rank} axis={axis}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn larger_indices_accept_all_embedded_encodings_and_exact_type_witnesses() -> Test {
    let dims = [2, 5, 3];
    let indices = [-1_i64, 0, -1, 2, 1, 4, 3, 2, 1, 0];
    let values = (0..30)
        .map(|index| if index % 4 == 0 { -0.0 } else { index as f32 - 8.0 })
        .collect::<Vec<_>>();
    for storage in 0..5 {
        let index_dims = if storage == 4 { vec![10] } else { vec![2, 5] };
        let stored = match storage {
            0 => int_weight("indices", &index_dims, &indices),
            1 | 2 => bytes(
                5,
                &index_tensor("indices", &index_dims, &indices, storage == 1),
            ),
            3 => node(
                "Constant",
                &[],
                &["indices"],
                &attribute(
                    "value",
                    4,
                    &bytes(
                        5,
                        &tensor(
                            "tensor-metadata",
                            &index_dims,
                            7,
                            &indices
                                .iter()
                                .flat_map(|value| value.to_le_bytes())
                                .collect::<Vec<_>>(),
                        ),
                    ),
                ),
            ),
            _ => node("Constant", &[], &["indices"], &ints_attr("value_ints", &indices)),
        };
        for constant_data in [false, true] {
            let mut graph = [
                stored.clone(),
                node(
                    "Gather",
                    &["input", "indices"],
                    &["output"],
                    &int_attr("axis", 1),
                ),
                bytes(13, &info("indices", &index_dims, 7)),
                bytes(12, &info("output", &gathered_shape(&dims, 1, &index_dims), 1)),
            ]
            .concat();
            let input = if constant_data {
                graph.extend(weight("input", &dims, &values));
                Vec::new()
            } else {
                graph.extend(bytes(11, &info("input", &dims, 1)));
                vec![("input", data(&dims, &values)?)]
            };
            let source = model(&graph);
            let imported = import(&source)?;
            assert_eq!(imported.parameters().len(), usize::from(constant_data));
            assert_eq!(imported.runtime_inputs().len(), usize::from(!constant_data));
            assert_eq!(
                bits(&roundtrip(&source, &input)?["output"]),
                bits(&gather_oracle(&values, &dims, 1, &indices)),
                "storage={storage} constant_data={constant_data}"
            );
        }
    }
    Ok(())
}

#[test]
fn long_contiguous_runs_and_multidimensional_permutations_keep_exact_sample_bits() -> Test {
    let dims = [2, 4096, 2];
    let indices = (0..4096).map(i64::from).collect::<Vec<_>>();
    let values = (0..dims.iter().product::<usize>())
        .map(|index| if index % 7 == 0 { -0.0 } else { index as f32 / 8.0 })
        .collect::<Vec<_>>();
    let source = gather_model(&dims, &[4096], &indices, 1, &dims);
    assert_eq!(import(&source)?.graph().node_count(), 1);
    assert_eq!(
        bits(&roundtrip(&source, &[("input", data(&dims, &values)?)])?["output"]),
        bits(&values)
    );

    let dims = [2, 64, 3];
    let indices = (0..64).rev().map(i64::from).collect::<Vec<_>>();
    let values = (0..dims.iter().product::<usize>())
        .map(|index| index as f32 - 99.5)
        .collect::<Vec<_>>();
    let source = gather_model(&dims, &[8, 8], &indices, -2, &[2, 8, 8, 3]);
    assert_eq!(import(&source)?.graph().node_count(), 66);
    assert_eq!(
        bits(&roundtrip(&source, &[("input", data(&dims, &values)?)])?["output"]),
        bits(&gather_oracle(&values, &dims, 1, &indices))
    );
    Ok(())
}

#[test]
fn generated_concat_exceeds_source_arity_within_the_native_node_budget() -> Test {
    // ONNX source nodes have an input-list ceiling; generated native Concat
    // nodes instead share the native graph's bounded node and named-value quotas.
    for (count, index_dims, nodes) in [
        (257, vec![257], 258),
        (511, vec![511], 512),
        (510, vec![2, 255], 512),
    ] {
        let indices = (0..count).rev().map(|value| value as i64).collect::<Vec<_>>();
        let values = (0..count)
            .map(|index| if index % 7 == 0 { -0.0 } else { index as f32 })
            .collect::<Vec<_>>();
        let source = gather_model(&[count], &index_dims, &indices, 0, &index_dims);
        let imported = import(&source)?;
        assert_eq!(imported.graph().node_count(), nodes);
        let concat = imported
            .graph()
            .nodes()
            .iter()
            .find(|node| node.op() == OpCode::Concat)
            .ok_or("missing concatenation")?;
        assert_eq!(concat.inputs().len(), count);
        assert_eq!(
            bits(&roundtrip(&source, &[("input", data(&[count], &values)?)])?["output"]),
            bits(&gather_oracle(&values, &[count], 0, &indices))
        );
    }
    for (count, index_dims) in [(512, vec![512]), (511, vec![1, 511])] {
        let indices = (0..count).rev().map(|value| value as i64).collect::<Vec<_>>();
        assert_eq!(
            refusal(&gather_model(&[count], &index_dims, &indices, 0, &index_dims)),
            Some(OnnxError::Limit)
        );
    }
    Ok(())
}

#[test]
fn selected_token_blocks_feed_a_batched_vector_projection_after_artifact_reload() -> Test {
    let indices = [7_i64, 0, 7, 6, 4, 2, 1, 1, 5, 3, 6, 0];
    let values = (0..16).map(|index| index as f32 - 4.0).collect::<Vec<_>>();
    let projection = [0.25_f32, -1.0, 2.0];
    let source = model(
        &[
            node(
                "Gather",
                &["input", "indices"],
                &["tokens"],
                &int_attr("axis", 1),
            ),
            node("MatMul", &["tokens", "projection"], &["output"], &[]),
            int_weight("indices", &[4, 3], &indices),
            weight("projection", &[3], &projection),
            bytes(11, &info("input", &[2, 8], 1)),
            bytes(13, &info("tokens", &[2, 4, 3], 1)),
            bytes(12, &info("output", &[2, 4], 1)),
        ]
        .concat(),
    );
    let expected = gather_oracle(&values, &[2, 8], 1, &indices)
        .chunks_exact(3)
        .map(|chunk| {
            chunk
                .iter()
                .zip(projection)
                .fold(0.0_f32, |sum, (&value, weight)| sum + value * weight)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        bits(&roundtrip(&source, &[("input", data(&[2, 8], &values)?)])?["output"]),
        bits(&expected)
    );
    Ok(())
}

#[test]
fn previous_scalar_and_vector_gathers_keep_their_exact_canonical_graphs() -> Test {
    for (index_dims, indices, output, ranges, scalar) in [
        (vec![], vec![1], vec![2], vec![(1, 2)], true),
        (
            vec![3],
            vec![-1, 0, -1],
            vec![2, 3],
            vec![(2, 3), (0, 1), (2, 3)],
            false,
        ),
        (
            vec![3],
            vec![-3, -2, -1],
            vec![2, 3],
            vec![(0, 3)],
            false,
        ),
    ] {
        let source = gather_model(&[2, 3], &index_dims, &indices, 1, &output);
        let imported = import(&source)?;
        let total = ranges.len() + usize::from(ranges.len() > 1) + usize::from(scalar);
        let mut nodes = Vec::new();
        let mut selected = Vec::new();
        for (ordinal, &(start, end)) in ranges.iter().enumerate() {
            let id = if total == 1 {
                "onnx-node-0000".to_owned()
            } else {
                format!("onnx-node-0000-gather-{}", total - ordinal)
            };
            let result = if total == 1 { "output".to_owned() } else { id.clone() };
            nodes.push(GraphNode::new(
                id,
                OpCode::Slice,
                "onnx-node-0000",
                vec!["input".into()],
                vec![result.clone()],
                AttributeMap::from([
                    ("axes".into(), AttrValue::IntList(vec![1])),
                    ("starts".into(), AttrValue::IntList(vec![start])),
                    ("ends".into(), AttrValue::IntList(vec![end])),
                    ("steps".into(), AttrValue::IntList(vec![1])),
                ]),
            )?);
            selected.push(result);
        }
        if ranges.len() > 1 || scalar {
            nodes.push(GraphNode::new(
                "onnx-node-0000",
                if scalar { OpCode::Reshape } else { OpCode::Concat },
                "onnx-node-0000",
                selected,
                vec!["output".into()],
                if scalar {
                    AttributeMap::from([("shape".into(), AttrValue::IntList(vec![2]))])
                } else {
                    AttributeMap::from([("axis".into(), AttrValue::Int(1))])
                },
            )?);
        }
        let port = |name: &str, dims: &[usize]| -> Test<TensorPort> {
            Ok(TensorPort::new(
                name,
                DType::F32,
                Shape::new(dims.to_vec())?,
                GENERATION,
            )?)
        };
        let expected = ModelIrGraph::new_validated(
            "onnx-graph",
            ModelIrVersion::V1,
            GENERATION,
            vec![port("input", &[2, 3])?],
            vec![port("output", &output)?],
            nodes,
        )?;
        assert_eq!(imported.graph(), &expected);
        assert_eq!(
            encode_canonical_model_ir(imported.graph())?,
            encode_canonical_model_ir(&expected)?
        );
    }
    Ok(())
}

#[test]
fn enlarged_index_tensors_do_not_expand_other_shape_control_profiles() {
    for (dims, values, expected) in [
        (vec![1, 1], vec![1], OnnxError::Unsupported),
        (vec![9], vec![1; 9], OnnxError::Limit),
    ] {
        let source = model(
            &[
                node("Reshape", &["input", "shape"], &["output"], &[]),
                int_weight("shape", &dims, &values),
                bytes(11, &info("input", &[1], 1)),
                bytes(12, &info("output", &[1], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(expected));
        let source = model(
            &[
                node("Identity", &["shape"], &["copy"], &[]),
                node("Reshape", &["input", "copy"], &["output"], &[]),
                int_weight("shape", &dims, &values),
                bytes(11, &info("input", &[1], 1)),
                bytes(12, &info("output", &[1], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(expected));
        let source = model(
            &[
                node("Shape", &["shape"], &["copy"], &[]),
                node("Reshape", &["input", "copy"], &["output"], &[]),
                int_weight("shape", &dims, &values),
                bytes(11, &info("input", &[1], 1)),
                bytes(12, &info("output", &[1], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(expected));
    }
    let source = model(
        &[
            node(
                "ConstantOfShape",
                &["dimensions"],
                &["shape"],
                &attribute(
                    "value",
                    4,
                    &bytes(5, &tensor("fill", &[1, 1], 7, &1_i64.to_le_bytes())),
                ),
            ),
            node("Reshape", &["input", "shape"], &["output"], &[]),
            int_weight("dimensions", &[1], &[1]),
            bytes(11, &info("input", &[1], 1)),
            bytes(12, &info("output", &[1], 1)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&source), Some(OnnxError::Unsupported));
    assert_eq!(
        refusal(&gather_model(&[2, 3], &[1; 8], &[0], 1, &[1])),
        Some(OnnxError::Unsupported)
    );
    assert_eq!(
        refusal(&gather_model(&[2, 3], &[2, 2], &[0, 1, 2, 0], 1, &[2, 4])),
        Some(OnnxError::Graph)
    );
    assert_eq!(
        refusal(&gather_model(&[2, 3], &[2, 2], &[0, 1, 2], 1, &[2, 2, 2])),
        Some(OnnxError::Malformed)
    );
    assert_eq!(
        refusal(&gather_model(&[2, 3], &[2, 2], &[0, 1, i64::MAX, 0], 1, &[2, 2, 2])),
        Some(OnnxError::Graph)
    );
}

#[test]
fn large_index_lowering_has_exact_aggregate_limits_and_cancellable_checkpoints() -> Test {
    let indices = (0..12).rev().map(i64::from).collect::<Vec<_>>();
    let source = gather_model(&[2, 12, 3], &[3, 4], &indices, 1, &[2, 3, 4, 3]);
    let imported = import(&source)?;
    assert_eq!(imported.graph().node_count(), 14);
    let digest = ContentDigest::sha256(&source);
    let exact = OnnxLimits {
        nodes: 14,
        tensors: 16,
        parameter_bytes: 96,
        tensor_bytes: 288,
        work_units: imported.work_units(),
        ..OnnxLimits::default()
    };
    import_onnx(&source, digest, GENERATION, exact, &|| false)?;
    for limits in [
        OnnxLimits { nodes: 13, ..exact },
        OnnxLimits { tensors: 15, ..exact },
        OnnxLimits { parameter_bytes: 95, ..exact },
        OnnxLimits { tensor_bytes: 287, ..exact },
    ] {
        assert_eq!(
            import_onnx(&source, digest, GENERATION, limits, &|| false).err(),
            Some(OnnxError::Limit)
        );
    }
    assert_eq!(
        import_onnx(
            &source,
            digest,
            GENERATION,
            OnnxLimits { work_units: exact.work_units - 1, ..exact },
            &|| false,
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
            Some(OnnxError::Cancelled),
            "checkpoint {stop}"
        );
    }
    Ok(())
}
