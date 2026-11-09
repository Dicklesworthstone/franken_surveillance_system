#![forbid(unsafe_code)]
//! Explicit named detector heads through the unchanged native executors and
//! canonical-graph/Safetensors loaders. Fixtures are untrained numerical data.
use super::*;
use fss_model_ir::{OnnxHeadLayout, OnnxSplitHeadAssembly, assemble_onnx_split_head};

fn recipe(
    boxes_layout: OnnxHeadLayout,
    scores_layout: OnnxHeadLayout,
    class_indices: &[usize],
) -> OnnxSplitHeadAssembly {
    OnnxSplitHeadAssembly {
        boxes_output: "boxes".into(),
        boxes_layout,
        scores_output: "scores".into(),
        scores_layout,
        class_indices: class_indices.to_vec(),
    }
}

fn dimensions(rows: usize, fields: usize, layout: OnnxHeadLayout) -> Vec<usize> {
    match layout {
        OnnxHeadLayout::Rows => vec![1, rows, fields],
        OnnxHeadLayout::Channels => vec![1, fields, rows],
    }
}

// Literal row coordinates, independent of the production Transpose/Slice/Concat
// implementations, convert the test input into either declared source layout.
fn layout_values(rows: &[&[f32]], layout: OnnxHeadLayout) -> Vec<f32> {
    match layout {
        OnnxHeadLayout::Rows => rows.iter().flat_map(|row| row.iter().copied()).collect(),
        OnnxHeadLayout::Channels => (0..rows[0].len())
            .flat_map(|field| rows.iter().map(move |row| row[field]))
            .collect(),
    }
}

fn head_source(boxes: &[usize], scores: &[usize]) -> Vec<u8> {
    model(
        &[
            node("Identity", &["box_input"], &["boxes"], &[]),
            node("Identity", &["score_input"], &["scores"], &[]),
            bytes(11, &info("box_input", boxes, 1)),
            bytes(11, &info("score_input", scores, 1)),
            bytes(12, &info("boxes", boxes, 1)),
            bytes(12, &info("scores", scores, 1)),
        ]
        .concat(),
    )
}

fn assemble<'a>(
    source: &'a [u8],
    recipe: &OnnxSplitHeadAssembly,
    output: &str,
    limits: OnnxLimits,
) -> Test<ImportedOnnx<'a>> {
    Ok(assemble_onnx_split_head(
        import(source)?,
        recipe,
        output,
        limits,
        &|| false,
    )?)
}

fn assembled_roundtrip(
    imported: &ImportedOnnx<'_>,
    input: &[(&str, Tensor)],
) -> Test<Outputs> {
    let before = execute(imported.graph(), imported.parameters().clone(), input)?;
    let artifacts = export(imported)?;
    let repeat = export(imported)?;
    assert_eq!(artifacts.source(), imported.source());
    assert_eq!(artifacts.source_digest(), ContentDigest::sha256(imported.source()));
    assert_eq!(artifacts.graph_bytes(), repeat.graph_bytes());
    assert_eq!(artifacts.weights_bytes(), repeat.weights_bytes());
    let graph = decode_canonical_model_ir(artifacts.graph_bytes(), artifacts.graph_digest())?;
    assert_eq!(graph.version(), imported.graph().version());
    assert_eq!(graph.generation(), imported.graph().generation());
    assert_eq!(encode_canonical_model_ir(&graph)?, artifacts.graph_bytes());
    let weights = reloaded(&artifacts)?;
    assert_eq!(weights.len(), imported.parameters().len());
    for (name, parameter) in imported.parameters() {
        assert_eq!(bits(&weights[name].to_vec::<f32>()?), bits(&parameter.to_vec::<f32>()?));
    }
    let after = execute(&graph, weights, input)?;
    for (name, expected) in &before {
        assert_eq!(bits(&after[name]), bits(expected), "reloaded {name}");
    }
    Ok(after)
}

#[test]
fn split_heads_bind_names_even_with_equal_widths_and_keep_exact_bits() -> Test {
    let boxes: [&[f32]; 2] = [
        &[-0., f32::from_bits(1), 12., 13.],
        &[20., 21., 22., 23.],
    ];
    let scores: [&[f32]; 2] = [
        &[0., -2., f32::MAX, 4.],
        &[-f32::from_bits(1), 5., f32::MIN, -0.],
    ];
    let expected = [
        -0., f32::from_bits(1), 12., 13., 4., 0., f32::MAX,
        20., 21., 22., 23., -0., -f32::from_bits(1), f32::MIN,
    ];
    for boxes_layout in [OnnxHeadLayout::Rows, OnnxHeadLayout::Channels] {
        for scores_layout in [OnnxHeadLayout::Rows, OnnxHeadLayout::Channels] {
            let box_dims = dimensions(2, 4, boxes_layout);
            let score_dims = dimensions(2, 4, scores_layout);
            let source = head_source(&box_dims, &score_dims);
            let original = import(&source)?;
            let recipe = recipe(boxes_layout, scores_layout, &[3, 0, 2]);
            let imported = assemble(&source, &recipe, "packed", OnnxLimits::default())?;
            assert_eq!(imported.graph().version(), original.graph().version());
            assert_eq!(imported.runtime_inputs(), original.runtime_inputs());
            assert!(imported.parameters().is_empty());
            assert_eq!(imported.graph().outputs().len(), 3);
            assert_eq!(
                imported.graph().find_output("packed").ok_or("packed output")?.shape().dims(),
                [1, 2, 7]
            );
            let box_values = layout_values(&boxes, boxes_layout);
            let score_values = layout_values(&scores, scores_layout);
            let output = assembled_roundtrip(
                &imported,
                &[
                    ("box_input", data(&box_dims, &box_values)?),
                    ("score_input", data(&score_dims, &score_values)?),
                ],
            )?;
            assert_eq!(bits(&output["boxes"]), bits(&box_values));
            assert_eq!(bits(&output["scores"]), bits(&score_values));
            assert_eq!(bits(&output["packed"]), bits(&expected));
        }
    }
    Ok(())
}

#[test]
fn split_heads_run_shared_rgb_feature_branches_and_preserve_v2_and_weights() -> Test {
    let source = model(
        &[
            node("Flatten", &["image"], &["features"], &int_attr("axis", 1)),
            node("MatMul", &["features", "box_weights"], &["box_flat"], &[]),
            node("Reshape", &["box_flat", "box_shape"], &["boxes"], &[]),
            node("MatMul", &["features", "score_weights"], &["score_flat"], &[]),
            node("Reshape", &["score_flat", "score_shape"], &["scores"], &[]),
            node("Sqrt", &["features"], &["auxiliary"], &[]),
            weight(
                "box_weights",
                &[3, 8],
                &[
                    1., 0., 0., 1., 1., 2., 0., 0.,
                    0., 1., 0., 0., 0., 0., 1., 0.,
                    0., 0., 1., 0., 0., 0., 0., 1.,
                ],
            ),
            weight(
                "score_weights",
                &[3, 6],
                &[
                    1., 0., 1., 1., 0., -1.,
                    0., 1., 0., 0., 1., 0.,
                    0., 0., -1., 0., 0., 1.,
                ],
            ),
            int_weight("box_shape", &[3], &[1, 2, 4]),
            int_weight("score_shape", &[3], &[1, 2, 3]),
            bytes(11, &info("image", &[1, 3, 1, 1], 1)),
            bytes(12, &info("boxes", &[1, 2, 4], 1)),
            bytes(12, &info("scores", &[1, 2, 3], 1)),
            bytes(12, &info("auxiliary", &[1, 3], 1)),
        ]
        .concat(),
    );
    let original = import(&source)?;
    let original_weights = export(&original)?.weights_bytes().to_vec();
    let recipe = recipe(OnnxHeadLayout::Rows, OnnxHeadLayout::Rows, &[2, 0]);
    let imported = assemble(&source, &recipe, "detections", OnnxLimits::default())?;
    assert_eq!(imported.graph().version(), fss_model_ir::ModelIrVersion::V2);
    assert_eq!(imported.runtime_inputs(), &["image"]);
    assert_eq!(export(&imported)?.weights_bytes(), original_weights);
    assert_eq!(imported.source_digest(), original.source_digest());
    let output = assembled_roundtrip(
        &imported,
        &[("image", data(&[1, 3, 1, 1], &[1., 4., 9.])?)],
    )?;
    assert_eq!(bits(&output["boxes"]), bits(&[1., 4., 9., 1., 1., 2., 4., 9.]));
    assert_eq!(bits(&output["scores"]), bits(&[1., 4., -8., 1., 4., 8.]));
    assert_eq!(bits(&output["auxiliary"]), bits(&[1., 2., 3.]));
    assert_eq!(
        bits(&output["detections"]),
        bits(&[1., 4., 9., 1., -8., 1., 1., 2., 4., 9., 8., 1.])
    );
    Ok(())
}

#[test]
fn split_heads_keep_explicit_sparse_background_and_label_order() -> Test {
    let source = head_source(&[1, 1, 4], &[1, 1, 257]);
    let values = (0..257).map(|index| index as f32 - 128.).collect::<Vec<_>>();
    let mappings = [
        (0..256).collect::<Vec<_>>(), // Explicit last-slot omission.
        (1..257).collect::<Vec<_>>(), // Explicit first-slot omission.
        (0..127).chain(128..257).collect::<Vec<_>>(), // Explicit interior omission.
        vec![90, 1, 3, 0], // Sparse foreground slots, in the requested label order.
        (1..257).rev().collect::<Vec<_>>(),
    ];
    for mapping in mappings {
        let recipe = recipe(OnnxHeadLayout::Rows, OnnxHeadLayout::Rows, &mapping);
        let imported = assemble(&source, &recipe, "packed", OnnxLimits::default())?;
        let output = assembled_roundtrip(
            &imported,
            &[
                ("box_input", data(&[1, 1, 4], &[1., 2., 3., 4.])?),
                ("score_input", data(&[1, 1, 257], &values)?),
            ],
        )?;
        let mut expected = vec![1., 2., 3., 4.];
        expected.extend(mapping.iter().map(|&index| values[index]));
        assert_eq!(bits(&output["packed"]), bits(&expected));
        assert_eq!(bits(&output["scores"]), bits(&values));
    }
    Ok(())
}

#[test]
fn split_heads_compact_contiguous_selections_independently_of_row_count() -> Test {
    for rows in [1, 4096] {
        let source = head_source(&[1, rows, 4], &[1, rows, 4]);
        for (indices, helper_count) in [
            (vec![0, 1, 2, 3], 1),
            (vec![1, 2, 3], 2),
            (vec![2, 3, 0, 1], 3),
        ] {
            let recipe = recipe(OnnxHeadLayout::Rows, OnnxHeadLayout::Rows, &indices);
            let imported = assemble(&source, &recipe, "packed", OnnxLimits::default())?;
            assert_eq!(imported.graph().node_count(), 2 + helper_count);
            assert!(imported.parameters().is_empty());
        }
    }
    // The full-width path must still retain signed zeros rather than performing
    // an arithmetic identity or sigmoid while avoiding unnecessary slices.
    let source = head_source(&[1, 1, 4], &[1, 1, 1]);
    let recipe = recipe(OnnxHeadLayout::Rows, OnnxHeadLayout::Rows, &[0]);
    let imported = assemble(&source, &recipe, "packed", OnnxLimits::default())?;
    let output = assembled_roundtrip(
        &imported,
        &[
            ("box_input", data(&[1, 1, 4], &[-0., 1., 2., 3.])?),
            ("score_input", data(&[1, 1, 1], &[-0.])?),
        ],
    )?;
    assert_eq!(bits(&output["packed"]), bits(&[-0., 1., 2., 3., -0.]));
    Ok(())
}

fn assembly_error(
    source: &[u8],
    recipe: &OnnxSplitHeadAssembly,
    output: &str,
    limits: OnnxLimits,
) -> Test<Option<OnnxError>> {
    Ok(assemble_onnx_split_head(
        import(source)?,
        recipe,
        output,
        limits,
        &|| false,
    )
    .err())
}

#[test]
fn split_heads_refuse_ambiguous_names_and_invalid_class_mappings() -> Test {
    let source = head_source(&[1, 2, 4], &[1, 2, 3]);
    let valid = recipe(OnnxHeadLayout::Rows, OnnxHeadLayout::Rows, &[0, 1]);
    for name in ["", " ", "boxes", "scores", "box_input", "\n"] {
        assert_eq!(
            assembly_error(&source, &valid, name, OnnxLimits::default())?,
            Some(OnnxError::Graph)
        );
    }
    assert_eq!(
        assembly_error(&source, &valid, &"x".repeat(513), OnnxLimits::default())?,
        Some(OnnxError::Graph)
    );
    for (boxes, scores) in [
        ("boxes", "boxes"),
        ("score_input", "scores"),
        ("missing", "scores"),
        ("boxes", "missing"),
        (" boxes", "scores"),
        ("boxes", "scores "),
    ] {
        let mut invalid = valid.clone();
        invalid.boxes_output = boxes.into();
        invalid.scores_output = scores.into();
        assert_eq!(
            assembly_error(&source, &invalid, "packed", OnnxLimits::default())?,
            Some(OnnxError::Graph)
        );
    }
    for mapping in [vec![0, 0], vec![3], vec![usize::MAX]] {
        let mut invalid = valid.clone();
        invalid.class_indices = mapping;
        assert_eq!(
            assembly_error(&source, &invalid, "packed", OnnxLimits::default())?,
            Some(OnnxError::Graph)
        );
    }
    for mapping in [vec![], (0..257).collect::<Vec<_>>()] {
        let mut invalid = valid.clone();
        invalid.class_indices = mapping;
        assert_eq!(
            assembly_error(&source, &invalid, "packed", OnnxLimits::default())?,
            Some(OnnxError::Unsupported)
        );
    }
    Ok(())
}

#[test]
fn split_heads_refuse_mismatched_batches_rows_ranks_and_source_widths() -> Test {
    let recipe = recipe(OnnxHeadLayout::Rows, OnnxHeadLayout::Rows, &[0]);
    for (box_dims, score_dims, error) in [
        (vec![2, 2, 4], vec![2, 2, 3], OnnxError::Graph),
        (vec![1, 2, 4], vec![1, 3, 3], OnnxError::Graph),
        (vec![1, 2, 5], vec![1, 2, 3], OnnxError::Graph),
        (vec![2, 4], vec![1, 2, 3], OnnxError::Graph),
        (vec![1, 2, 4], vec![1, 1, 2, 3], OnnxError::Graph),
        (vec![1, 2, 4], vec![1, 2, 258], OnnxError::Unsupported),
        (vec![1, 32769, 4], vec![1, 32769, 1], OnnxError::Limit),
    ] {
        let source = head_source(&box_dims, &score_dims);
        assert_eq!(
            assembly_error(&source, &recipe, "packed", OnnxLimits::default())?,
            Some(error)
        );
    }
    let source = head_source(&[1, 2, 4], &[1, 2, 3]);
    let wrong_layout = OnnxSplitHeadAssembly {
        boxes_layout: OnnxHeadLayout::Channels,
        ..recipe
    };
    assert_eq!(
        assembly_error(&source, &wrong_layout, "packed", OnnxLimits::default())?,
        Some(OnnxError::Graph)
    );
    Ok(())
}

fn controlled_head_source() -> Vec<u8> {
    model(
        &[
            node("Reshape", &["box_input", "shape"], &["boxes"], &[]),
            node("Identity", &["score_input"], &["scores"], &[]),
            int_weight("shape", &[3], &[1, 2, 4]),
            bytes(11, &info("box_input", &[1, 2, 4], 1)),
            bytes(11, &info("score_input", &[1, 2, 3], 1)),
            bytes(12, &info("boxes", &[1, 2, 4], 1)),
            bytes(12, &info("scores", &[1, 2, 3], 1)),
        ]
        .concat(),
    )
}

#[test]
fn split_heads_charge_original_controls_and_exact_expansion_limits() -> Test {
    let source = controlled_head_source();
    let recipe = recipe(OnnxHeadLayout::Rows, OnnxHeadLayout::Rows, &[2, 0]);
    let mut exact = OnnxLimits {
        source_bytes: source.len(),
        nodes: 5,
        tensors: 8,
        parameter_bytes: 24,
        tensor_bytes: 48,
        ..OnnxLimits::default()
    };
    let imported = assemble(&source, &recipe, "packed", exact)?;
    assert_eq!(imported.graph().node_count(), 5);
    assert!(imported.parameters().is_empty());
    exact.work_units = imported.work_units();
    assert!(assemble(&source, &recipe, "packed", exact).is_ok());
    for limits in [
        OnnxLimits { source_bytes: source.len() - 1, ..exact },
        OnnxLimits { nodes: 4, ..exact },
        OnnxLimits { tensors: 7, ..exact },
        OnnxLimits { parameter_bytes: 23, ..exact },
        OnnxLimits { tensor_bytes: 47, ..exact },
    ] {
        assert_eq!(
            assembly_error(&source, &recipe, "packed", limits)?,
            Some(OnnxError::Limit)
        );
    }
    assert_eq!(
        assembly_error(
            &source,
            &recipe,
            "packed",
            OnnxLimits { work_units: exact.work_units - 1, ..exact },
        )?,
        Some(OnnxError::WorkBudget)
    );
    // Tightening the ceiling also rechecks an original intermediate that is
    // larger than both original ports and the newly packed head.
    let expanded_source = model(
        &[
            node(
                "Concat",
                &["box_input", "box_input", "box_input", "box_input"],
                &["wide"],
                &int_attr("axis", 1),
            ),
            node("Slice", &["wide", "start", "end", "axis"], &["boxes"], &[]),
            node("Identity", &["score_input"], &["scores"], &[]),
            int_weight("start", &[1], &[0]),
            int_weight("end", &[1], &[2]),
            int_weight("axis", &[1], &[1]),
            bytes(11, &info("box_input", &[1, 2, 4], 1)),
            bytes(11, &info("score_input", &[1, 2, 3], 1)),
            bytes(12, &info("boxes", &[1, 2, 4], 1)),
            bytes(12, &info("scores", &[1, 2, 3], 1)),
        ]
        .concat(),
    );
    assert!(
        assemble(
            &expanded_source,
            &recipe,
            "packed",
            OnnxLimits { tensor_bytes: 128, ..OnnxLimits::default() },
        )
        .is_ok()
    );
    assert_eq!(
        assembly_error(
            &expanded_source,
            &recipe,
            "packed",
            OnnxLimits { tensor_bytes: 127, ..OnnxLimits::default() },
        )?,
        Some(OnnxError::Limit)
    );
    // Consumed shape controls are no longer executable inputs, but their names
    // and allocations cannot be reused or omitted from cumulative admission.
    assert_eq!(
        assembly_error(&source, &recipe, "shape", OnnxLimits::default())?,
        Some(OnnxError::Graph)
    );
    let original_work = import(&source)?.work_units();
    assert_eq!(
        assembly_error(
            &source,
            &recipe,
            "packed",
            OnnxLimits { work_units: original_work, ..exact },
        )?,
        Some(OnnxError::WorkBudget)
    );
    Ok(())
}

#[test]
fn split_heads_cancel_at_every_assembly_checkpoint_without_partial_result() -> Test {
    let source = head_source(&[1, 4, 2], &[1, 4, 2]);
    let recipe = recipe(OnnxHeadLayout::Channels, OnnxHeadLayout::Channels, &[3, 0, 2]);
    let calls = Cell::new(0);
    assemble_onnx_split_head(
        import(&source)?,
        &recipe,
        "packed",
        OnnxLimits::default(),
        &|| {
            calls.set(calls.get() + 1);
            false
        },
    )?;
    assert!(calls.get() > 10);
    for checkpoint in 1..=calls.get() {
        let observed = Cell::new(0);
        let result = assemble_onnx_split_head(
            import(&source)?,
            &recipe,
            "packed",
            OnnxLimits::default(),
            &|| {
                observed.set(observed.get() + 1);
                observed.get() == checkpoint
            },
        );
        assert_eq!(result.err(), Some(OnnxError::Cancelled));
        assert_eq!(observed.get(), checkpoint);
    }
    Ok(())
}

#[test]
fn split_heads_reserve_helpers_outputs_and_repeated_assembly_names() -> Test {
    let dims = [1, 4, 2];
    let source = model(
        &[
            node("Identity", &["box_input"], &["boxes"], &[]),
            node("Identity", &["score_input"], &["scores"], &[]),
            node("Identity", &["box_input"], &["fss:split-head:boxes"], &[]),
            node("Identity", &["score_input"], &["fss:split-head:scores"], &[]),
            node("Identity", &["score_input"], &["fss:split-head:classes-0"], &[]),
            bytes(11, &info("box_input", &dims, 1)),
            bytes(11, &info("score_input", &dims, 1)),
            bytes(12, &info("boxes", &dims, 1)),
            bytes(12, &info("scores", &dims, 1)),
            bytes(12, &info("fss:split-head:boxes", &dims, 1)),
            bytes(12, &info("fss:split-head:scores", &dims, 1)),
            bytes(12, &info("fss:split-head:classes-0", &dims, 1)),
        ]
        .concat(),
    );
    let recipe = recipe(OnnxHeadLayout::Channels, OnnxHeadLayout::Channels, &[2, 0]);
    let first = assemble(&source, &recipe, "onnx-split-head-0000", OnnxLimits::default())?;
    let imported = assemble_onnx_split_head(
        first,
        &recipe,
        "second",
        OnnxLimits::default(),
        &|| false,
    )?;
    assert_eq!(imported.graph().outputs().len(), 7);
    let output = assembled_roundtrip(
        &imported,
        &[
            ("box_input", data(&dims, &[1., 5., 2., 6., 3., 7., 4., 8.])?),
            ("score_input", data(&dims, &[9., 13., 10., 14., 11., 15., 12., 16.])?),
        ],
    )?;
    assert_eq!(
        bits(&output["second"]),
        bits(&[1., 2., 3., 4., 11., 9., 5., 6., 7., 8., 15., 13.])
    );
    assert_eq!(bits(&output["second"]), bits(&output["onnx-split-head-0000"]));
    assert_eq!(bits(&output["scores"]), bits(&output["fss:split-head:classes-0"]));
    assert_eq!(bits(&output["boxes"]), bits(&output["fss:split-head:boxes"]));
    Ok(())
}
