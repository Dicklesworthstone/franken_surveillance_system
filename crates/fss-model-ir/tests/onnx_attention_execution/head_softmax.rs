#![forbid(unsafe_code)]
//! Explicit full-class Softmax precedes sparse foreground selection. Both actual
//! native executors and real graph/weight artifacts preserve that distinction.

use super::*;
use fss_model_ir::{OnnxHeadLayout, OnnxSplitHeadAssembly, assemble_onnx_softmax_split_head};

#[path = "../../../../tests/fixtures/model/onnx_softmax_split.rs"]
mod fixture;

fn profile(
    boxes: OnnxHeadLayout,
    scores: OnnxHeadLayout,
    classes: &[usize],
) -> OnnxSplitHeadAssembly {
    OnnxSplitHeadAssembly {
        boxes_output: "boxes".into(),
        boxes_layout: boxes,
        scores_output: "logits".into(),
        scores_layout: scores,
        class_indices: classes.to_vec(),
    }
}

fn dimensions(rows: usize, fields: usize, layout: OnnxHeadLayout) -> Vec<usize> {
    match layout {
        OnnxHeadLayout::Rows => vec![1, rows, fields],
        OnnxHeadLayout::Channels => vec![1, fields, rows],
    }
}

fn layout_values(rows: &[Vec<f32>], layout: OnnxHeadLayout) -> Vec<f32> {
    match layout {
        OnnxHeadLayout::Rows => rows.iter().flatten().copied().collect(),
        OnnxHeadLayout::Channels => (0..rows[0].len())
            .flat_map(|field| rows.iter().map(move |row| row[field]))
            .collect(),
    }
}

fn source(boxes: &[usize], scores: &[usize], collision: Option<&str>) -> Vec<u8> {
    let mut graph = [
        node("Identity", &["box_input"], &["boxes"], &[]),
        node("Identity", &["score_input"], &["logits"], &[]),
        bytes(11, &info("box_input", boxes, 1)),
        bytes(11, &info("score_input", scores, 1)),
        bytes(12, &info("logits", scores, 1)),
        bytes(12, &info("boxes", boxes, 1)),
    ]
    .concat();
    if let Some(name) = collision {
        graph.extend(node("Identity", &["box_input"], &[name], &[]));
        graph.extend(bytes(12, &info(name, boxes, 1)));
    }
    model(&graph)
}

fn adapted<'a>(
    source: &'a [u8],
    profile: &OnnxSplitHeadAssembly,
    output: &str,
    limits: OnnxLimits,
) -> Test<ImportedOnnx<'a>> {
    Ok(assemble_onnx_softmax_split_head(
        import(source)?,
        profile,
        output,
        limits,
        &|| false,
    )?)
}

fn roundtrip(imported: &ImportedOnnx<'_>, input: &[(&str, Tensor)]) -> Test<Outputs> {
    let before = execute(imported.graph(), imported.parameters().clone(), input)?;
    let first = export(imported)?;
    let second = export(imported)?;
    assert_eq!(first.source(), imported.source());
    assert_eq!(first.source_digest(), imported.source_digest());
    assert_eq!(first.graph_bytes(), second.graph_bytes());
    assert_eq!(first.weights_bytes(), second.weights_bytes());
    let graph = decode_canonical_model_ir(first.graph_bytes(), first.graph_digest())?;
    assert_eq!(encode_canonical_model_ir(&graph)?, first.graph_bytes());
    assert_eq!(graph.version(), imported.graph().version());
    let loaded = reloaded(&first)?;
    assert_eq!(loaded.len(), imported.parameters().len());
    for (name, tensor) in imported.parameters() {
        assert_eq!(
            bits(&loaded[name].to_vec::<f32>()?),
            bits(&tensor.to_vec::<f32>()?)
        );
    }
    let after = execute(&graph, loaded, input)?;
    assert_eq!(before.len(), after.len());
    for (name, values) in before {
        assert_eq!(bits(&after[&name]), bits(&values), "reloaded {name}");
    }
    Ok(after)
}

fn softmax_oracle(logits: &[f32]) -> Vec<f64> {
    let maximum = logits
        .iter()
        .map(|&value| f64::from(value))
        .fold(f64::NEG_INFINITY, f64::max);
    let exponentials = logits
        .iter()
        .map(|&value| (f64::from(value) - maximum).exp())
        .collect::<Vec<_>>();
    let total: f64 = exponentials.iter().sum();
    exponentials
        .into_iter()
        .map(|value| value / total)
        .collect()
}

fn assert_rows(actual: &[f32], boxes: &[Vec<f32>], logits: &[Vec<f32>], classes: &[usize]) {
    let fields = 4 + classes.len();
    assert_eq!(actual.len(), boxes.len() * fields);
    for (index, (boxes, logits)) in boxes.iter().zip(logits).enumerate() {
        let row = &actual[index * fields..(index + 1) * fields];
        assert_eq!(bits(&row[..4]), bits(boxes));
        let probabilities = softmax_oracle(logits);
        for (offset, &class) in classes.iter().enumerate() {
            let expected = probabilities[class];
            assert!(row[4 + offset].is_finite());
            assert!(
                (f64::from(row[4 + offset]) - expected).abs() <= 2e-6,
                "row {index} class {class}: {} vs {expected}",
                row[4 + offset]
            );
        }
    }
}

#[test]
fn omitted_background_keeps_its_mass_before_sparse_permuted_selection_in_every_layout() -> Test {
    let boxes = vec![
        vec![-0.0, f32::from_bits(1), 3.0, 4.0],
        vec![5.0, 6.0, 7.0, 8.0],
        vec![-1.0, -2.0, f32::MAX, f32::MIN],
    ];
    let logits = vec![
        vec![1.0, 0.0, -1.0, 12.0, 2.0, -2.0],
        vec![-4.0, 0.0, -1.0, -3.0, 7.0, 2.0],
        vec![0.0, 3.0, 1.0, -2.0, 2.0, 4.0],
    ];
    for boxes_layout in [OnnxHeadLayout::Rows, OnnxHeadLayout::Channels] {
        for scores_layout in [OnnxHeadLayout::Rows, OnnxHeadLayout::Channels] {
            let box_dims = dimensions(3, 4, boxes_layout);
            let score_dims = dimensions(3, 6, scores_layout);
            let source = source(&box_dims, &score_dims, None);
            for selected in [vec![4, 0, 2], vec![5, 3, 1], (0..6).collect()] {
                let profile = profile(boxes_layout, scores_layout, &selected);
                let converted = adapted(&source, &profile, "detections", OnnxLimits::default())?;
                let box_values = layout_values(&boxes, boxes_layout);
                let logit_values = layout_values(&logits, scores_layout);
                let result = roundtrip(
                    &converted,
                    &[
                        ("box_input", data(&box_dims, &box_values)?),
                        ("score_input", data(&score_dims, &logit_values)?),
                    ],
                )?;
                assert_eq!(bits(&result["boxes"]), bits(&box_values));
                assert_eq!(bits(&result["logits"]), bits(&logit_values));
                assert_rows(&result["detections"], &boxes, &logits, &selected);
                assert_eq!(
                    converted
                        .graph()
                        .outputs()
                        .iter()
                        .map(|port| port.name())
                        .collect::<Vec<_>>(),
                    ["logits", "boxes", "detections"]
                );
                if selected == [4, 0, 2] {
                    assert!(
                        result["detections"][4..7]
                            .iter()
                            .all(|&probability| probability < 0.001)
                    );
                    // Normalizing only selected classes would invent a >0.5 foreground.
                    assert!(softmax_oracle(&[2.0, 1.0, -1.0])[0] > 0.5);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn extreme_finite_logits_ties_and_single_class_follow_the_existing_stable_softmax() -> Test {
    let logits = vec![
        vec![f32::MAX, f32::MIN, 0.0],
        vec![f32::MIN, f32::MAX, f32::MAX],
        vec![1000.0, -1000.0, -1000.0],
        vec![-f32::MAX, -f32::MAX, -f32::MAX],
    ];
    let boxes = vec![vec![0.0, 0.0, 1.0, 1.0]; logits.len()];
    for layout in [OnnxHeadLayout::Rows, OnnxHeadLayout::Channels] {
        let score_dims = dimensions(4, 3, layout);
        let source = source(&[1, 4, 4], &score_dims, None);
        let converted = adapted(
            &source,
            &profile(OnnxHeadLayout::Rows, layout, &[2, 0, 1]),
            "detections",
            OnnxLimits::default(),
        )?;
        let result = roundtrip(
            &converted,
            &[
                (
                    "box_input",
                    data(&[1, 4, 4], &layout_values(&boxes, OnnxHeadLayout::Rows))?,
                ),
                (
                    "score_input",
                    data(&score_dims, &layout_values(&logits, layout))?,
                ),
            ],
        )?;
        assert_rows(&result["detections"], &boxes, &logits, &[2, 0, 1]);
        assert_eq!(&result["detections"][4..7], &[0.0, 1.0, 0.0]);
        assert_eq!(&result["detections"][11..14], &[0.5, 0.0, 0.5]);
    }
    let source = source(&[1, 1, 4], &[1, 1, 1], None);
    let converted = adapted(
        &source,
        &profile(OnnxHeadLayout::Rows, OnnxHeadLayout::Rows, &[0]),
        "detections",
        OnnxLimits::default(),
    )?;
    let result = roundtrip(
        &converted,
        &[
            ("box_input", data(&[1, 1, 4], &[-0.0, 0.0, 1.0, 1.0])?),
            ("score_input", data(&[1, 1, 1], &[f32::MIN])?),
        ],
    )?;
    assert_eq!(
        bits(&result["detections"]),
        bits(&[-0.0, 0.0, 1.0, 1.0, 1.0])
    );
    Ok(())
}

#[test]
fn rgb_dependent_source_preserves_v2_parameters_original_outputs_and_complete_probabilities() -> Test
{
    let source = fixture::model();
    let original = import(&source)?;
    let profile = profile(
        OnnxHeadLayout::Rows,
        OnnxHeadLayout::Channels,
        &fixture::CLASS_INDICES,
    );
    let converted = adapted(&source, &profile, fixture::OUTPUT, OnnxLimits::default())?;
    assert_eq!(converted.source(), source);
    assert!(std::ptr::eq(converted.source().as_ptr(), source.as_ptr()));
    assert_eq!(converted.source_digest(), original.source_digest());
    assert_eq!(converted.runtime_inputs(), &[fixture::INPUT]);
    assert_eq!(
        converted.graph().version(),
        fss_model_ir::ModelIrVersion::V2
    );
    assert_eq!(converted.graph().version(), original.graph().version());
    assert_eq!(
        converted.graph().generation(),
        original.graph().generation()
    );
    assert_eq!(
        export(&converted)?.weights_bytes(),
        export(&original)?.weights_bytes()
    );
    assert_eq!(
        converted
            .graph()
            .outputs()
            .iter()
            .map(|port| port.name())
            .collect::<Vec<_>>(),
        [
            fixture::SCORES,
            "embedding",
            fixture::BOXES,
            fixture::OUTPUT
        ]
    );
    assert_eq!(
        converted
            .graph()
            .find_output(fixture::OUTPUT)
            .ok_or("detections")?
            .shape()
            .dims(),
        [1, fixture::ROWS, 4 + fixture::CLASS_INDICES.len()]
    );
    let mut outcomes = Vec::new();
    for values in [vec![0.0; 12], fixture::sample_input()] {
        let input = [(
            fixture::INPUT,
            data(&[1, 3, fixture::TARGET[0], fixture::TARGET[1]], &values)?,
        )];
        let before = execute(original.graph(), original.parameters().clone(), &input)?;
        let after = roundtrip(&converted, &input)?;
        for (name, values) in before {
            assert_eq!(bits(&after[&name]), bits(&values), "original {name}");
        }
        let oracle = fixture::oracle(&values);
        for (index, (&actual, &expected)) in after[fixture::OUTPUT].iter().zip(&oracle).enumerate()
        {
            if index % 6 < 4 {
                assert_eq!(actual.to_bits(), expected.to_bits());
            } else {
                assert!((actual - expected).abs() < 2e-6);
            }
        }
        assert!(after[fixture::OUTPUT][4] < 0.005);
        assert!(after[fixture::OUTPUT][5] < 0.005);
        assert!(after[fixture::OUTPUT][10] > 0.99);
        let raw = &after[fixture::SCORES];
        assert!(
            softmax_oracle(&[raw[4], raw[0]])[0] > 0.5,
            "dropping background before normalization would falsely admit row zero"
        );
        outcomes.push(after[fixture::OUTPUT].clone());
    }
    assert_ne!(bits(&outcomes[0]), bits(&outcomes[1]));
    // The 24-byte INT64 Reshape control is consumed but remains quota-charged;
    // full-class Softmax and selection introduce no new parameter bytes.
    assert!(
        assemble_onnx_softmax_split_head(
            import(&source)?,
            &profile,
            fixture::OUTPUT,
            OnnxLimits {
                parameter_bytes: 368,
                ..OnnxLimits::default()
            },
            &|| false
        )
        .is_ok()
    );
    assert_eq!(
        assemble_onnx_softmax_split_head(
            import(&source)?,
            &profile,
            fixture::OUTPUT,
            OnnxLimits {
                parameter_bytes: 367,
                ..OnnxLimits::default()
            },
            &|| false
        )
        .err(),
        Some(OnnxError::Limit)
    );
    Ok(())
}

#[test]
fn maximum_class_axis_is_normalized_before_omitting_one_background_and_reordering_foreground()
-> Test {
    let source = source(&[1, 1, 4], &[1, 257, 1], None);
    let classes = (0..256).rev().collect::<Vec<_>>();
    let mut logits = vec![0.0_f32; 257];
    logits[256] = 16.0;
    let converted = adapted(
        &source,
        &profile(OnnxHeadLayout::Rows, OnnxHeadLayout::Channels, &classes),
        "detections",
        OnnxLimits::default(),
    )?;
    let result = roundtrip(
        &converted,
        &[
            ("box_input", data(&[1, 1, 4], &[0.0, 0.0, 1.0, 1.0])?),
            ("score_input", data(&[1, 257, 1], &logits)?),
        ],
    )?;
    assert_rows(
        &result["detections"],
        &[vec![0.0, 0.0, 1.0, 1.0]],
        &[logits],
        &classes,
    );
    assert!(result["detections"][4..].iter().sum::<f32>() < 0.001);
    Ok(())
}

#[test]
fn source_and_final_helper_like_names_and_repeated_assembly_cannot_capture_each_other() -> Test {
    let recipe = profile(OnnxHeadLayout::Channels, OnnxHeadLayout::Channels, &[2, 0]);
    for collision in [
        "fss:split-head-softmax:scores",
        "fss:split-head:scores",
        "fss:split-head:classes-0",
    ] {
        let source = source(&[1, 4, 2], &[1, 3, 2], Some(collision));
        let output = if collision == "fss:split-head-softmax:scores" {
            "fss:split-head:classes-0"
        } else {
            "fss:split-head-softmax:scores"
        };
        let first = adapted(&source, &recipe, output, OnnxLimits::default())?;
        let twice = assemble_onnx_softmax_split_head(
            first,
            &recipe,
            "second",
            OnnxLimits::default(),
            &|| false,
        )?;
        let boxes = vec![vec![-0.0, 0.0, 1.0, 1.0], vec![1.0, 1.0, 2.0, 2.0]];
        let logits = vec![vec![0.5, 8.0, 1.5], vec![-1.0, -2.0, 4.0]];
        let raw_boxes = layout_values(&boxes, OnnxHeadLayout::Channels);
        let result = roundtrip(
            &twice,
            &[
                ("box_input", data(&[1, 4, 2], &raw_boxes)?),
                (
                    "score_input",
                    data(
                        &[1, 3, 2],
                        &layout_values(&logits, OnnxHeadLayout::Channels),
                    )?,
                ),
            ],
        )?;
        assert_rows(&result[output], &boxes, &logits, &recipe.class_indices);
        assert_eq!(bits(&result[output]), bits(&result["second"]));
        assert_eq!(bits(&result[collision]), bits(&raw_boxes));
        assert_eq!(
            twice
                .graph()
                .outputs()
                .iter()
                .map(|port| port.name())
                .collect::<Vec<_>>(),
            ["logits", "boxes", collision, output, "second"]
        );
    }
    Ok(())
}

#[test]
fn source_roles_shapes_class_mapping_and_output_collisions_refuse_before_expansion() -> Test {
    let recipe = profile(OnnxHeadLayout::Rows, OnnxHeadLayout::Rows, &[2, 0]);
    for (boxes, scores, expected) in [
        (vec![1, 2, 5], vec![1, 2, 3], OnnxError::Graph),
        (vec![1, 2, 4], vec![1, 3, 3], OnnxError::Graph),
        (vec![1, 2, 4], vec![2, 2, 3], OnnxError::Graph),
        (vec![1, 2, 4], vec![2, 3], OnnxError::Graph),
        (vec![1, 2, 4], vec![1, 2, 258], OnnxError::Unsupported),
        (vec![1, 32769, 4], vec![1, 32769, 3], OnnxError::Limit),
    ] {
        let source = source(&boxes, &scores, None);
        assert_eq!(
            assemble_onnx_softmax_split_head(
                import(&source)?,
                &recipe,
                "detections",
                OnnxLimits::default(),
                &|| false
            )
            .err(),
            Some(expected)
        );
    }
    let source = source(&[1, 2, 4], &[1, 2, 3], None);
    for role in ["missing", "score_input", "box_input", "boxes"] {
        let mut wrong = recipe.clone();
        wrong.scores_output = role.into();
        assert_eq!(
            assemble_onnx_softmax_split_head(
                import(&source)?,
                &wrong,
                "detections",
                OnnxLimits::default(),
                &|| false
            )
            .err(),
            Some(OnnxError::Graph)
        );
    }
    for selected in [vec![], vec![0, 0], vec![3], vec![usize::MAX], vec![0; 257]] {
        let mut wrong = recipe.clone();
        wrong.class_indices = selected;
        assert!(
            assemble_onnx_softmax_split_head(
                import(&source)?,
                &wrong,
                "detections",
                OnnxLimits::default(),
                &|| false
            )
            .is_err()
        );
    }
    for output in [
        "",
        " ",
        "bad\nname",
        "boxes",
        "logits",
        "box_input",
        "score_input",
    ] {
        assert_eq!(
            assemble_onnx_softmax_split_head(
                import(&source)?,
                &recipe,
                output,
                OnnxLimits::default(),
                &|| false
            )
            .err(),
            Some(OnnxError::Graph)
        );
    }
    let source = fixture::model();
    let recipe = profile(OnnxHeadLayout::Rows, OnnxHeadLayout::Channels, &[2, 0]);
    assert_eq!(
        assemble_onnx_softmax_split_head(
            import(&source)?,
            &recipe,
            "score_shape",
            OnnxLimits::default(),
            &|| false
        )
        .err(),
        Some(OnnxError::Graph)
    );
    Ok(())
}

#[test]
fn complete_softmax_and_selection_share_exact_cumulative_quotas() -> Test {
    let source = source(&[1, 4, 3], &[1, 6, 3], None);
    let recipe = profile(
        OnnxHeadLayout::Channels,
        OnnxHeadLayout::Channels,
        &[4, 0, 2],
    );
    let original = import(&source)?;
    let full = adapted(&source, &recipe, "detections", OnnxLimits::default())?;
    assert_eq!(full.graph().node_count(), original.graph().node_count() + 7);
    assert!(full.parameters().is_empty());
    let exact = OnnxLimits {
        source_bytes: source.len(),
        nodes: full.graph().node_count(),
        tensors: full.graph().inputs().len() + full.graph().node_count(),
        parameter_bytes: 0,
        tensor_bytes: 3 * 7 * 4,
        work_units: full.work_units(),
    };
    assert!(full.work_units() > original.work_units());
    let repeated = adapted(&source, &recipe, "detections", exact)?;
    assert_eq!(
        encode_canonical_model_ir(full.graph())?,
        encode_canonical_model_ir(repeated.graph())?
    );
    for limits in [
        OnnxLimits {
            source_bytes: exact.source_bytes - 1,
            ..exact
        },
        OnnxLimits {
            nodes: exact.nodes - 1,
            ..exact
        },
        OnnxLimits {
            tensors: exact.tensors - 1,
            ..exact
        },
        OnnxLimits {
            tensor_bytes: exact.tensor_bytes - 1,
            ..exact
        },
    ] {
        assert_eq!(
            assemble_onnx_softmax_split_head(
                import(&source)?,
                &recipe,
                "detections",
                limits,
                &|| false
            )
            .err(),
            Some(OnnxError::Limit)
        );
    }
    assert_eq!(
        assemble_onnx_softmax_split_head(
            import(&source)?,
            &recipe,
            "detections",
            OnnxLimits {
                work_units: exact.work_units - 1,
                ..exact
            },
            &|| false
        )
        .err(),
        Some(OnnxError::WorkBudget)
    );
    // A very wide raw class axis still needs its full tensor allowance, even if
    // only one foreground score survives selection into a much smaller head.
    let source = self::source(&[1, 1, 4], &[1, 1, 257], None);
    let recipe = profile(OnnxHeadLayout::Rows, OnnxHeadLayout::Rows, &[0]);
    assert_eq!(
        assemble_onnx_softmax_split_head(
            import(&source)?,
            &recipe,
            "detections",
            OnnxLimits {
                tensor_bytes: 257 * 4 - 1,
                ..OnnxLimits::default()
            },
            &|| false
        )
        .err(),
        Some(OnnxError::Limit)
    );
    Ok(())
}

#[test]
fn cancellation_at_every_normalize_assemble_and_final_visibility_checkpoint_refuses() -> Test {
    let source = source(&[1, 2, 4], &[1, 3, 2], None);
    let recipe = profile(OnnxHeadLayout::Rows, OnnxHeadLayout::Channels, &[2, 0]);
    let calls = Cell::new(0_usize);
    let full = assemble_onnx_softmax_split_head(
        import(&source)?,
        &recipe,
        "detections",
        OnnxLimits::default(),
        &|| {
            calls.set(calls.get() + 1);
            false
        },
    )?;
    let count = calls.get();
    assert!(count > 20);
    for deadline in 1..=count {
        calls.set(0);
        assert_eq!(
            assemble_onnx_softmax_split_head(
                import(&source)?,
                &recipe,
                "detections",
                OnnxLimits::default(),
                &|| {
                    calls.set(calls.get() + 1);
                    calls.get() == deadline
                }
            )
            .err(),
            Some(OnnxError::Cancelled),
            "checkpoint {deadline}/{count}"
        );
    }
    let repeated = adapted(&source, &recipe, "detections", OnnxLimits::default())?;
    assert_eq!(
        encode_canonical_model_ir(full.graph())?,
        encode_canonical_model_ir(repeated.graph())?
    );
    Ok(())
}
