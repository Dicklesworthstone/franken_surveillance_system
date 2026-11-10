#![forbid(unsafe_code)]
//! Explicit multi-scale outputs run through both unchanged native executors and
//! real canonical/Safetensors artifacts. The RGB Conv fixture has an independent
//! image-coordinate oracle; exact layout tests use authored rectangular grids.

use super::*;
use fss_model_ir::{
    OnnxDflPyramidDecode, OnnxDflPyramidLayout, OnnxDflPyramidLevel, decode_onnx_dfl_pyramid,
};

#[path = "../../../../tests/fixtures/model/onnx_dfl_pyramid.rs"]
mod fixture;

fn profile() -> OnnxDflPyramidDecode {
    OnnxDflPyramidDecode {
        bins: fixture::BINS,
        levels: (0..3)
            .map(|index| OnnxDflPyramidLevel {
                output: fixture::LEVEL_OUTPUTS[index].into(),
                stride: fixture::LEVEL_STRIDES[index],
                layout: if fixture::LEVEL_NCHW[index] {
                    OnnxDflPyramidLayout::Nchw
                } else {
                    OnnxDflPyramidLayout::Nhwc
                },
            })
            .collect(),
    }
}

fn adapted<'a>(
    source: &'a [u8],
    profile: &OnnxDflPyramidDecode,
    output: &str,
    target: [usize; 2],
    scores: usize,
) -> Test<ImportedOnnx<'a>> {
    Ok(decode_onnx_dfl_pyramid(
        import(source)?,
        profile,
        output,
        target,
        scores,
        OnnxLimits::default(),
        &|| false,
    )?)
}

fn converted_roundtrip(imported: &ImportedOnnx<'_>, input: &[(&str, Tensor)]) -> Test<Outputs> {
    let before = execute(imported.graph(), imported.parameters().clone(), input)?;
    let first = export(imported)?;
    let second = export(imported)?;
    assert_eq!(first.graph_bytes(), second.graph_bytes());
    assert_eq!(first.weights_bytes(), second.weights_bytes());
    assert_eq!(first.source(), imported.source());
    assert_eq!(first.source_digest(), imported.source_digest());
    let graph = decode_canonical_model_ir(first.graph_bytes(), first.graph_digest())?;
    assert_eq!(encode_canonical_model_ir(&graph)?, first.graph_bytes());
    let loaded = reloaded(&first)?;
    for (name, tensor) in imported.parameters() {
        assert_eq!(
            bits(&loaded[name].to_vec::<f32>()?),
            bits(&tensor.to_vec::<f32>()?)
        );
    }
    let after = execute(&graph, loaded, input)?;
    assert_eq!(before.len(), after.len());
    for (name, values) in before {
        assert_eq!(bits(&after[&name]), bits(&values), "reload output {name}");
    }
    Ok(after)
}

fn assert_rgb_oracle(actual: &[f32], expected: &[f32]) {
    assert_eq!(actual.len(), fixture::ROWS * (4 + fixture::SCORE_FIELDS));
    assert_eq!(actual.len(), expected.len());
    for (index, (&actual, &expected)) in actual.iter().zip(expected).enumerate() {
        let tolerance = if index % 6 < 4 { 2e-4_f32 } else { 2e-6_f32 };
        assert!(actual.is_finite());
        assert!(
            (actual - expected).abs() <= tolerance,
            "RGB oracle field {index}: {actual} vs {expected}; tolerance {tolerance}"
        );
    }
}

#[test]
fn three_scale_rgb_model_preserves_original_outputs_and_runs_after_real_artifact_reload() -> Test {
    let source = fixture::model();
    let original = import(&source)?;
    let decoded = adapted(
        &source,
        &profile(),
        fixture::OUTPUT,
        fixture::TARGET,
        fixture::SCORE_FIELDS,
    )?;
    assert_eq!(decoded.source(), source);
    assert!(std::ptr::eq(decoded.source().as_ptr(), source.as_ptr()));
    assert_eq!(decoded.source_digest(), original.source_digest());
    assert_eq!(decoded.runtime_inputs(), original.runtime_inputs());
    assert_eq!(decoded.graph().version(), original.graph().version());
    assert_eq!(decoded.graph().generation(), original.graph().generation());
    assert_eq!(decoded.parameters().len(), original.parameters().len() + 3);
    assert_eq!(
        decoded
            .graph()
            .outputs()
            .iter()
            .map(|port| port.name())
            .collect::<Vec<_>>(),
        ["fine", "global", "coarse", "embedding", fixture::OUTPUT],
    );
    assert_eq!(
        decoded
            .graph()
            .find_output(fixture::OUTPUT)
            .ok_or("decoded output")?
            .shape()
            .dims(),
        [1, fixture::ROWS, 4 + fixture::SCORE_FIELDS],
    );
    for (name, tensor) in original.parameters() {
        assert_eq!(
            bits(&decoded.parameters()[name].to_vec::<f32>()?),
            bits(&tensor.to_vec::<f32>()?)
        );
    }
    let mut outcomes = Vec::new();
    for values in [vec![0.0_f32; 3 * 8 * 8], fixture::sample_input()] {
        let input = [(fixture::INPUT, data(&[1, 3, 8, 8], &values)?)];
        let before = execute(original.graph(), original.parameters().clone(), &input)?;
        let after = converted_roundtrip(&decoded, &input)?;
        for (name, values) in before {
            assert_eq!(bits(&after[&name]), bits(&values), "original output {name}");
        }
        assert_rgb_oracle(&after[fixture::OUTPUT], &fixture::oracle(&values));
        // Score-tail preservation is bit-exact against the actual raw source heads;
        // the independent real-number oracle has its own arithmetic tolerance.
        let mut decoded_row = 0;
        for level in 0..3 {
            let raw = &after[fixture::LEVEL_OUTPUTS[level]];
            let count = (8 / fixture::LEVEL_STRIDES[level]).pow(2);
            for row in 0..count {
                for score in 0..fixture::SCORE_FIELDS {
                    let field = 4 * fixture::BINS + score;
                    let index = if fixture::LEVEL_NCHW[level] {
                        field * count + row
                    } else {
                        row * fixture::FIELDS + field
                    };
                    assert_eq!(
                        after[fixture::OUTPUT][decoded_row * 6 + 4 + score].to_bits(),
                        raw[index].to_bits(),
                    );
                }
                decoded_row += 1;
            }
        }
        assert_eq!(decoded_row, fixture::ROWS);
        outcomes.push(after[fixture::OUTPUT].clone());
    }
    assert_ne!(
        bits(&outcomes[0]),
        bits(&outcomes[1]),
        "RGB must affect real inference"
    );
    Ok(())
}

fn explicit_profile(mask: usize) -> OnnxDflPyramidDecode {
    OnnxDflPyramidDecode {
        bins: 2,
        levels: [4, 1, 2]
            .into_iter()
            .enumerate()
            .map(|(index, stride)| OnnxDflPyramidLevel {
                output: format!("level-{index}"),
                stride,
                layout: if mask & (1 << index) == 0 {
                    OnnxDflPyramidLayout::Nchw
                } else {
                    OnnxDflPyramidLayout::Nhwc
                },
            })
            .collect(),
    }
}

fn dimensions(level: &OnnxDflPyramidLevel, target: [usize; 2], fields: usize) -> Vec<usize> {
    let [height, width] = target.map(|axis| axis / level.stride);
    match level.layout {
        OnnxDflPyramidLayout::Nchw => vec![1, fields, height, width],
        OnnxDflPyramidLayout::Nhwc => vec![1, height, width, fields],
    }
}

fn raw_model(names: &[String], shapes: &[Vec<usize>], collision: Option<&str>) -> Vec<u8> {
    let mut graph = Vec::new();
    for (index, (name, shape)) in names.iter().zip(shapes).enumerate() {
        let input = format!("input-{index}");
        let internal = format!("internal-{index}");
        graph.extend(node("Identity", &[&input], &[&internal], &[]));
        graph.extend(node("Identity", &[&internal], &[name], &[]));
        graph.extend(bytes(11, &info(&input, shape, 1)));
    }
    // Deliberately reverse declarations: decoding follows only explicit roles.
    for (name, shape) in names.iter().zip(shapes).rev() {
        graph.extend(bytes(12, &info(name, shape, 1)));
    }
    if let Some(name) = collision {
        graph.extend(node("Identity", &["input-0"], &[name], &[]));
        graph.extend(bytes(12, &info(name, &shapes[0], 1)));
    }
    model(&graph)
}

fn raw_source(profile: &OnnxDflPyramidDecode, target: [usize; 2], scores: usize) -> Vec<u8> {
    let names = profile
        .levels
        .iter()
        .map(|level| level.output.clone())
        .collect::<Vec<_>>();
    let shapes = profile
        .levels
        .iter()
        .map(|level| dimensions(level, target, 4 * profile.bins + scores))
        .collect::<Vec<_>>();
    raw_model(&names, &shapes, None)
}

fn direct_inputs(
    profile: &OnnxDflPyramidDecode,
    target: [usize; 2],
) -> Test<Vec<(String, Tensor)>> {
    let fields = 4 * profile.bins + 2;
    profile
        .levels
        .iter()
        .enumerate()
        .map(|(index, level)| {
            let height = target[0] / level.stride;
            let width = target[1] / level.stride;
            let count = height * width;
            let mut values = vec![0.0_f32; count * fields];
            for row in 0..count {
                for field in 4 * profile.bins..fields {
                    let position = match level.layout {
                        OnnxDflPyramidLayout::Nchw => field * count + row,
                        OnnxDflPyramidLayout::Nhwc => row * fields + field,
                    };
                    values[position] = if field == 4 * profile.bins {
                        // A distinct level/row tag makes reordering observable.
                        (100 * index + row) as f32 + 0.25
                    } else {
                        [-0.0_f32, f32::from_bits(1), -3.5, 1e20][row % 4]
                    };
                }
            }
            Ok((
                format!("input-{index}"),
                data(&dimensions(level, target, fields), &values)?,
            ))
        })
        .collect()
}

fn assert_direct_grid(actual: &[f32], profile: &OnnxDflPyramidDecode, target: [usize; 2]) {
    let mut row = 0;
    for (level_index, level) in profile.levels.iter().enumerate() {
        for y in 0..target[0] / level.stride {
            for x in 0..target[1] / level.stride {
                let local = y * (target[1] / level.stride) + x;
                // Two equal logits give exact distance one half-cell on every side.
                let expected = [
                    (x * level.stride) as f32,
                    (y * level.stride) as f32,
                    ((x + 1) * level.stride) as f32,
                    ((y + 1) * level.stride) as f32,
                    (100 * level_index + local) as f32 + 0.25,
                    [-0.0_f32, f32::from_bits(1), -3.5, 1e20][local % 4],
                ];
                assert_eq!(bits(&actual[row * 6..(row + 1) * 6]), bits(&expected));
                row += 1;
            }
        }
    }
    assert_eq!(actual.len(), row * 6);
}

#[test]
fn every_three_level_layout_combination_preserves_rectangular_grid_order_and_score_bits() -> Test {
    for mask in 0..8 {
        let profile = explicit_profile(mask);
        let source = raw_source(&profile, [4, 8], 2);
        let converted = adapted(&source, &profile, "decoded", [4, 8], 2)?;
        let owned = direct_inputs(&profile, [4, 8])?;
        let input = owned
            .iter()
            .map(|(name, tensor)| (name.as_str(), tensor.clone()))
            .collect::<Vec<_>>();
        let actual = converted_roundtrip(&converted, &input)?;
        assert_direct_grid(&actual["decoded"], &profile, [4, 8]);
        assert_eq!(actual.len(), 4);
        for (index, level) in profile.levels.iter().enumerate() {
            assert_eq!(
                bits(&actual[&level.output]),
                bits(&owned[index].1.to_vec::<f32>()?)
            );
        }
    }
    Ok(())
}

#[test]
fn single_level_and_repeated_decodes_reserve_helper_like_names_without_public_temporaries() -> Test
{
    for collision in [
        "fss:dfl-pyramid:level-0-nhwc",
        "fss:dfl-pyramid:level-0-rows",
        "fss:dfl-pyramid:packed",
        "fss:dfl:bins",
    ] {
        let mut profile = explicit_profile(0);
        profile.levels.truncate(1);
        let shape = dimensions(&profile.levels[0], [4, 8], 10);
        let source = raw_model(
            &[profile.levels[0].output.clone()],
            &[shape],
            Some(collision),
        );
        let first_name = "fss:dfl-pyramid:level-0-rows";
        let first_name = if collision == first_name {
            "fss:dfl-pyramid:packed"
        } else {
            first_name
        };
        let first = adapted(&source, &profile, first_name, [4, 8], 2)?;
        let twice = decode_onnx_dfl_pyramid(
            first,
            &profile,
            "decoded-again",
            [4, 8],
            2,
            OnnxLimits::default(),
            &|| false,
        )?;
        let owned = direct_inputs(&profile, [4, 8])?;
        let input = owned
            .iter()
            .map(|(name, tensor)| (name.as_str(), tensor.clone()))
            .collect::<Vec<_>>();
        let output = converted_roundtrip(&twice, &input)?;
        assert_eq!(output.len(), 4);
        assert_direct_grid(&output[first_name], &profile, [4, 8]);
        assert_eq!(bits(&output[first_name]), bits(&output["decoded-again"]));
        assert_eq!(bits(&output[collision]), bits(&owned[0].1.to_vec::<f32>()?));
        assert_eq!(
            twice
                .graph()
                .outputs()
                .iter()
                .map(|p| p.name())
                .collect::<Vec<_>>(),
            ["level-0", collision, first_name, "decoded-again"]
        );
    }
    Ok(())
}

#[test]
fn only_exact_declared_roles_batch_field_width_layout_and_grid_shapes_are_admitted() -> Test {
    let mut profile = explicit_profile(0);
    profile.levels.truncate(1);
    for shape in [
        vec![1, 10, 2],
        vec![2, 10, 1, 2],
        vec![1, 9, 1, 2],
        vec![1, 11, 1, 2],
        vec![1, 10, 2, 1],
        vec![1, 1, 2, 10],
    ] {
        let source = raw_model(&["level-0".into()], &[shape], None);
        assert_eq!(
            decode_onnx_dfl_pyramid(
                import(&source)?,
                &profile,
                "decoded",
                [4, 8],
                2,
                OnnxLimits::default(),
                &|| false,
            )
            .err(),
            Some(OnnxError::Graph)
        );
    }
    let source = raw_source(&profile, [4, 8], 2);
    for role in ["missing", "input-0", "internal-0"] {
        let mut wrong = profile.clone();
        wrong.levels[0].output = role.into();
        assert_eq!(
            decode_onnx_dfl_pyramid(
                import(&source)?,
                &wrong,
                "decoded",
                [4, 8],
                2,
                OnnxLimits::default(),
                &|| false,
            )
            .err(),
            Some(OnnxError::Graph)
        );
    }
    for output in ["", "   ", "bad\nname", "input-0", "internal-0", "level-0"] {
        assert_eq!(
            decode_onnx_dfl_pyramid(
                import(&source)?,
                &profile,
                output,
                [4, 8],
                2,
                OnnxLimits::default(),
                &|| false,
            )
            .err(),
            Some(OnnxError::Graph)
        );
    }
    for target in [
        [0, 8],
        [4, 0],
        [4097, 8],
        [4096, 4096],
        [usize::MAX, 8],
        [5, 8],
    ] {
        assert_eq!(
            decode_onnx_dfl_pyramid(
                import(&source)?,
                &profile,
                "decoded",
                target,
                2,
                OnnxLimits::default(),
                &|| false,
            )
            .err(),
            Some(OnnxError::Unsupported)
        );
    }
    for scores in [0, 258, usize::MAX] {
        assert_eq!(
            decode_onnx_dfl_pyramid(
                import(&source)?,
                &profile,
                "decoded",
                [4, 8],
                scores,
                OnnxLimits::default(),
                &|| false,
            )
            .err(),
            Some(OnnxError::Unsupported)
        );
    }
    profile.levels[0].stride = 1;
    let source = raw_source(&profile, [256, 256], 2);
    assert_eq!(
        decode_onnx_dfl_pyramid(
            import(&source)?,
            &profile,
            "decoded",
            [256, 256],
            2,
            OnnxLimits::default(),
            &|| false,
        )
        .err(),
        Some(OnnxError::Limit)
    );
    Ok(())
}

#[test]
fn ambiguous_and_unbounded_profiles_refuse_without_guessing() {
    let base = explicit_profile(0);
    for bins in [0, 1, 33, usize::MAX] {
        let mut bad = base.clone();
        bad.bins = bins;
        assert_eq!(bad.validate(), Err(OnnxError::Unsupported));
    }
    let mut bad = base.clone();
    bad.levels.clear();
    assert_eq!(bad.validate(), Err(OnnxError::Unsupported));
    let mut bad = base.clone();
    bad.levels = (1..=9)
        .map(|stride| OnnxDflPyramidLevel {
            output: format!("level-{stride}"),
            stride,
            layout: OnnxDflPyramidLayout::Nchw,
        })
        .collect();
    assert_eq!(bad.validate(), Err(OnnxError::Unsupported));
    for stride in [0, 4097, usize::MAX, base.levels[1].stride] {
        let mut bad = base.clone();
        bad.levels[0].stride = stride;
        assert_eq!(bad.validate(), Err(OnnxError::Unsupported));
    }
    for output in [
        "".to_owned(),
        "bad\tname".into(),
        " ".into(),
        "x".repeat(513),
        base.levels[1].output.clone(),
    ] {
        let mut bad = base.clone();
        bad.levels[0].output = output;
        assert_eq!(bad.validate(), Err(OnnxError::Graph));
    }
}

#[test]
fn packing_and_decode_share_exact_cumulative_node_name_byte_and_work_quotas() -> Test {
    let profile = explicit_profile(2);
    let source = raw_source(&profile, [4, 8], 2);
    let original = import(&source)?;
    let full = adapted(&source, &profile, "decoded", [4, 8], 2)?;
    let exact = OnnxLimits {
        source_bytes: source.len(),
        nodes: full.graph().node_count(),
        // This fixture has one distinct output per node, no erased controls, and
        // three runtime inputs. All source and generated names therefore remain.
        tensors: full.graph().inputs().len() + full.graph().node_count(),
        parameter_bytes: (3 * 42 + profile.bins) * 4,
        // Larger than each individual level, smaller than their aggregate only
        // by one byte in the failure case below.
        tensor_bytes: 42 * 10 * 4,
        work_units: full.work_units(),
    };
    assert!(full.work_units() > original.work_units());
    let repeat = decode_onnx_dfl_pyramid(
        import(&source)?,
        &profile,
        "decoded",
        [4, 8],
        2,
        exact,
        &|| false,
    )?;
    assert_eq!(
        encode_canonical_model_ir(full.graph())?,
        encode_canonical_model_ir(repeat.graph())?
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
            parameter_bytes: exact.parameter_bytes - 1,
            ..exact
        },
        OnnxLimits {
            tensor_bytes: exact.tensor_bytes - 1,
            ..exact
        },
    ] {
        assert_eq!(
            decode_onnx_dfl_pyramid(
                import(&source)?,
                &profile,
                "decoded",
                [4, 8],
                2,
                limits,
                &|| false,
            )
            .err(),
            Some(OnnxError::Limit)
        );
    }
    assert_eq!(
        decode_onnx_dfl_pyramid(
            import(&source)?,
            &profile,
            "decoded",
            [4, 8],
            2,
            OnnxLimits {
                work_units: exact.work_units - 1,
                ..exact
            },
            &|| false,
        )
        .err(),
        Some(OnnxError::WorkBudget)
    );
    Ok(())
}

#[test]
fn every_conversion_checkpoint_can_cancel_without_returning_a_partial_graph() -> Test {
    let mut profile = explicit_profile(0);
    profile.levels.truncate(1);
    let source = raw_source(&profile, [4, 8], 2);
    let calls = Cell::new(0_usize);
    let full = decode_onnx_dfl_pyramid(
        import(&source)?,
        &profile,
        "decoded",
        [4, 8],
        2,
        OnnxLimits::default(),
        &|| {
            calls.set(calls.get() + 1);
            false
        },
    )?;
    let total = calls.get();
    assert!(total > 20);
    for deadline in 1..=total {
        calls.set(0);
        assert_eq!(
            decode_onnx_dfl_pyramid(
                import(&source)?,
                &profile,
                "decoded",
                [4, 8],
                2,
                OnnxLimits::default(),
                &|| {
                    calls.set(calls.get() + 1);
                    calls.get() == deadline
                },
            )
            .err(),
            Some(OnnxError::Cancelled),
            "checkpoint {deadline}/{total}"
        );
    }
    let repeated = adapted(&source, &profile, "decoded", [4, 8], 2)?;
    assert_eq!(
        encode_canonical_model_ir(full.graph())?,
        encode_canonical_model_ir(repeated.graph())?
    );
    Ok(())
}

#[test]
fn actual_native_pyramid_execution_accounts_helpers_and_refuses_short_budgets_stale_input_and_cancel()
-> Test {
    let source = fixture::model();
    let imported = adapted(
        &source,
        &profile(),
        fixture::OUTPUT,
        fixture::TARGET,
        fixture::SCORE_FIELDS,
    )?;
    let values = fixture::sample_input();
    let input = [(fixture::INPUT, data(&[1, 3, 8, 8], &values)?)];
    let constants = imported
        .parameters()
        .iter()
        .map(|(name, tensor)| Ok((name.clone(), tensor.to_vec::<f32>()?)))
        .collect::<Result<BTreeMap<_, _>, fss_tensor::TensorError>>()?;
    let fast = optimized_executor::OptimizedGraph::prepare(
        imported.graph(),
        &constants,
        &ScalarExecCx::new(),
    )?;
    let mut bindings = imported.parameters().clone();
    bindings.insert(fixture::INPUT.into(), input[0].1.clone());
    let bindings = bindings.into_iter().collect::<Vec<_>>();
    let outcome = ScalarExecutor::run(
        imported.graph(),
        &bindings,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;
    assert_eq!(
        outcome.node_output_digests().len(),
        imported.graph().node_count()
    );
    let exact = ExecBudget::new(outcome.executed_macs(), outcome.allocated_bytes());
    let optimized = fast.run(&input, exact, &ScalarExecCx::new())?;
    assert_eq!(optimized.executed_macs(), outcome.executed_macs());
    assert_eq!(optimized.allocated_bytes(), outcome.allocated_bytes());
    for budget in [
        ExecBudget::new(outcome.executed_macs() - 1, outcome.allocated_bytes()),
        ExecBudget::new(outcome.executed_macs(), outcome.allocated_bytes() - 1),
    ] {
        assert!(matches!(
            ScalarExecutor::run(imported.graph(), &bindings, budget, &ScalarExecCx::new()),
            Err(ExecError::BudgetExceeded { .. })
        ));
        assert!(matches!(
            fast.run(&input, budget, &ScalarExecCx::new()),
            Err(ExecError::BudgetExceeded { .. })
        ));
    }
    let stale = Tensor::from_values(
        Shape::new(vec![1, 3, 8, 8])?,
        &values,
        Generation(GENERATION.0 + 1),
    )?;
    let mut stale_bindings = bindings.clone();
    stale_bindings
        .iter_mut()
        .find(|(name, _)| name == fixture::INPUT)
        .ok_or("input")?
        .1 = stale.clone();
    assert!(matches!(
        ScalarExecutor::run(
            imported.graph(),
            &stale_bindings,
            exact,
            &ScalarExecCx::new()
        ),
        Err(ExecError::GenerationMismatch { .. })
    ));
    assert!(matches!(
        fast.run(&[(fixture::INPUT, stale)], exact, &ScalarExecCx::new()),
        Err(ExecError::GenerationMismatch { .. })
    ));
    for optimized in [false, true] {
        let cx = ScalarExecCx::new();
        cx.request_cancellation();
        let result = if optimized {
            fast.run(&input, exact, &cx)
        } else {
            ScalarExecutor::run(imported.graph(), &bindings, exact, &cx)
        };
        assert!(matches!(
            result,
            Err(ExecError::CancellationRequested { .. })
        ));
        assert!(cx.is_drain_completed());
    }
    Ok(())
}
