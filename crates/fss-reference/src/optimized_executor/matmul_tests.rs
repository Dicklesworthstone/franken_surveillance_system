#![forbid(unsafe_code)]
//! Actual-graph differential tests, refusal contracts and same-binary MatMul measurements.

use std::collections::BTreeMap;

use fss_core::{ContentDigest, Generation};
use fss_model_ir::{
    AttributeMap, GraphNode, ModelIrGraph, ModelIrVersion, OpCode, TensorPort,
    infer_operator_outputs,
};
use fss_tensor::{DType, Shape, Tensor};

use super::{ExecThreads, OptimizedGraph};
use crate::{ExecBudget, ExecError, ScalarExecCx, ScalarExecutor};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const G: Generation = Generation(1);

fn graph(a: &[usize], b: &[usize], alias: bool) -> Result<ModelIrGraph> {
    let a = TensorPort::new("a", DType::F32, Shape::new(a)?, G)?;
    let b = TensorPort::new(
        if alias { "a" } else { "b" },
        DType::F32,
        Shape::new(b)?,
        G,
    )?;
    let outputs = infer_operator_outputs(
        "matmul",
        OpCode::MatMul,
        &[&a, &b],
        &["y".into()],
        &AttributeMap::new(),
        G,
    )?;
    let inputs = if alias { vec![a] } else { vec![a, b] };
    let node = GraphNode::new(
        "matmul",
        OpCode::MatMul,
        "matmul",
        vec!["a".into(), if alias { "a".into() } else { "b".into() }],
        vec!["y".into()],
        AttributeMap::new(),
    )?;
    Ok(ModelIrGraph::new_validated(
        "matmul-differential",
        ModelIrVersion::V1,
        G,
        inputs,
        outputs,
        vec![node],
    )?)
}

fn values(size: usize, seed: u64, special: bool) -> Vec<f32> {
    let mut state = seed;
    (0..size)
        .map(|i| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            if special && i % 13 == 0 {
                let cases = [
                    0.0,
                    -0.0,
                    f32::from_bits(1),
                    -f32::from_bits(1),
                    f32::MAX,
                    -f32::MAX,
                    f32::INFINITY,
                    f32::NEG_INFINITY,
                    f32::NAN,
                ];
                cases[(state as usize) % cases.len()]
            } else {
                ((state >> 40) as f32 / (1_u32 << 24) as f32 - 0.5) * 8.0
            }
        })
        .collect()
}

fn same(a: &[f32], b: &[f32]) {
    assert_eq!(a.len(), b.len());
    for (i, (&a, &b)) in a.iter().zip(b).enumerate() {
        if a.is_nan() || b.is_nan() {
            assert!(
                a.is_nan() && b.is_nan(),
                "NaN classification at {i}: {a} vs {b}"
            );
        } else {
            assert_eq!(a.to_bits(), b.to_bits(), "output {i}: {a} vs {b}");
        }
    }
}

fn tensors(graph: &ModelIrGraph, special: bool) -> Result<Vec<(String, Tensor)>> {
    graph
        .inputs()
        .iter()
        .enumerate()
        .map(|(i, port)| {
            let data = values(
                port.shape().num_elements()?,
                0x4a31_987b + i as u64,
                special,
            );
            Ok((
                port.name().into(),
                Tensor::from_values(port.shape().clone(), &data, G)?,
            ))
        })
        .collect()
}

fn differential(a: &[usize], b: &[usize], special: bool, constant: usize) -> Result {
    let graph = graph(a, b, false)?;
    let input = tensors(&graph, special)?;
    let mut constants = BTreeMap::new();
    let mut runtime = Vec::new();
    for (i, (name, tensor)) in input.iter().enumerate() {
        if constant & (1 << i) != 0 {
            constants.insert(name.clone(), tensor.to_vec::<f32>()?);
        } else {
            runtime.push((name.clone(), tensor.clone()));
        }
    }
    let cx = ScalarExecCx::new();
    let oracle = ScalarExecutor::run(&graph, &input, ExecBudget::unlimited(), &cx)?;
    let plan = OptimizedGraph::prepare(&graph, &constants, &cx)?;
    let (actual, report) = plan.run_with_report(&runtime, ExecBudget::unlimited(), &cx)?;
    assert_eq!(oracle.executed_macs(), actual.executed_macs());
    assert_eq!(oracle.allocated_bytes(), actual.allocated_bytes());
    assert_eq!(oracle.nodes_executed(), actual.nodes_executed());
    same(
        &oracle.get_output("y").ok_or("oracle output")?.to_vec::<f32>()?,
        &actual
            .get_output("y")
            .ok_or("optimized output")?
            .to_vec::<f32>()?,
    );
    if a.contains(&0) || b.contains(&0) {
        assert_eq!(
            plan.kernel_counts().get("scalar-reference-node.v1"),
            Some(&1)
        );
    } else {
        assert_eq!(plan.kernel_counts().get("matmul.tiles4x8.v1"), Some(&1));
        assert_eq!(report.scratch_bytes, 128);
    }
    Ok(())
}

#[test]
fn tiled_matmul_matches_scalar_for_uneven_tiles_and_reduction_checkpoints() -> Result {
    for m in [1, 3, 4, 5, 9] {
        for n in [1, 7, 8, 9, 17] {
            for k in [1, 7, 256, 257] {
                differential(
                    &[m, k],
                    &[k, n],
                    (m + n + k) % 2 == 0,
                    (m + n + k) % 4,
                )?;
            }
        }
    }
    Ok(())
}

#[test]
fn batch_broadcast_and_shared_operands_preserve_exact_reference_results() -> Result {
    let shapes = [
        (vec![2, 1, 5, 7], vec![1, 3, 7, 9]),
        (vec![4, 3, 7], vec![7, 11]),
        (vec![5, 7], vec![2, 3, 7, 9]),
        (vec![2, 1, 3, 1, 5, 7], vec![1, 4, 1, 2, 7, 9]),
        (
            vec![1, 2, 1, 1, 1, 1, 4, 3],
            vec![2, 1, 1, 1, 1, 1, 3, 8],
        ),
    ];
    for (a, b) in shapes {
        for constant in 0..4 {
            differential(&a, &b, constant % 2 == 0, constant)?;
        }
    }
    Ok(())
}

#[test]
fn broadcast_batch_positions_match_an_independent_hand_computed_example() -> Result {
    let graph = graph(&[2, 1, 1, 2], &[1, 3, 2, 1], false)?;
    let inputs = vec![
        (
            "a",
            Tensor::from_values(
                Shape::new([2, 1, 1, 2])?,
                &[1.0_f32, 2.0, 3.0, 4.0],
                G,
            )?,
        ),
        (
            "b",
            Tensor::from_values(
                Shape::new([1, 3, 2, 1])?,
                &[10.0_f32, 20.0, 30.0, 40.0, 50.0, 60.0],
                G,
            )?,
        ),
    ];
    let cx = ScalarExecCx::new();
    let plan = OptimizedGraph::prepare(&graph, &BTreeMap::new(), &cx)?;
    let result = plan.run(&inputs, ExecBudget::unlimited(), &cx)?;
    same(
        &result.get_output("y").ok_or("output")?.to_vec::<f32>()?,
        &[50.0, 110.0, 170.0, 110.0, 250.0, 390.0],
    );
    Ok(())
}

#[test]
fn empty_geometries_keep_the_established_scalar_semantics() -> Result {
    differential(&[2, 0], &[0, 3], false, 0)?;
    differential(&[0, 3], &[3, 2], false, 3)?;
    differential(&[2, 3], &[3, 0], false, 2)?;
    Ok(())
}

#[test]
fn repeated_input_aliases_and_thread_requests_do_not_change_output() -> Result {
    let graph = graph(&[5, 5], &[5, 5], true)?;
    let inputs = tensors(&graph, false)?;
    let cx = ScalarExecCx::new();
    let plan = OptimizedGraph::prepare(&graph, &BTreeMap::new(), &cx)?;
    let oracle = ScalarExecutor::run(&graph, &inputs, ExecBudget::unlimited(), &cx)?;
    let digest = plan.digest();
    for count in [1, 2, 7] {
        let (actual, report) = plan.run_threaded(
            &inputs,
            ExecBudget::unlimited(),
            ExecThreads::new(count)?,
            &cx,
        )?;
        same(
            &actual.get_output("y").ok_or("output")?.to_vec::<f32>()?,
            &oracle.get_output("y").ok_or("oracle")?.to_vec::<f32>()?,
        );
        assert_eq!(report.threads_used, 1);
        assert_eq!(report.threads_requested, count);
        assert_eq!(digest, plan.digest());
    }
    Ok(())
}

#[test]
fn exact_budgets_succeed_and_short_budgets_or_cancellation_withhold_outputs() -> Result {
    let graph = graph(&[7, 13], &[13, 11], false)?;
    let inputs = tensors(&graph, false)?;
    let cx = ScalarExecCx::new();
    let plan = OptimizedGraph::prepare(&graph, &BTreeMap::new(), &cx)?;
    let oracle = ScalarExecutor::run(&graph, &inputs, ExecBudget::unlimited(), &cx)?;
    let exact = ExecBudget {
        max_macs: oracle.executed_macs(),
        max_bytes: oracle.allocated_bytes(),
    };
    let actual = plan.run(&inputs, exact, &cx)?;
    same(
        &actual.get_output("y").ok_or("output")?.to_vec::<f32>()?,
        &oracle.get_output("y").ok_or("oracle")?.to_vec::<f32>()?,
    );
    for budget in [
        ExecBudget {
            max_macs: exact.max_macs - 1,
            ..exact
        },
        ExecBudget {
            max_bytes: exact.max_bytes - 1,
            ..exact
        },
    ] {
        assert!(matches!(
            plan.run(&inputs, budget, &cx),
            Err(ExecError::BudgetExceeded { .. })
        ));
    }
    cx.request_cancellation();
    assert!(matches!(
        plan.run(&inputs, exact, &cx),
        Err(ExecError::CancellationRequested { .. })
    ));
    assert!(cx.is_drain_completed());
    Ok(())
}

/// Same executable, exact inputs, alternating arm order, one warmup and seven observations.
/// Run with a release test build and --ignored --nocapture; timings are never pass gates.
#[test]
#[ignore = "same-binary performance experiment; run explicitly in release mode"]
fn profile_matmul_same_binary() -> Result {
    use std::{hint::black_box, time::Instant};

    for (name, a, b) in [
        ("projection", vec![128, 256], vec![256, 256]),
        ("attention", vec![4, 96, 64], vec![4, 64, 96]),
        ("broadcast_projection", vec![4, 64, 128], vec![128, 192]),
        ("small_vector", vec![1, 64], vec![64, 32]),
    ] {
        let graph = graph(&a, &b, false)?;
        let inputs = tensors(&graph, false)?;
        let cx = ScalarExecCx::new();
        let start = Instant::now();
        let plan = OptimizedGraph::prepare(&graph, &BTreeMap::new(), &cx)?;
        let prepare_ns = start.elapsed().as_nanos();
        let reference =
            ScalarExecutor::run(&graph, &inputs, ExecBudget::unlimited(), &cx)?;
        let (warm, report) = plan.run_with_report(&inputs, ExecBudget::unlimited(), &cx)?;
        let expected = reference.get_output("y").ok_or("oracle")?.to_vec::<f32>()?;
        same(
            &expected,
            &warm.get_output("y").ok_or("output")?.to_vec::<f32>()?,
        );
        let bytes: Vec<u8> = expected
            .iter()
            .flat_map(|v| v.to_bits().to_le_bytes())
            .collect();
        let output = ContentDigest::sha256(&bytes);
        let mut scalar_ns = Vec::new();
        let mut optimized_ns = Vec::new();
        for iteration in 0..7 {
            for which in 0..2 {
                let scalar = (iteration + which) % 2 == 0;
                let start = Instant::now();
                let result = if scalar {
                    ScalarExecutor::run(
                        black_box(&graph),
                        black_box(&inputs),
                        ExecBudget::unlimited(),
                        &cx,
                    )?
                } else {
                    plan.run(black_box(&inputs), ExecBudget::unlimited(), &cx)?
                };
                let elapsed = start.elapsed().as_nanos();
                same(
                    &expected,
                    &result
                        .get_output("y")
                        .ok_or("measured output")?
                        .to_vec::<f32>()?,
                );
                if scalar {
                    scalar_ns.push(elapsed);
                } else {
                    optimized_ns.push(elapsed);
                }
            }
        }
        println!(
            "MATMUL_PROFILE {{\"case\":\"{name}\",\"a\":{a:?},\"b\":{b:?},\"prepare_ns\":{prepare_ns},\"scalar_ns\":{scalar_ns:?},\"optimized_ns\":{optimized_ns:?},\"output_sha256\":\"{output}\",\"macs\":{},\"cumulative_tensor_bytes\":{},\"peak_live_bytes\":{},\"scratch_bytes\":{},\"kernel_generation\":\"{}\"}}",
            reference.executed_macs(),
            reference.allocated_bytes(),
            report.peak_live_bytes,
            report.scratch_bytes,
            plan.kernel_generation()
        );
    }
    Ok(())
}
