#![forbid(unsafe_code)]
//! Public liveness contracts; independent future-consumer oracle never uses last-use indices.
use fss_core::Generation;
use fss_model_ir::{
    AttrValue, AttributeMap, GraphNode, MemoryPlan, MemoryPlanError, MemoryPlanLimits,
    ModelIrGraph, ModelIrVersion, OpCode, TensorPort,
};
use fss_tensor::{DType, MAX_STORAGE_BYTES, Shape};
use std::collections::BTreeSet;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const GEN: Generation = Generation(3);
fn port(name: &str, dims: &[usize]) -> Test<TensorPort> {
    Ok(TensorPort::new(name, DType::F32, Shape::new(dims)?, GEN)?)
}
fn node(id: &str, op: OpCode, inputs: &[&str], output: &str) -> Test<GraphNode> {
    Ok(GraphNode::new(
        id,
        op,
        id,
        inputs.iter().map(|s| (*s).to_owned()).collect(),
        vec![output.to_owned()],
        AttributeMap::new(),
    )?)
}
fn graph(nodes: Vec<GraphNode>, outputs: &[&str], dims: &[usize]) -> Test<ModelIrGraph> {
    Ok(ModelIrGraph::new(
        "graph:memory",
        ModelIrVersion::V1,
        GEN,
        vec![port("x", dims)?],
        outputs
            .iter()
            .map(|name| port(name, dims))
            .collect::<Test<_>>()?,
        nodes,
    )?)
}
fn compile(graph: &ModelIrGraph) -> Test<MemoryPlan> {
    Ok(MemoryPlan::compile(graph, MemoryPlanLimits::default())?)
}
fn chain(n: usize, dims: &[usize]) -> Test<ModelIrGraph> {
    let mut nodes = Vec::new();
    let mut input = "x".to_owned();
    for i in 0..n {
        let output = format!("v{i:04}");
        nodes.push(node(
            &format!("node:{i:04}"),
            OpCode::Relu,
            &[&input],
            &output,
        )?);
        input = output;
    }
    graph(nodes, &[&input], dims)
}
fn diamond(pin_a: bool) -> Test<ModelIrGraph> {
    graph(
        vec![
            node("a", OpCode::Relu, &["x"], "a0")?,
            node("b", OpCode::Relu, &["a0"], "b0")?,
            node("c", OpCode::Relu, &["a0"], "c0")?,
            node("d", OpCode::Add, &["b0", "c0"], "d0")?,
        ],
        if pin_a { &["a0", "d0"] } else { &["d0"] },
        &[4],
    )
}

#[test]
fn long_chain_memory_is_not_cumulative_activation_volume() -> Test {
    let p = compile(&chain(100, &[4])?)?;
    assert_eq!(p.input_bytes(), 16);
    assert_eq!(p.output_bytes(), 16);
    assert_eq!(p.cumulative_bytes(), 1616);
    assert_eq!(p.peak_live_bytes(), 48);
    assert!(p.steps()[0].release_after().is_empty());
    assert_eq!(p.steps()[1].release_after(), &["v0000".to_owned()]);
    assert_eq!(p.steps()[99].retained_bytes(), 32);
    assert_eq!(p.values()["x"].release_after(), None);
    assert_eq!(p.values()["v0099"].release_after(), None);
    assert_eq!(p.values()["v0000"].producer(), Some(0));
    Ok(())
}

#[test]
fn diamond_holds_branch_input_until_both_consumers_finish() -> Test {
    let p = compile(&diamond(false)?)?;
    assert_eq!(p.cumulative_bytes(), 80);
    assert_eq!(p.peak_live_bytes(), 64);
    assert!(p.steps()[1].release_after().is_empty());
    assert_eq!(p.steps()[2].release_after(), &["a0".to_owned()]);
    assert_eq!(
        p.steps()[3].release_after(),
        &["b0".to_owned(), "c0".to_owned()]
    );
    assert_eq!(p.steps()[3].retained_bytes(), 32);
    Ok(())
}

#[test]
fn intermediate_declared_as_graph_output_is_pinned_even_after_consumption() -> Test {
    let p = compile(&diamond(true)?)?;
    assert_eq!(p.output_bytes(), 32);
    assert_eq!(p.peak_live_bytes(), 80);
    assert_eq!(p.steps()[3].retained_bytes(), 48);
    assert_eq!(p.values()["a0"].release_after(), None);
    assert!(
        p.steps()
            .iter()
            .all(|s| !s.release_after().iter().any(|n| n == "a0"))
    );
    Ok(())
}

#[test]
fn repeated_input_retires_one_storage_not_one_per_edge() -> Test {
    let g = graph(
        vec![
            node("a", OpCode::Relu, &["x"], "a0")?,
            node("b", OpCode::Add, &["a0", "a0"], "b0")?,
        ],
        &["b0"],
        &[4],
    )?;
    let p = compile(&g)?;
    assert_eq!(p.peak_live_bytes(), 48);
    assert_eq!(p.steps()[1].release_after(), &["a0".to_owned()]);
    assert_eq!(p.steps()[1].retained_bytes(), 32);
    Ok(())
}

#[test]
fn unused_node_still_materializes_then_retires_at_its_own_step() -> Test {
    let g = graph(
        vec![
            node("a", OpCode::Relu, &["x"], "a0")?,
            node("z", OpCode::Relu, &["x"], "unused")?,
        ],
        &["a0"],
        &[4],
    )?;
    let p = compile(&g)?;
    assert_eq!(p.steps().len(), 2);
    assert_eq!(p.cumulative_bytes(), 48);
    assert_eq!(p.steps()[1].produced(), &["unused".to_owned()]);
    assert_eq!(p.steps()[1].release_after(), &["unused".to_owned()]);
    assert_eq!(p.steps()[1].live_bytes(), 48);
    assert_eq!(p.steps()[1].retained_bytes(), 32);
    Ok(())
}

#[test]
fn pass_through_and_unused_inputs_stay_resident() -> Test {
    let g = ModelIrGraph::new(
        "graph:inputs",
        ModelIrVersion::V1,
        GEN,
        vec![port("x", &[4])?, port("unused", &[8])?],
        vec![port("x", &[4])?],
        vec![node("dead", OpCode::Relu, &["x"], "dead0")?],
    )?;
    let p = compile(&g)?;
    assert_eq!(p.steps().len(), 1);
    assert_eq!(p.input_bytes(), 48);
    assert_eq!(p.cumulative_bytes(), 64);
    assert_eq!(p.peak_live_bytes(), 64);
    assert_eq!(p.steps()[0].retained_bytes(), 48);
    assert_eq!(p.output_bytes(), 16);
    assert_eq!(p.peak_with_scratch(&[0])?, 64);
    Ok(())
}

#[test]
fn scalar_and_zero_sized_payloads_are_distinct() -> Test {
    assert_eq!(compile(&chain(3, &[])?)?.peak_live_bytes(), 12);
    let empty = compile(&chain(3, &[2, 0, 7])?)?;
    assert_eq!(empty.peak_live_bytes(), 0);
    assert_eq!(empty.cumulative_bytes(), 0);
    assert_eq!(empty.steps()[1].release_after(), &["v0000".to_owned()]);
    assert_eq!(empty.peak_with_scratch(&[0, 17, 3])?, 17);
    Ok(())
}

#[test]
fn view_like_operators_are_materialized_not_unsafely_aliased() -> Test {
    let n = GraphNode::new(
        "reshape",
        OpCode::Reshape,
        "reshape",
        vec!["x".into()],
        vec!["y".into()],
        [("shape".to_owned(), AttrValue::IntList(vec![4]))]
            .into_iter()
            .collect(),
    )?;
    let g = ModelIrGraph::new(
        "graph:reshape",
        ModelIrVersion::V1,
        GEN,
        vec![port("x", &[2, 2])?],
        vec![port("y", &[4])?],
        vec![n],
    )?;
    let p = compile(&g)?;
    assert_eq!(p.peak_live_bytes(), 32);
    assert_eq!(p.values()["y"].port().shape().dims(), &[4]);
    Ok(())
}

#[test]
fn schedule_and_digest_ignore_node_insertion_order_and_admission_limits() -> Test {
    let g = diamond(false)?;
    let mut nodes = g.nodes().to_vec();
    nodes.reverse();
    let reversed = graph(nodes, &["d0"], &[4])?;
    let a = compile(&g)?;
    let b = MemoryPlan::compile(
        &reversed,
        MemoryPlanLimits {
            max_nodes: 4,
            max_values: 5,
            max_references: 11,
            ..MemoryPlanLimits::default()
        },
    )?;
    assert_eq!(a, b);
    let changed = compile(&diamond(true)?)?;
    assert_ne!(a.digest(), changed.digest());
    Ok(())
}

#[test]
fn scratch_is_added_at_the_same_node_not_to_an_unrelated_peak() -> Test {
    let p = compile(&diamond(false)?)?;
    assert_eq!(p.peak_with_scratch(&[100, 0, 0, 0])?, 132);
    assert_eq!(p.peak_with_scratch(&[0, 0, 100, 0])?, 164);
    assert!(matches!(
        p.peak_with_scratch(&[1]),
        Err(MemoryPlanError::ScratchLength)
    ));
    assert!(matches!(
        p.peak_with_scratch(&[usize::MAX, 0, 0, 0]),
        Err(MemoryPlanError::Overflow)
    ));
    Ok(())
}

#[test]
fn bounds_refuse_without_truncating_the_graph() -> Test {
    let g = chain(3, &[4])?;
    for limits in [
        MemoryPlanLimits {
            max_nodes: 2,
            ..MemoryPlanLimits::default()
        },
        MemoryPlanLimits {
            max_values: 3,
            ..MemoryPlanLimits::default()
        },
        MemoryPlanLimits {
            max_references: 1,
            ..MemoryPlanLimits::default()
        },
        MemoryPlanLimits {
            max_metadata_bytes: 0,
            ..MemoryPlanLimits::default()
        },
        MemoryPlanLimits {
            max_nodes: usize::MAX,
            ..MemoryPlanLimits::default()
        },
    ] {
        assert!(matches!(
            MemoryPlan::compile(&g, limits),
            Err(MemoryPlanError::Limit(_))
        ));
    }
    let too_large = chain(1, &[MAX_STORAGE_BYTES / 4 + 1])?;
    assert!(matches!(
        MemoryPlan::compile(&too_large, MemoryPlanLimits::default()),
        Err(MemoryPlanError::Limit("tensor payload"))
    ));
    Ok(())
}

#[test]
fn malformed_topology_and_generations_never_receive_a_schedule() -> Test {
    let missing = graph(
        vec![node("a", OpCode::Relu, &["missing"], "a0")?],
        &["a0"],
        &[4],
    )?;
    assert!(matches!(
        MemoryPlan::compile(&missing, MemoryPlanLimits::default()),
        Err(MemoryPlanError::Ir(_))
    ));
    let cycle = graph(
        vec![
            node("a", OpCode::Relu, &["b0"], "a0")?,
            node("b", OpCode::Relu, &["a0"], "b0")?,
        ],
        &["a0"],
        &[4],
    )?;
    assert!(matches!(
        MemoryPlan::compile(&cycle, MemoryPlanLimits::default()),
        Err(MemoryPlanError::Ir(_))
    ));
    let bad_generation = ModelIrGraph::new(
        "graph:stale",
        ModelIrVersion::V1,
        Generation(4),
        vec![port("x", &[4])?],
        vec![port("y", &[4])?],
        vec![node("a", OpCode::Relu, &["x"], "y")?],
    )?;
    assert!(matches!(
        MemoryPlan::compile(&bad_generation, MemoryPlanLimits::default()),
        Err(MemoryPlanError::Ir(
            fss_model_ir::ModelIrError::GenerationMismatch { .. }
        ))
    ));
    let empty = graph(vec![], &["x"], &[4])?;
    assert!(matches!(
        MemoryPlan::compile(&empty, MemoryPlanLimits::default()),
        Err(MemoryPlanError::Ir(fss_model_ir::ModelIrError::EmptyGraph))
    ));
    Ok(())
}

#[test]
fn every_planning_checkpoint_can_cancel_without_returning_partial_state() -> Test {
    let g = diamond(false)?;
    let mut calls = 0;
    let expected = MemoryPlan::compile_cancellable(&g, MemoryPlanLimits::default(), || {
        calls += 1;
        false
    })?;
    assert!(calls > g.node_count());
    for stop in 1..=calls {
        let mut at = 0;
        let result = MemoryPlan::compile_cancellable(&g, MemoryPlanLimits::default(), || {
            at += 1;
            at == stop
        });
        assert!(
            matches!(result, Err(MemoryPlanError::Cancelled)),
            "cut {stop}"
        );
    }
    assert_eq!(compile(&g)?, expected);
    Ok(())
}

#[test]
fn generated_dags_match_independent_future_consumer_set_oracle() -> Test {
    let mut seed = 0x4567_8934_1212_u64;
    for _ in 0..1000 {
        let mut names = vec!["x".to_owned()];
        let mut nodes = Vec::new();
        for i in 0..12 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let a = (seed >> 32) as usize % names.len();
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let b = (seed >> 32) as usize % names.len();
            let output = format!("v{i:02}");
            nodes.push(node(
                &format!("n{i:02}"),
                OpCode::Add,
                &[&names[a], &names[b]],
                &output,
            )?);
            names.push(output);
        }
        let extra = (seed as usize % 11) + 1;
        let g = graph(nodes, &[&names[12], &names[extra]], &[2])?;
        let p = compile(&g)?;
        let mut live = BTreeSet::from(["x".to_owned()]);
        let mut peak = 8;
        for (position, step) in p.steps().iter().enumerate() {
            let n = g.find_node(step.node_id()).ok_or("missing oracle node")?;
            live.extend(n.outputs().iter().cloned());
            let during = live.len() * 8;
            peak = peak.max(during);
            assert_eq!(step.live_bytes(), during);
            let mut future = BTreeSet::from(["x".to_owned()]);
            future.extend(g.outputs().iter().map(|v| v.name().to_owned()));
            for next in &p.steps()[position + 1..] {
                let consumer = g.find_node(next.node_id()).ok_or("missing future node")?;
                future.extend(consumer.inputs().iter().cloned());
            }
            let drop: Vec<_> = live.difference(&future).cloned().collect();
            assert_eq!(step.release_after(), drop.as_slice());
            live.retain(|name| future.contains(name));
            assert_eq!(step.retained_bytes(), live.len() * 8);
        }
        assert_eq!(p.peak_live_bytes(), peak);
        assert_eq!(p.cumulative_bytes(), 13 * 8);
    }
    Ok(())
}
