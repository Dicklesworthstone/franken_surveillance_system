#![forbid(unsafe_code)]
//! Contract, reuse-efficiency, zero-aliasing oracle, execution-equivalence, fault, and wire tests
//! for `FSS-140` (`fss-x4a.14.11`: shape/layout/liveness scratch planner).

use fss_core::{ContentDigest, Generation};
use fss_model_ir::{
    AttributeMap, DEFAULT_SCRATCH_ALIGNMENT, GraphNode, MemoryPlan, MemoryPlanLimits, ModelIrGraph,
    ModelIrVersion, OnnxExportLimits, OnnxLimits, OpCode, SCRATCH_ARENA_PLAN_DOMAIN,
    SCRATCH_PLAN_WIRE_MAGIC, SCRATCH_PLAN_WIRE_VERSION, ScratchArenaPlan, ScratchPlanBudget,
    ScratchPlanError, TensorPort, decode_canonical_model_ir, export_onnx_artifacts, import_onnx,
};
use fss_reference::planned_scalar::{CompiledScalarPlan, PeakExecBudget};
use fss_reference::{
    ChannelTransform, ExecBudget, PreprocessProgram, ScalarExecCx, ScalarExecutor,
};
use fss_tensor::{DType, Shape, Tensor};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const DETECTOR_ONNX: &[u8] =
    include_bytes!("../../fss-model-ir/tests/fixtures/onnx/detector_split_pool.onnx");
const DETECTOR_GEN: Generation = Generation(23);

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

#[test]
fn detector_and_deep_chain_scratch_plans_reuse_slots_zero_aliasing_and_match_scalar_execution()
-> TestResult {
    assert_eq!(
        SCRATCH_ARENA_PLAN_DOMAIN,
        "fss.model_ir.scratch_arena_plan.v1"
    );

    // 1. Real 12-node ONNX detector graph (`detector_split_pool.onnx`).
    let imported = import_onnx(
        DETECTOR_ONNX,
        ContentDigest::sha256(DETECTOR_ONNX),
        DETECTOR_GEN,
        OnnxLimits::default(),
        &|| false,
    )?;
    let artifacts = export_onnx_artifacts(&imported, OnnxExportLimits::default(), &|| false)?;
    let detector_graph =
        decode_canonical_model_ir(artifacts.graph_bytes(), artifacts.graph_digest())?;

    let mem_plan = MemoryPlan::compile(&detector_graph, MemoryPlanLimits::default())?;
    let step_scratch = vec![256_usize; mem_plan.steps().len()];
    let arena_plan = ScratchArenaPlan::compile(
        &mem_plan,
        DEFAULT_SCRATCH_ALIGNMENT,
        &step_scratch,
        ScratchPlanBudget::ceiling(),
        || false,
    )?;
    assert!(!arena_plan.grants_effect_authority());
    assert_eq!(arena_plan.alignment_bytes, DEFAULT_SCRATCH_ALIGNMENT);
    assert_eq!(arena_plan.operator_scratch_bytes, 256);
    assert!(
        arena_plan.reused_allocation_count > 0 && arena_plan.reuse_saved_bytes > 0,
        "detector graph must demonstrably recycle intermediate activation slots"
    );
    assert!(arena_plan.activation_arena_bytes < arena_plan.naive_unaliased_bytes);
    arena_plan.verify_no_aliasing_overlaps()?;

    // Verify deterministic byte-exact reproducibility across repeated planning + wire round-trip.
    let arena_plan_2 = ScratchArenaPlan::compile(
        &mem_plan,
        DEFAULT_SCRATCH_ALIGNMENT,
        &step_scratch,
        ScratchPlanBudget::ceiling(),
        || false,
    )?;
    assert_eq!(arena_plan, arena_plan_2);
    let wire1 = arena_plan.to_canonical_bytes()?;
    let wire2 = arena_plan.to_canonical_bytes()?;
    assert_eq!(wire1, wire2);
    assert_eq!(&wire1[..8], &SCRATCH_PLAN_WIRE_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire1[8], wire1[9], wire1[10], wire1[11]]),
        SCRATCH_PLAN_WIRE_VERSION
    );
    assert_eq!(ScratchArenaPlan::from_canonical_bytes(&wire1)?, arena_plan);

    // Execute detector via CompiledScalarPlan vs ScalarExecutor and assert bit-exact output match!
    let raw_rgb: Vec<u8> = (0..48_u8).map(|i| i.wrapping_mul(5)).collect();
    let image = PreprocessProgram::new(4, 4, ChannelTransform::Rgb, true).execute_bytes(
        &raw_rgb,
        4,
        4,
        3,
        DETECTOR_GEN,
    )?;
    let mut bindings: Vec<(&str, Tensor)> = imported
        .parameters()
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();
    bindings.push(("image", image));

    let scalar = ScalarExecutor::run(
        &detector_graph,
        &bindings,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;
    let compiled = CompiledScalarPlan::compile(
        &detector_graph,
        MemoryPlanLimits::default(),
        &ScalarExecCx::new(),
    )?;
    let req = compiled.minimum_requirements();
    let planned = compiled.run(
        &bindings,
        PeakExecBudget::new(req.macs, req.peak_bytes, req.scratch_bytes),
        &ScalarExecCx::new(),
    )?;
    assert_eq!(
        scalar
            .get_output("head")
            .ok_or("missing head")?
            .to_vec::<f32>()?
            .iter()
            .map(|v| v.to_bits())
            .collect::<Vec<_>>(),
        planned
            .execution()
            .get_output("head")
            .ok_or("missing planned head")?
            .to_vec::<f32>()?
            .iter()
            .map(|v| v.to_bits())
            .collect::<Vec<_>>(),
    );

    // 2. Deep 10-layer unary chain `[1, 16, 16]` (1024 bytes per activation):
    //    Naive unaliased = 10 * 1024 = 10,240 bytes.
    //    With output-before-retirement ping-pong reuse, ONLY 2 slots (2,048 bytes!) are needed!
    let g = Generation(7);
    let shape = Shape::new(vec![1, 16, 16])?;
    let mut nodes = Vec::new();
    for i in 0..10_usize {
        let inp = if i == 0 {
            "x".to_owned()
        } else {
            format!("t{}", i - 1)
        };
        let out = if i == 9 {
            "y".to_owned()
        } else {
            format!("t{i}")
        };
        nodes.push(GraphNode::new(
            format!("relu_{i}"),
            OpCode::Relu,
            "relu",
            vec![inp],
            vec![out],
            AttributeMap::new(),
        )?);
    }
    let chain = ModelIrGraph::new_validated(
        "deep_chain_10",
        ModelIrVersion::V1,
        g,
        vec![TensorPort::new("x", DType::F32, shape.clone(), g)?],
        vec![TensorPort::new("y", DType::F32, shape, g)?],
        nodes,
    )?;
    let chain_mem = MemoryPlan::compile(&chain, MemoryPlanLimits::default())?;
    let chain_arena = ScratchArenaPlan::compile(
        &chain_mem,
        64,
        &[0_usize; 10],
        ScratchPlanBudget::ceiling(),
        || false,
    )?;
    assert_eq!(chain_arena.naive_unaliased_bytes, 10 * 1024);
    assert_eq!(
        chain_arena.activation_arena_bytes,
        2 * 1024,
        "10-step chain must ping-pong in exactly 2 slots (2048 bytes)"
    );
    assert_eq!(chain_arena.reuse_saved_bytes, 8 * 1024);
    assert_eq!(chain_arena.reused_allocation_count, 8);
    chain_arena.verify_no_aliasing_overlaps()?;

    emit_caplog(
        "fss_140_scratch_arena_reuse_and_equivalence",
        "detector_and_10layer_pingpong_reuse_zero_aliasing_and_0ulp_execution_verified",
        "detector_and_10layer_pingpong_reuse_zero_aliasing_and_0ulp_execution_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn scratch_planner_faults_alignment_budget_cancel_aliasing_oracle_and_wire_fail_closed()
-> TestResult {
    let g = Generation(11);
    let shape = Shape::new(vec![1, 8, 8])?; // 256 bytes
    let graph = ModelIrGraph::new_validated(
        "fault_chain",
        ModelIrVersion::V1,
        g,
        vec![TensorPort::new("x", DType::F32, shape.clone(), g)?],
        vec![TensorPort::new("y", DType::F32, shape, g)?],
        vec![
            GraphNode::new(
                "n0",
                OpCode::Relu,
                "r0",
                vec!["x".into()],
                vec!["a".into()],
                AttributeMap::new(),
            )?,
            GraphNode::new(
                "n1",
                OpCode::Sigmoid,
                "s1",
                vec!["a".into()],
                vec!["b".into()],
                AttributeMap::new(),
            )?,
            GraphNode::new(
                "n2",
                OpCode::Relu,
                "r2",
                vec!["b".into()],
                vec!["y".into()],
                AttributeMap::new(),
            )?,
        ],
    )?;
    let mem = MemoryPlan::compile(&graph, MemoryPlanLimits::default())?;

    // 1. Non-power-of-two, zero, and oversized alignment fail closed!
    for bad_align in [0, 3, 48, 8192] {
        assert_eq!(
            ScratchArenaPlan::compile(
                &mem,
                bad_align,
                &[0, 0, 0],
                ScratchPlanBudget::ceiling(),
                || { false }
            ),
            Err(ScratchPlanError::InvalidAlignment {
                alignment_bytes: bad_align,
            })
        );
    }

    // 2. Mismatched scratch schedule length fails closed!
    assert_eq!(
        ScratchArenaPlan::compile(&mem, 64, &[0, 0], ScratchPlanBudget::ceiling(), || false),
        Err(ScratchPlanError::ScratchScheduleLengthMismatch {
            expected: 3,
            observed: 2,
        })
    );

    // 3. Budget 1-short on arena_bytes, operator_scratch_bytes, and slots fails closed!
    let baseline = ScratchArenaPlan::compile(
        &mem,
        64,
        &[128, 64, 0],
        ScratchPlanBudget::ceiling(),
        || false,
    )?;
    assert!(matches!(
        ScratchArenaPlan::compile(
            &mem,
            64,
            &[128, 64, 0],
            ScratchPlanBudget::new(baseline.total_arena_bytes - 1, usize::MAX, usize::MAX),
            || false,
        ),
        Err(ScratchPlanError::BudgetExceeded {
            dimension: "arena_bytes",
            ..
        })
    ));
    assert!(matches!(
        ScratchArenaPlan::compile(
            &mem,
            64,
            &[128, 64, 0],
            ScratchPlanBudget::new(usize::MAX, 64, usize::MAX),
            || false,
        ),
        Err(ScratchPlanError::BudgetExceeded {
            dimension: "operator_scratch_bytes",
            ..
        })
    ));
    assert!(matches!(
        ScratchArenaPlan::compile(
            &mem,
            64,
            &[128, 64, 0],
            ScratchPlanBudget::new(usize::MAX, usize::MAX, 2),
            || false,
        ),
        Err(ScratchPlanError::BudgetExceeded {
            dimension: "slots",
            ..
        })
    ));

    // 4. Cooperative cancellation fails closed!
    assert_eq!(
        ScratchArenaPlan::compile(&mem, 64, &[0, 0, 0], ScratchPlanBudget::ceiling(), || true),
        Err(ScratchPlanError::Cancelled)
    );

    // 5. Independent zero-aliasing oracle catches deliberately forged overlapping live slots!
    let mut forged = baseline.clone();
    // Step 0 produces `a` (live [0..=1]), step 1 produces `b` (live [1..=2]); forcing same offset 0 MUST fail!
    forged.assignments[0].arena_offset = 0;
    forged.assignments[1].arena_offset = 0;
    assert!(matches!(
        forged.verify_no_aliasing_overlaps(),
        Err(ScratchPlanError::AliasingOrInvariantViolation(_))
    ));

    // 6. Hostile wire decoding on `FSSSPL01`: bad magic, bad version, truncation, bit-flip, trailing byte!
    let wire = baseline.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        ScratchArenaPlan::from_canonical_bytes(&bad_magic),
        Err(ScratchPlanError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&99_u32.to_be_bytes());
    assert_eq!(
        ScratchArenaPlan::from_canonical_bytes(&bad_ver),
        Err(ScratchPlanError::UnsupportedVersion { version: 99 })
    );
    assert!(matches!(
        ScratchArenaPlan::from_canonical_bytes(&wire[..wire.len() - 4]),
        Err(ScratchPlanError::MalformedWire(_))
    ));
    let mut flipped = wire.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    assert_eq!(
        ScratchArenaPlan::from_canonical_bytes(&flipped),
        Err(ScratchPlanError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0x42);
    assert!(matches!(
        ScratchArenaPlan::from_canonical_bytes(&trailing),
        Err(ScratchPlanError::MalformedWire(_))
    ));

    emit_caplog(
        "fss_140_scratch_planner_faults_and_wire",
        "alignment_schedule_budget_cancel_aliasing_oracle_and_wire_failed_closed",
        "alignment_schedule_budget_cancel_aliasing_oracle_and_wire_failed_closed",
        "pass",
    );
    Ok(())
}
