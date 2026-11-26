#![forbid(unsafe_code)]
//! Contract, thread-invariance, 0-ULP scalar-oracle equivalence, strict no-fallback, cancellation,
//! budget, and hostile-wire tests for `FSS-141` (`fss-x4a.14.12`: static kernel dispatch receipts).

use std::collections::BTreeMap;

use fss_core::{ContentDigest, Generation};
use fss_model_ir::{
    AttributeMap, GraphNode, ModelIrGraph, ModelIrVersion, OnnxExportLimits, OnnxLimits, OpCode,
    ScratchPlanBudget, TensorPort, decode_canonical_model_ir, export_onnx_artifacts, import_onnx,
};
use fss_reference::kernel_dispatch::{
    DispatchFallbackReason, DispatchOutcomeState, KERNEL_DISPATCH_RECEIPT_DOMAIN,
    KERNEL_DISPATCH_WIRE_MAGIC, KERNEL_DISPATCH_WIRE_VERSION, KernelDispatchDecisionReceipt,
    KernelDispatchError, KernelDispatchPolicy, StaticKernelDispatcher,
};
use fss_reference::optimized_executor::{ExecThreads, KernelBackend};
use fss_reference::{ChannelTransform, ExecBudget, PreprocessProgram, ScalarExecCx};
use fss_tensor::{DType, Shape, Tensor};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const DETECTOR_ONNX: &[u8] =
    include_bytes!("../../fss-model-ir/tests/fixtures/onnx/detector_split_pool.onnx");
const DETECTOR_GEN: Generation = Generation(31);

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

#[test]
fn detector_static_dispatch_is_thread_invariant_0ulp_oracle_verified_and_wire_deterministic()
-> TestResult {
    assert_eq!(
        KERNEL_DISPATCH_RECEIPT_DOMAIN,
        "fss.reference.kernel_dispatch_receipt.v1"
    );

    let imported = import_onnx(
        DETECTOR_ONNX,
        ContentDigest::sha256(DETECTOR_ONNX),
        DETECTOR_GEN,
        OnnxLimits::default(),
        &|| false,
    )?;
    let artifacts = export_onnx_artifacts(&imported, OnnxExportLimits::default(), &|| false)?;
    let graph = decode_canonical_model_ir(artifacts.graph_bytes(), artifacts.graph_digest())?;

    let mut constants: BTreeMap<String, Vec<f32>> = BTreeMap::new();
    for (name, tensor) in imported.parameters() {
        constants.insert(name.clone(), tensor.to_vec::<f32>()?);
    }

    let cx = ScalarExecCx::new();
    let policy_t1 = KernelDispatchPolicy {
        backend: KernelBackend::OptimizedCpuV1,
        threads: ExecThreads::SINGLE,
        allow_scalar_fallback: false,
        verify_against_scalar_oracle: true,
        ..KernelDispatchPolicy::default()
    };
    let policy_t4 = KernelDispatchPolicy {
        threads: ExecThreads::new(4)?,
        ..policy_t1
    };

    // Compile with 1 thread vs 4 threads -> static receipts MUST be bit-for-bit IDENTICAL!
    let plan_t1 = StaticKernelDispatcher::compile(&graph, &constants, policy_t1, &cx)?;
    let plan_t4 = StaticKernelDispatcher::compile(&graph, &constants, policy_t4, &cx)?;
    assert!(!plan_t1.receipt().grants_effect_authority());
    assert_eq!(
        plan_t1.receipt().outcome_state,
        DispatchOutcomeState::StaticOptimizedExact
    );
    assert_eq!(plan_t1.receipt().fallback_node_count, 0);
    assert!(plan_t1.receipt().reuse_saved_bytes > 0);
    assert_eq!(plan_t1.receipt(), plan_t4.receipt());
    assert_eq!(
        plan_t1.receipt().decision_path_digest,
        plan_t4.receipt().decision_path_digest
    );

    // Execute both plans with 0-ULP scalar oracle verification enabled!
    let raw_rgb: Vec<u8> = (0..48_u8).map(|i| i.wrapping_mul(11)).collect();
    let image = PreprocessProgram::new(4, 4, ChannelTransform::Rgb, true).execute_bytes(
        &raw_rgb,
        4,
        4,
        3,
        DETECTOR_GEN,
    )?;
    let runtime_inputs = [("image", image.clone())];

    let exec_t1 = plan_t1.execute(&runtime_inputs, ExecBudget::unlimited(), &cx)?;
    let exec_t4 = plan_t4.execute(&runtime_inputs, ExecBudget::unlimited(), &cx)?;
    assert!(exec_t1.oracle_bit_exact_verified);
    assert!(exec_t4.oracle_bit_exact_verified);
    let head_t1: Vec<u32> = exec_t1
        .outcome
        .get_output("head")
        .ok_or("missing head")?
        .to_vec::<f32>()?
        .iter()
        .map(|v| v.to_bits())
        .collect();
    let head_t4: Vec<u32> = exec_t4
        .outcome
        .get_output("head")
        .ok_or("missing head")?
        .to_vec::<f32>()?
        .iter()
        .map(|v| v.to_bits())
        .collect();
    assert_eq!(head_t1, head_t4);

    // Compare against explicit ScalarReferenceOnly dispatch policy.
    let policy_scalar = KernelDispatchPolicy {
        backend: KernelBackend::ScalarReference,
        allow_scalar_fallback: true,
        verify_against_scalar_oracle: true,
        ..KernelDispatchPolicy::default()
    };
    let plan_scalar = StaticKernelDispatcher::compile(&graph, &constants, policy_scalar, &cx)?;
    assert_eq!(
        plan_scalar.receipt().outcome_state,
        DispatchOutcomeState::ScalarReferenceOnly
    );
    assert_eq!(
        plan_scalar.receipt().fallback_node_count,
        plan_scalar.receipt().decisions.len()
    );
    assert_eq!(
        plan_scalar.receipt().total_macs,
        plan_t1.receipt().total_macs
    );
    assert!(plan_scalar.receipt().total_macs > 0);
    let exec_scalar = plan_scalar.execute(&runtime_inputs, ExecBudget::unlimited(), &cx)?;
    let head_scalar: Vec<u32> = exec_scalar
        .outcome
        .get_output("head")
        .ok_or("missing scalar head")?
        .to_vec::<f32>()?
        .iter()
        .map(|v| v.to_bits())
        .collect();
    assert_eq!(head_t1, head_scalar);

    // Verify deterministic `FSSKDR01` v1 wire round-trip.
    let wire1 = plan_t1.receipt().to_canonical_bytes()?;
    let wire2 = plan_t4.receipt().to_canonical_bytes()?;
    assert_eq!(wire1, wire2);
    assert_eq!(&wire1[..8], &KERNEL_DISPATCH_WIRE_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire1[8], wire1[9], wire1[10], wire1[11]]),
        KERNEL_DISPATCH_WIRE_VERSION
    );
    assert_eq!(
        KernelDispatchDecisionReceipt::from_canonical_bytes(&wire1)?,
        *plan_t1.receipt()
    );

    emit_caplog(
        "fss_141_detector_static_dispatch_and_receipt",
        "thread_invariant_0ulp_verified_static_dispatch_and_fsskdr01_roundtrip",
        "thread_invariant_0ulp_verified_static_dispatch_and_fsskdr01_roundtrip",
        "pass",
    );
    Ok(())
}

#[test]
fn hybrid_fallback_strict_refusal_cancel_budget_and_hostile_wire_fail_closed() -> TestResult {
    // Build a graph containing `Gelu` (which intentionally routes to scalar-reference-node.v1).
    let g = Generation(9);
    let shape = Shape::new(vec![1, 4, 4])?;
    let graph = ModelIrGraph::new_validated(
        "hybrid_gelu_graph",
        ModelIrVersion::V2,
        g,
        vec![TensorPort::new("x", DType::F32, shape.clone(), g)?],
        vec![TensorPort::new("y", DType::F32, shape.clone(), g)?],
        vec![
            GraphNode::new(
                "relu_0",
                OpCode::Relu,
                "relu",
                vec!["x".into()],
                vec!["h".into()],
                AttributeMap::new(),
            )?,
            GraphNode::new(
                "gelu_1",
                OpCode::Gelu,
                "gelu",
                vec!["h".into()],
                vec!["y".into()],
                AttributeMap::new(),
            )?,
        ],
    )?;

    let cx = ScalarExecCx::new();
    let constants = BTreeMap::new();

    // 1. Strict `allow_scalar_fallback == false` MUST fail closed on `Gelu`!
    let strict_policy = KernelDispatchPolicy {
        allow_scalar_fallback: false,
        ..KernelDispatchPolicy::default()
    };
    assert_eq!(
        StaticKernelDispatcher::compile(&graph, &constants, strict_policy, &cx).unwrap_err(),
        KernelDispatchError::ScalarFallbackForbidden {
            node_id: "gelu_1".to_owned(),
            op_stable_id: "OP-GELU-001".to_owned(),
            reason: DispatchFallbackReason::OperatorUsesScalarOracle,
        }
    );

    // 2. Hybrid `allow_scalar_fallback == true` explicitly records StaticHybridWithScalarFallback!
    let hybrid_policy = KernelDispatchPolicy {
        allow_scalar_fallback: true,
        verify_against_scalar_oracle: true,
        ..KernelDispatchPolicy::default()
    };
    let hybrid = StaticKernelDispatcher::compile(&graph, &constants, hybrid_policy, &cx)?;
    assert_eq!(
        hybrid.receipt().outcome_state,
        DispatchOutcomeState::StaticHybridWithScalarFallback
    );
    assert_eq!(hybrid.receipt().fallback_node_count, 1);
    assert_eq!(
        hybrid.receipt().decisions[1].fallback_reason,
        Some(DispatchFallbackReason::OperatorUsesScalarOracle)
    );

    let x_vals: Vec<f32> = (0..16).map(|i| (i as f32 - 8.0) * 0.25).collect();
    let x = Tensor::from_values(shape, &x_vals, g)?;
    let out = hybrid.execute(&[("x", x)], ExecBudget::unlimited(), &cx)?;
    assert!(out.oracle_bit_exact_verified);

    // 3. Invalid alignment, tiny scratch budget, and cooperative cancellation fail closed!
    let bad_align = KernelDispatchPolicy {
        alignment_bytes: 24,
        ..hybrid_policy
    };
    assert!(matches!(
        StaticKernelDispatcher::compile(&graph, &constants, bad_align, &cx),
        Err(KernelDispatchError::InvalidPolicy(_))
    ));
    let tiny_budget = KernelDispatchPolicy {
        scratch_budget: ScratchPlanBudget::new(16, 0, 16),
        ..hybrid_policy
    };
    assert!(matches!(
        StaticKernelDispatcher::compile(&graph, &constants, tiny_budget, &cx),
        Err(KernelDispatchError::ScratchPlan(_))
    ));
    let cancelled_cx = ScalarExecCx::new();
    cancelled_cx.request_cancellation();
    assert_eq!(
        StaticKernelDispatcher::compile(&graph, &constants, hybrid_policy, &cancelled_cx)
            .unwrap_err(),
        KernelDispatchError::Cancelled
    );

    // 4. Hostile wire decoding on `FSSKDR01`: bad magic, bad version, truncation, bit-flip, trailing byte!
    let wire = hybrid.receipt().to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        KernelDispatchDecisionReceipt::from_canonical_bytes(&bad_magic),
        Err(KernelDispatchError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&7_u32.to_be_bytes());
    assert_eq!(
        KernelDispatchDecisionReceipt::from_canonical_bytes(&bad_ver),
        Err(KernelDispatchError::UnsupportedVersion { version: 7 })
    );
    assert!(matches!(
        KernelDispatchDecisionReceipt::from_canonical_bytes(&wire[..wire.len() - 4]),
        Err(KernelDispatchError::MalformedWire(_))
    ));
    let mut flipped = wire.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    assert_eq!(
        KernelDispatchDecisionReceipt::from_canonical_bytes(&flipped),
        Err(KernelDispatchError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0x99);
    assert!(matches!(
        KernelDispatchDecisionReceipt::from_canonical_bytes(&trailing),
        Err(KernelDispatchError::MalformedWire(_))
    ));

    emit_caplog(
        "fss_141_hybrid_fallback_and_faults",
        "strict_fallback_refusal_hybrid_receipt_budget_cancel_and_wire_verified",
        "strict_fallback_refusal_hybrid_receipt_budget_cancel_and_wire_verified",
        "pass",
    );
    Ok(())
}
