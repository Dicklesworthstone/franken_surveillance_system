#![forbid(unsafe_code)]
//! FSS-073 property family: model invocation quotas and memory-pressure
//! admission. Each property emits one JSONL verdict line.

use fss_core::{ContentDigest, Generation, ResourcePressure};
use fss_model_ir::graph::ModelIrGraph;
use fss_model_ir::invocation::{
    InputBinding, InvocationError, InvocationOutcome, ModelInvocationSpec,
};
use fss_model_ir::node::GraphNode;
use fss_model_ir::op::OpCode;
use fss_model_ir::port::TensorPort;
use fss_model_ir::quotas::{InvocationQuota, InvocationQuotaLedger, MemoryAdmission, QuotaError};
use fss_tensor::{DType, Shape};

fn emit(property: &str, cases: u64) {
    println!(
        "{{\"family\":\"FSS-073\",\"property\":\"{property}\",\"cases\":{cases},\"verdict\":\"pass\"}}"
    );
}

fn port(name: &str) -> Result<TensorPort, Box<dyn std::error::Error>> {
    Ok(TensorPort::new(
        name,
        DType::F32,
        Shape::new(vec![2])?,
        Generation::GENESIS,
    )?)
}

fn graph() -> Result<ModelIrGraph, Box<dyn std::error::Error>> {
    let add = GraphNode::new(
        "n-add",
        OpCode::Add,
        "add",
        vec!["x".to_string(), "y".to_string()],
        vec!["sum".to_string()],
        Default::default(),
    )?;
    let relu = GraphNode::new(
        "n-relu",
        OpCode::Relu,
        "relu",
        vec!["sum".to_string()],
        vec!["out".to_string()],
        Default::default(),
    )?;
    Ok(ModelIrGraph::builder("graph:quota", Generation::GENESIS)
        .add_input(port("x")?)
        .add_input(port("y")?)
        .add_output(port("out")?)
        .add_node(add)
        .add_node(relu)
        .build_and_validate()?)
}

fn spec(model_root: ContentDigest) -> ModelInvocationSpec {
    ModelInvocationSpec {
        model_root,
        preprocess_generation: Generation::GENESIS,
        calibration_generation: None,
        inputs: vec![
            InputBinding {
                name: "x".to_string(),
                digest: ContentDigest::sha256(b"x"),
                generation: Generation::GENESIS,
                declared_bytes: Some(8),
            },
            InputBinding {
                name: "y".to_string(),
                digest: ContentDigest::sha256(b"y"),
                generation: Generation::GENESIS,
                declared_bytes: Some(8),
            },
        ],
        max_nodes: 100,
    }
}

fn model_a() -> ContentDigest {
    ContentDigest::sha256(b"model-a")
}

fn model_b() -> ContentDigest {
    ContentDigest::sha256(b"model-b")
}

/// P1 INVOCATION QUOTA: the count budget refuses the N+1st invocation with
/// the exact usage named; a refused prepare debits nothing.
#[test]
fn p1_invocation_count_quota() -> Result<(), Box<dyn std::error::Error>> {
    let graph = graph()?;
    let mut ledger = InvocationQuotaLedger::new(
        InvocationQuota {
            max_invocations: 2,
            max_total_nodes: u64::MAX,
        },
        MemoryAdmission::AdmitAlways,
    );
    for i in 0..2 {
        let prepared = ledger.prepare(&graph, &spec(model_a()), ResourcePressure::Nominal)?;
        ledger.execute_and_debit(&graph, &prepared, fss_core::TimestampNs(i))?;
    }
    assert_eq!(ledger.usage(model_a()), (2, 4));
    let err = ledger
        .prepare(&graph, &spec(model_a()), ResourcePressure::Nominal)
        .err()
        .and_then(|e| e.quota_cause().cloned());
    assert_eq!(
        err,
        Some(QuotaError::InvocationsExhausted {
            model_root: model_a(),
            used: 2,
            maximum: 2,
        })
    );
    assert_eq!(ledger.usage(model_a()), (2, 4), "refusal debits nothing");
    emit("invocation-count-quota", 3);
    Ok(())
}

/// P2 NODE-WORK QUOTA: the cumulative node budget refuses further work
/// with the exact node usage named, even under remaining invocation count.
#[test]
fn p2_node_work_quota() -> Result<(), Box<dyn std::error::Error>> {
    let graph = graph()?;
    let mut ledger = InvocationQuotaLedger::new(
        InvocationQuota {
            max_invocations: u64::MAX,
            max_total_nodes: 3,
        },
        MemoryAdmission::AdmitAlways,
    );
    let prepared = ledger.prepare(&graph, &spec(model_a()), ResourcePressure::Nominal)?;
    ledger.execute_and_debit(&graph, &prepared, fss_core::TimestampNs(0))?;
    assert_eq!(ledger.usage(model_a()), (1, 2));
    // Second invocation would exceed the node budget (2 used + 2 > 3).
    let err = ledger
        .prepare(&graph, &spec(model_a()), ResourcePressure::Nominal)
        .err()
        .and_then(|e| e.quota_cause().cloned());
    assert!(matches!(
        err,
        Some(QuotaError::NodeWorkExhausted {
            used: 2,
            maximum: 3,
            ..
        })
    ));
    emit("node-work-quota", 2);
    Ok(())
}

/// P3 PRESSURE ADMISSION: the policy ladder refuses under constrained/
/// critical pressure with the level named; nominal always admits; the
/// conservative default refuses everything above nominal.
#[test]
fn p3_memory_pressure_admission() -> Result<(), Box<dyn std::error::Error>> {
    let graph = graph()?;
    let mut ledger = InvocationQuotaLedger::new(
        InvocationQuota {
            max_invocations: u64::MAX,
            max_total_nodes: u64::MAX,
        },
        MemoryAdmission::NominalOnly,
    );
    assert!(
        ledger
            .prepare(&graph, &spec(model_a()), ResourcePressure::Nominal)
            .is_ok()
    );
    for pressure in [
        ResourcePressure::Elevated,
        ResourcePressure::Constrained,
        ResourcePressure::Critical,
    ] {
        let err = ledger
            .prepare(&graph, &spec(model_a()), pressure)
            .err()
            .and_then(|e| e.quota_cause().cloned());
        assert!(matches!(
            err,
            Some(QuotaError::PressureRefused { pressure: p, .. }) if p == pressure
        ));
    }
    // RefuseConstrained admits elevated but not constrained/critical.
    let mut relaxed = InvocationQuotaLedger::new(
        InvocationQuota {
            max_invocations: u64::MAX,
            max_total_nodes: u64::MAX,
        },
        MemoryAdmission::RefuseConstrained,
    );
    assert!(
        relaxed
            .prepare(&graph, &spec(model_a()), ResourcePressure::Elevated)
            .is_ok()
    );
    assert!(
        relaxed
            .prepare(&graph, &spec(model_a()), ResourcePressure::Constrained)
            .is_err()
    );
    emit("memory-pressure-admission", 6);
    Ok(())
}

/// P4 PER-MODEL ISOLATION: exhausting one model's quota never affects a
/// different model identity.
#[test]
fn p4_quotas_are_per_model() -> Result<(), Box<dyn std::error::Error>> {
    let graph = graph()?;
    let mut ledger = InvocationQuotaLedger::new(
        InvocationQuota {
            max_invocations: 1,
            max_total_nodes: u64::MAX,
        },
        MemoryAdmission::AdmitAlways,
    );
    let prepared = ledger.prepare(&graph, &spec(model_a()), ResourcePressure::Nominal)?;
    ledger.execute_and_debit(&graph, &prepared, fss_core::TimestampNs(0))?;
    assert!(
        ledger
            .prepare(&graph, &spec(model_a()), ResourcePressure::Nominal)
            .is_err()
    );
    let other = ledger.prepare(&graph, &spec(model_b()), ResourcePressure::Nominal)?;
    ledger.execute_and_debit(&graph, &other, fss_core::TimestampNs(1))?;
    assert_eq!(ledger.usage(model_b()), (1, 2));
    emit("per-model-isolation", 2);
    Ok(())
}

/// P5 UNCOUNTED OUTCOMES: abstained/quarantined executions do not consume
/// the invocation-count budget (uncertainty is not work) — via the
/// receipt helper over every outcome class.
#[test]
fn p5_uncertain_outcomes_free() -> Result<(), Box<dyn std::error::Error>> {
    use fss_model_ir::invocation::{execute, prepare};
    let graph = graph()?;
    // Completed counts.
    let good = execute(&graph, &prepare(&graph, &spec(model_a()))?)?;
    assert!(good.outcome_is_counted());
    // Quarantined does not (invalid graph).
    let bad_node = GraphNode::new(
        "n-add",
        OpCode::Add,
        "add",
        vec!["x".to_string(), "y".to_string()],
        vec!["wrong".to_string()],
        Default::default(),
    )?;
    let bad_graph = ModelIrGraph::builder("graph:bad", Generation::GENESIS)
        .add_input(port("x")?)
        .add_input(port("y")?)
        .add_output(port("out")?)
        .add_node(bad_node)
        .build()?;
    let quarantined = execute(&bad_graph, &prepare(&bad_graph, &spec(model_a()))?)?;
    assert!(matches!(
        quarantined.outcome,
        InvocationOutcome::Quarantined { .. }
    ));
    assert!(!quarantined.outcome_is_counted());
    emit("uncertain-outcomes-free", 2);
    Ok(())
}

/// P6 WOULD-ADMIT PURITY: the check is a pure function (no mutation, no
/// side effects on later admissions).
#[test]
fn p6_would_admit_is_pure() -> Result<(), Box<dyn std::error::Error>> {
    let graph = graph()?;
    let mut ledger = InvocationQuotaLedger::new(
        InvocationQuota {
            max_invocations: 1,
            max_total_nodes: u64::MAX,
        },
        MemoryAdmission::AdmitAlways,
    );
    assert!(ledger.would_admit(model_a(), ResourcePressure::Nominal));
    assert!(
        ledger.would_admit(model_a(), ResourcePressure::Nominal),
        "repeat checks mutate nothing"
    );
    let prepared = ledger.prepare(&graph, &spec(model_a()), ResourcePressure::Nominal)?;
    ledger.execute_and_debit(&graph, &prepared, fss_core::TimestampNs(0))?;
    assert!(!ledger.would_admit(model_a(), ResourcePressure::Nominal));
    let _ = InvocationError::Digest("x".into());
    emit("would-admit-purity", 3);
    Ok(())
}
