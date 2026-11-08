#![forbid(unsafe_code)]
//! Native execution contracts for Model IR v2 Sqrt/Erf, including the exact
//! production scalar, planned scalar and optimized backends. No surrogate kernel.

use std::collections::BTreeMap;

use fss_core::Generation;
use fss_model_ir::{
    AttributeMap, GraphNode, MemoryPlanLimits, ModelIrGraph, ModelIrVersion, OpCode, TensorPort,
};
use fss_tensor::{DType, Shape, Tensor};

#[path = "../../fss-reference/src/scalar_executor.rs"]
pub mod scalar_executor;
pub use scalar_executor::{
    ExecBudget, ExecError, ExecOutcome, ScalarExecCx, ScalarExecutor, deterministic_sigmoid_f32,
};
#[path = "../../fss-reference/src/optimized_executor.rs"]
pub mod optimized_executor;
#[path = "../../fss-reference/src/planned_scalar.rs"]
pub mod planned_scalar;

use planned_scalar::{CompiledScalarPlan, PeakExecBudget, PlannedExecError};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const GENERATION: Generation = Generation(71);

fn graph(op: OpCode, dims: &[usize]) -> Test<ModelIrGraph> {
    let shape = Shape::new(dims)?;
    Ok(ModelIrGraph::new_validated(
        "unary-math-v2",
        ModelIrVersion::V2,
        GENERATION,
        vec![TensorPort::new("x", DType::F32, shape.clone(), GENERATION)?],
        vec![TensorPort::new("y", DType::F32, shape, GENERATION)?],
        vec![GraphNode::new(
            "unary",
            op,
            "unary",
            vec!["x".into()],
            vec!["y".into()],
            AttributeMap::new(),
        )?],
    )?)
}

fn output_bits(execution: &ExecOutcome) -> Test<Vec<u32>> {
    Ok(execution
        .get_output("y")
        .ok_or("missing output")?
        .to_vec::<f32>()?
        .into_iter()
        .map(f32::to_bits)
        .collect())
}

fn exact_budget(plan: &CompiledScalarPlan) -> PeakExecBudget {
    let requirements = plan.minimum_requirements();
    PeakExecBudget::new(
        requirements.macs,
        requirements.peak_bytes,
        requirements.scratch_bytes,
    )
}

fn execute_all(graph: &ModelIrGraph, tensor: Tensor) -> Test<Vec<u32>> {
    let inputs = [("x", tensor)];
    let scalar = ScalarExecutor::run(
        graph,
        &inputs,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;
    let expected = output_bits(&scalar)?;
    let fast =
        optimized_executor::OptimizedGraph::prepare(graph, &BTreeMap::new(), &ScalarExecCx::new())?;
    let optimized = fast.run(&inputs, ExecBudget::unlimited(), &ScalarExecCx::new())?;
    let plan =
        CompiledScalarPlan::compile(graph, MemoryPlanLimits::default(), &ScalarExecCx::new())?;
    let planned = plan.run(&inputs, exact_budget(&plan), &ScalarExecCx::new())?;
    for execution in [&optimized, planned.execution()] {
        assert_eq!(expected, output_bits(execution)?);
        assert_eq!(scalar.executed_macs(), execution.executed_macs());
        assert_eq!(scalar.allocated_bytes(), execution.allocated_bytes());
        assert_eq!(scalar.nodes_executed(), execution.nodes_executed());
    }
    assert_eq!(planned.receipt().graph(), graph.content_digest()?);
    assert_eq!(planned.receipt().plan(), plan.digest());
    Ok(expected)
}

fn unary(op: OpCode, values: &[f32]) -> Test<Vec<u32>> {
    let graph = graph(op, &[values.len()])?;
    execute_all(
        &graph,
        Tensor::from_values(Shape::new(vec![values.len()])?, values, GENERATION)?,
    )
}

#[test]
fn sqrt_matches_independent_high_precision_rounding() -> Test {
    let input: Vec<_> = GOLDEN.iter().map(|row| f32::from_bits(row.0)).collect();
    let actual = unary(OpCode::Sqrt, &input)?;
    for (row, actual) in GOLDEN.iter().zip(actual) {
        assert_eq!(actual, row.2, "sqrt at input bits {:#010x}", row.0);
    }
    Ok(())
}

#[test]
fn erf_matches_independent_high_precision_values_and_odd_symmetry() -> Test {
    let input: Vec<_> = GOLDEN
        .iter()
        .flat_map(|row| [f32::from_bits(row.0), -f32::from_bits(row.0)])
        .collect();
    let actual = unary(OpCode::Erf, &input)?;
    for (row, pair) in GOLDEN.iter().zip(actual.chunks_exact(2)) {
        assert!(
            pair[0].abs_diff(row.1) <= 2,
            "erf at {:#010x}: {:#010x}, expected {:#010x}",
            row.0,
            pair[0],
            row.1,
        );
        assert_eq!(pair[0] ^ 0x8000_0000, pair[1]);
    }
    Ok(())
}

#[test]
fn unary_nonfinite_and_signed_zero_policy_is_identical_in_every_backend() -> Test {
    let input = [
        0.0,
        -0.0,
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::from_bits(0x7fa0_0001),
        f32::from_bits(0xffc0_1234),
        -1.0,
        -f32::from_bits(1),
    ];
    assert_eq!(
        unary(OpCode::Sqrt, &input)?,
        vec![
            0,
            0x8000_0000,
            0x7f80_0000,
            0x7fc0_0000,
            0x7fc0_0000,
            0x7fc0_0000,
            0x7fc0_0000,
            0x7fc0_0000
        ],
    );
    let erf = unary(OpCode::Erf, &input)?;
    assert_eq!(
        &erf[..6],
        &[
            0,
            0x8000_0000,
            0x3f80_0000,
            0xbf80_0000,
            0x7fc0_0000,
            0x7fc0_0000
        ]
    );
    assert_eq!(erf[7], 0x8000_0001);
    Ok(())
}

#[test]
fn unary_honors_strided_input_and_empty_tensor_shapes() -> Test {
    let input = Tensor::from_values(
        Shape::new(vec![2, 3])?,
        &[0.0_f32, 0.25, 1.0, 2.0, 4.0, 9.0],
        GENERATION,
    )?;
    let transposed = input.transpose(0, 1)?;
    for op in [OpCode::Sqrt, OpCode::Erf] {
        let actual = execute_all(&graph(op, &[3, 2])?, transposed.clone())?;
        assert_eq!(actual, unary(op, &[0.0, 2.0, 0.25, 4.0, 1.0, 9.0])?);
        let empty = Tensor::from_values(Shape::new(vec![2, 0, 3])?, &[] as &[f32], GENERATION)?;
        assert!(execute_all(&graph(op, &[2, 0, 3])?, empty)?.is_empty());
    }
    Ok(())
}

#[test]
fn work_and_memory_budgets_refuse_one_below_before_unary_execution() -> Test {
    for (op, work) in [(OpCode::Sqrt, 8), (OpCode::Erf, 896)] {
        let graph = graph(op, &[4])?;
        let inputs = [(
            "x",
            Tensor::from_values(Shape::new(vec![4])?, &[0.0_f32, 0.25, 1.0, 4.0], GENERATION)?,
        )];
        let exact = ExecBudget::new(work * 4, 32);
        let fast = optimized_executor::OptimizedGraph::prepare(
            &graph,
            &BTreeMap::new(),
            &ScalarExecCx::new(),
        )?;
        for budget in [
            ExecBudget::new(exact.max_macs - 1, 32),
            ExecBudget::new(exact.max_macs, 31),
        ] {
            assert!(matches!(
                ScalarExecutor::run(&graph, &inputs, budget, &ScalarExecCx::new()),
                Err(ExecError::BudgetExceeded { .. })
            ));
            assert!(matches!(
                fast.run(&inputs, budget, &ScalarExecCx::new()),
                Err(ExecError::BudgetExceeded { .. })
            ));
        }
        let scalar = ScalarExecutor::run(&graph, &inputs, exact, &ScalarExecCx::new())?;
        assert_eq!(scalar.executed_macs(), work * 4);
        assert_eq!(scalar.allocated_bytes(), 32);
        fast.run(&inputs, exact, &ScalarExecCx::new())?;
        let plan =
            CompiledScalarPlan::compile(&graph, MemoryPlanLimits::default(), &ScalarExecCx::new())?;
        let budget = exact_budget(&plan);
        for below in [
            PeakExecBudget {
                max_macs: budget.max_macs - 1,
                ..budget
            },
            PeakExecBudget {
                max_peak_bytes: budget.max_peak_bytes - 1,
                ..budget
            },
            PeakExecBudget {
                max_scratch_bytes: budget.max_scratch_bytes - 1,
                ..budget
            },
        ] {
            assert!(matches!(
                plan.run(&inputs, below, &ScalarExecCx::new()),
                Err(PlannedExecError::BudgetExceeded { .. })
            ));
        }
        plan.run(&inputs, budget, &ScalarExecCx::new())?;
    }
    Ok(())
}

#[test]
fn cancellation_drains_and_never_publishes_a_unary_result() -> Test {
    for op in [OpCode::Sqrt, OpCode::Erf] {
        let graph = graph(op, &[1])?;
        let inputs = [(
            "x",
            Tensor::from_values(Shape::new(vec![1])?, &[1.0_f32], GENERATION)?,
        )];
        let fast = optimized_executor::OptimizedGraph::prepare(
            &graph,
            &BTreeMap::new(),
            &ScalarExecCx::new(),
        )?;
        let plan =
            CompiledScalarPlan::compile(&graph, MemoryPlanLimits::default(), &ScalarExecCx::new())?;
        let cx = ScalarExecCx::new();
        cx.request_cancellation();
        assert!(matches!(
            ScalarExecutor::run(&graph, &inputs, ExecBudget::unlimited(), &cx),
            Err(ExecError::CancellationRequested { .. })
        ));
        assert!(cx.is_drain_completed());
        let cx = ScalarExecCx::new();
        cx.request_cancellation();
        assert!(matches!(
            fast.run(&inputs, ExecBudget::unlimited(), &cx),
            Err(ExecError::CancellationRequested { .. })
        ));
        assert!(cx.is_drain_completed());
        let cx = ScalarExecCx::new();
        cx.request_cancellation();
        assert!(matches!(
            plan.run(&inputs, exact_budget(&plan), &cx),
            Err(PlannedExecError::Execution(
                ExecError::CancellationRequested { .. }
            ))
        ));
        assert!(cx.is_drain_completed());
    }
    Ok(())
}

// (input bits, rounded erf bits, correctly rounded sqrt bits). Generated offline
// with mpmath 1.3.0 at 100 decimal digits from exact binary32 inputs, then rounded
// to binary32. This independent fixture includes subnormals, both sides of the
// series/tail/saturation boundaries, broad exponents, and a fixed grid on [0, 4].
const GOLDEN: &[(u32, u32, u32)] = &[
    (0x00000000, 0x00000000, 0x00000000),
    (0x00000001, 0x00000001, 0x1a3504f3),
    (0x00000002, 0x00000002, 0x1a800000),
    (0x00000003, 0x00000003, 0x1a9cc471),
    (0x00000004, 0x00000005, 0x1ab504f3),
    (0x00000007, 0x00000008, 0x1aef7751),
    (0x0000000f, 0x00000011, 0x1b2f456f),
    (0x00000010, 0x00000012, 0x1b3504f3),
    (0x000000ff, 0x00000120, 0x1c34aa5a),
    (0x00000100, 0x00000121, 0x1c3504f3),
    (0x003fffff, 0x0048375c, 0x1fb504f2),
    (0x00400000, 0x0048375d, 0x1fb504f3),
    (0x007fffff, 0x00906eb9, 0x1fffffff),
    (0x00800000, 0x00906ebb, 0x20000000),
    (0x00800001, 0x00906ebc, 0x20000000),
    (0x00923456, 0x00a4f95b, 0x2008ccbc),
    (0x05123456, 0x0524f95b, 0x224176cc),
    (0x09923456, 0x09a4f95b, 0x2488ccbc),
    (0x0e123456, 0x0e24f95b, 0x26c176cc),
    (0x12923456, 0x12a4f95b, 0x2908ccbc),
    (0x17123456, 0x1724f95b, 0x2b4176cc),
    (0x1b923456, 0x1ba4f95b, 0x2d88ccbc),
    (0x20123456, 0x2024f95b, 0x2fc176cc),
    (0x24923456, 0x24a4f95b, 0x3208ccbc),
    (0x29123456, 0x2924f95b, 0x344176cc),
    (0x2d923456, 0x2da4f95b, 0x3688ccbc),
    (0x32123456, 0x3224f95b, 0x38c176cc),
    (0x36923456, 0x36a4f95b, 0x3b08ccbc),
    (0x3b123456, 0x3b24f949, 0x3d4176cc),
    (0x3d010204, 0x3d11858d, 0x3e35bb09),
    (0x3d810204, 0x3d9160a3, 0x3e8080c1),
    (0x3dc18306, 0x3dd9b4e4, 0x3e9d6222),
    (0x3e010204, 0x3e10cda4, 0x3eb5bb09),
    (0x3e214285, 0x3e34781a, 0x3ecb2e56),
    (0x3e418306, 0x3e57c873, 0x3ede92da),
    (0x3e61c387, 0x3e7aadd6, 0x3ef06831),
    (0x3e810204, 0x3e8e8c05, 0x3f0080c1),
    (0x3e912245, 0x3e9f7bc4, 0x3f084c47),
    (0x3ea14285, 0x3eb01eca, 0x3f0fabb1),
    (0x3eb162c6, 0x3ec06e29, 0x3f16aedd),
    (0x3ec18306, 0x3ed06369, 0x3f1d6222),
    (0x3ed1a347, 0x3edff891, 0x3f23cf4d),
    (0x3ee1c387, 0x3eef2829, 0x3f29fe51),
    (0x3ef1e3c8, 0x3efded48, 0x3f2ff5bd),
    (0x3effffff, 0x3f053f7a, 0x3f3504f3),
    (0x3f000000, 0x3f053f7b, 0x3f3504f3),
    (0x3f000001, 0x3f053f7c, 0x3f3504f4),
    (0x3f010204, 0x3f0621c6, 0x3f35bb09),
    (0x3f091224, 0x3f0d1393, 0x3f3b52d9),
    (0x3f112245, 0x3f13ca6e, 0x3f40c122),
    (0x3f193265, 0x3f1a44fd, 0x3f46094e),
    (0x3f214285, 0x3f208233, 0x3f4b2e56),
    (0x3f2952a5, 0x3f268149, 0x3f5032d5),
    (0x3f3162c6, 0x3f2c41bd, 0x3f551919),
    (0x3f3972e6, 0x3f31c351, 0x3f59e32a),
    (0x3f418306, 0x3f370606, 0x3f5e92da),
    (0x3f499326, 0x3f3c0a1f, 0x3f6329cc),
    (0x3f51a347, 0x3f40d017, 0x3f67a978),
    (0x3f59b367, 0x3f4558a2, 0x3f6c1333),
    (0x3f61c387, 0x3f49a4a7, 0x3f706831),
    (0x3f69d3a7, 0x3f4db53e, 0x3f74a98e),
    (0x3f71e3c8, 0x3f518ba9, 0x3f78d84b),
    (0x3f79f3e8, 0x3f552951, 0x3f7cf554),
    (0x3f7fffff, 0x3f57bb3d, 0x3f7fffff),
    (0x3f800000, 0x3f57bb3d, 0x3f800000),
    (0x3f800001, 0x3f57bb3e, 0x3f800000),
    (0x3f810204, 0x3f588fc4, 0x3f8080c1),
    (0x3f850a14, 0x3f5bc0ae, 0x3f827ed0),
    (0x3f891224, 0x3f5ebdd4, 0x3f847533),
    (0x3f8d1a34, 0x3f618913, 0x3f866440),
    (0x3f912245, 0x3f642459, 0x3f884c47),
    (0x3f923456, 0x3f64cdbc, 0x3f88ccbc),
    (0x3f952a55, 0x3f6691a1, 0x3f8a2d93),
    (0x3f993265, 0x3f68d2f2, 0x3f8c0868),
    (0x3f9d3a75, 0x3f6aea58, 0x3f8ddd09),
    (0x3fa14285, 0x3f6cd9e2, 0x3f8fabb1),
    (0x3fa54a95, 0x3f6ea39f, 0x3f917499),
    (0x3fa952a5, 0x3f70499b, 0x3f9337f8),
    (0x3fad5ab5, 0x3f71cddb, 0x3f94f5fe),
    (0x3fb162c6, 0x3f73325e, 0x3f96aedd),
    (0x3fb56ad6, 0x3f747913, 0x3f9862c1),
    (0x3fb972e6, 0x3f75a3e3, 0x3f9a11d3),
    (0x3fbd7af6, 0x3f76b4a3, 0x3f9bbc3c),
    (0x3fc18306, 0x3f77ad1c, 0x3f9d6222),
    (0x3fc58b16, 0x3f788f03, 0x3f9f03a8),
    (0x3fc99326, 0x3f795bfe, 0x3fa0a0f1),
    (0x3fcd9b36, 0x3f7a159e, 0x3fa23a1e),
    (0x3fd1a347, 0x3f7abd62, 0x3fa3cf4d),
    (0x3fd5ab57, 0x3f7b54b4, 0x3fa5609a),
    (0x3fd9b367, 0x3f7bdcec, 0x3fa6ee23),
    (0x3fddbb77, 0x3f7c574e, 0x3fa87802),
    (0x3fe1c387, 0x3f7cc50a, 0x3fa9fe51),
    (0x3fe5cb97, 0x3f7d273c, 0x3fab8127),
    (0x3fe9d3a7, 0x3f7d7eef, 0x3fad009c),
    (0x3feddbb7, 0x3f7dcd1a, 0x3fae7cc7),
    (0x3ff1e3c8, 0x3f7e12a2, 0x3faff5bd),
    (0x3ff5ebd8, 0x3f7e505d, 0x3fb16b91),
    (0x3ff9f3e8, 0x3f7e870f, 0x3fb2de58),
    (0x3ffdfbf8, 0x3f7eb76d, 0x3fb44e25),
    (0x3fffffff, 0x3f7ecd71, 0x3fb504f3),
    (0x40000000, 0x3f7ecd71, 0x3fb504f3),
    (0x40000001, 0x3f7ecd71, 0x3fb504f4),
    (0x40010204, 0x3f7ee21c, 0x3fb5bb09),
    (0x4003060c, 0x3f7f07b4, 0x3fb72517),
    (0x40050a14, 0x3f7f28c0, 0x3fb88c5e),
    (0x40070e1c, 0x3f7f45be, 0x3fb9f0ef),
    (0x40091224, 0x3f7f5f20, 0x3fbb52d9),
    (0x400b162c, 0x3f7f754f, 0x3fbcb22c),
    (0x400d1a34, 0x3f7f88a6, 0x3fbe0ef5),
    (0x400f1e3c, 0x3f7f997c, 0x3fbf6942),
    (0x40112245, 0x3f7fa81c, 0x3fc0c122),
    (0x4013264d, 0x3f7fb4c9, 0x3fc216a0),
    (0x40152a55, 0x3f7fbfc1, 0x3fc369ca),
    (0x40172e5d, 0x3f7fc93a, 0x3fc4baaa),
    (0x40193265, 0x3f7fd163, 0x3fc6094e),
    (0x401b366d, 0x3f7fd868, 0x3fc755c0),
    (0x401d3a75, 0x3f7fde6f, 0x3fc8a00b),
    (0x401f3e7d, 0x3f7fe398, 0x3fc9e83a),
    (0x40214285, 0x3f7fe802, 0x3fcb2e56),
    (0x4023468d, 0x3f7febc5, 0x3fcc726b),
    (0x40254a95, 0x3f7feefa, 0x3fcdb480),
    (0x40274e9d, 0x3f7ff1b4, 0x3fcef4a1),
    (0x402952a5, 0x3f7ff404, 0x3fd032d5),
    (0x402b56ad, 0x3f7ff5f8, 0x3fd16f26),
    (0x402d5ab5, 0x3f7ff7a0, 0x3fd2a99c),
    (0x402f5ebd, 0x3f7ff904, 0x3fd3e240),
    (0x403162c6, 0x3f7ffa31, 0x3fd51919),
    (0x403366ce, 0x3f7ffb2d, 0x3fd64e2f),
    (0x40356ad6, 0x3f7ffc00, 0x3fd78189),
    (0x40376ede, 0x3f7ffcb1, 0x3fd8b330),
    (0x403972e6, 0x3f7ffd44, 0x3fd9e32a),
    (0x403b76ee, 0x3f7ffdbf, 0x3fdb117e),
    (0x403d7af6, 0x3f7ffe26, 0x3fdc3e33),
    (0x403f7efe, 0x3f7ffe7b, 0x3fdd694f),
    (0x40418306, 0x3f7ffec1, 0x3fde92da),
    (0x4043870e, 0x3f7ffefb, 0x3fdfbad9),
    (0x40458b16, 0x3f7fff2b, 0x3fe0e152),
    (0x40478f1e, 0x3f7fff52, 0x3fe2064c),
    (0x40499326, 0x3f7fff73, 0x3fe329cc),
    (0x404b972e, 0x3f7fff8d, 0x3fe44bd7),
    (0x404d9b36, 0x3f7fffa3, 0x3fe56c74),
    (0x404f9f3e, 0x3f7fffb5, 0x3fe68ba8),
    (0x4051a347, 0x3f7fffc3, 0x3fe7a978),
    (0x4053a74f, 0x3f7fffcf, 0x3fe8c5e9),
    (0x4055ab57, 0x3f7fffd9, 0x3fe9e100),
    (0x4057af5f, 0x3f7fffe0, 0x3feafac1),
    (0x4059b367, 0x3f7fffe7, 0x3fec1333),
    (0x405bb76f, 0x3f7fffec, 0x3fed2a59),
    (0x405dbb77, 0x3f7ffff0, 0x3fee4037),
    (0x405fbf7f, 0x3f7ffff3, 0x3fef54d3),
    (0x4061c387, 0x3f7ffff6, 0x3ff06831),
    (0x4063c78f, 0x3f7ffff8, 0x3ff17a55),
    (0x4065cb97, 0x3f7ffffa, 0x3ff28b43),
    (0x4067cf9f, 0x3f7ffffb, 0x3ff39b00),
    (0x4069d3a7, 0x3f7ffffc, 0x3ff4a98e),
    (0x406bd7af, 0x3f7ffffd, 0x3ff5b6f3),
    (0x406ddbb7, 0x3f7ffffe, 0x3ff6c331),
    (0x406fdfbf, 0x3f7ffffe, 0x3ff7ce4d),
    (0x4071e3c8, 0x3f7ffffe, 0x3ff8d84b),
    (0x4073e7d0, 0x3f7fffff, 0x3ff9e12d),
    (0x4075ebd8, 0x3f7fffff, 0x3ffae8f8),
    (0x4077efe0, 0x3f7fffff, 0x3ffbefae),
    (0x4079f3e8, 0x3f7fffff, 0x3ffcf554),
    (0x407bf7f0, 0x3f800000, 0x3ffdf9ec),
    (0x407dfbf8, 0x3f800000, 0x3ffefd79),
    (0x407fffff, 0x3f800000, 0x3fffffff),
    (0x40800000, 0x3f800000, 0x40000000),
    (0x40800001, 0x3f800000, 0x40000000),
    (0x44123456, 0x3f800000, 0x41c176cc),
    (0x48923456, 0x3f800000, 0x4408ccbc),
    (0x4d123456, 0x3f800000, 0x464176cc),
    (0x51923456, 0x3f800000, 0x4888ccbc),
    (0x56123456, 0x3f800000, 0x4ac176cc),
    (0x5a923456, 0x3f800000, 0x4d08ccbc),
    (0x5f123456, 0x3f800000, 0x4f4176cc),
    (0x63923456, 0x3f800000, 0x5188ccbc),
    (0x68123456, 0x3f800000, 0x53c176cc),
    (0x6c923456, 0x3f800000, 0x5608ccbc),
    (0x71123456, 0x3f800000, 0x584176cc),
    (0x75923456, 0x3f800000, 0x5a88ccbc),
    (0x7a123456, 0x3f800000, 0x5cc176cc),
    (0x7e923456, 0x3f800000, 0x5f08ccbc),
    (0x7f7fffff, 0x3f800000, 0x5f7fffff),
];
