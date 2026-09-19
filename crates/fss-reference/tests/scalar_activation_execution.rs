#![forbid(unsafe_code)]
//! Numerical and integration contracts for the public scalar activation path.

use fss_core::Generation;
use fss_model_ir::{AttrValue, AttributeMap, GraphNode, ModelIrGraph, ModelIrVersion, OpCode, TensorPort};
use fss_reference::{ExecBudget, ExecError, ExecOutcome, ScalarExecCx, ScalarExecutor};
use fss_tensor::{DType, Shape, Tensor};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const GEN: Generation = Generation(9);
fn attrs(mode: Option<&str>) -> AttributeMap {
    mode.map(|s| AttributeMap::from([("approximate".into(),AttrValue::String(s.into()))]))
        .unwrap_or_default()
}
fn graph(op: OpCode, dims: &[usize], mode: Option<&str>) -> Result<ModelIrGraph, ExecError> {
    let shape = Shape::new(dims.to_vec())?;
    Ok(ModelIrGraph::new_validated("activation-test",ModelIrVersion::V1,GEN,
        vec![TensorPort::new("x",DType::F32,shape.clone(),GEN)?],
        vec![TensorPort::new("out",DType::F32,shape,GEN)?],
        vec![GraphNode::new("a",op,"activation",vec!["x".into()],vec!["out".into()],attrs(mode))?])?)
}
fn run(op: OpCode, data: &[f32], mode: Option<&str>, budget: ExecBudget) -> Result<ExecOutcome, ExecError> {
    let graph = graph(op,&[data.len()],mode)?;
    let input = Tensor::from_values(Shape::new(vec![data.len()])?,data,GEN)?;
    ScalarExecutor::run(&graph,&[("x",input)],budget,&ScalarExecCx::new())
}
fn values(result: &ExecOutcome) -> Result<Vec<f32>,Box<dyn std::error::Error>> {
    Ok(result.get_output("out").ok_or("missing output")?.to_vec::<f32>()?)
}
fn ulp_close(actual: &[f32], expected: &[f64]) {
    assert_eq!(actual.len(),expected.len());
    for (&a,&b) in actual.iter().zip(expected) {
        let b = b as f32;
        assert!(a.is_finite() && b.is_finite());
        assert_eq!(a.is_sign_negative(),b.is_sign_negative(),"{a} != {b}");
        assert!(a.to_bits().abs_diff(b.to_bits()) <= 2,"{a} != {b}: more than two ulps");
    }
}

// Golden values generated independently with SciPy normal CDF/logistic and NumPy tanh,
// at the exact binary32 inputs converted to binary64. They are not a copy of the kernel.
const INPUT: &[f32] = &[-15.0,-10.0,-8.0,-6.0,-4.0,-3.0,-2.0,-1.0,-0.5,-9.999999747378752e-05,-9.99999993922529e-09,0.0,9.99999993922529e-09,0.5,1.0,2.0,3.0,4.0,8.0,15.0];

#[test]
fn silu_matches_independent_golden_values() -> TestResult {
    let expected: &[f64] = &[
        -4.58853340388437051e-06,
        -4.53978687024343946e-04,
        -2.68280104373182487e-03,
        -1.48357389398086452e-02,
        -7.19448398483662349e-02,
        -1.42277619532700350e-01,
        -2.38405844044235093e-01,
        -2.68941421369995104e-01,
        -1.88770334399072703e-01,
        -4.99974987370221493e-05,
        -4.99999994461264555e-09,
        0.00000000000000000e+00,
        4.99999999461264474e-09,
        3.11229665600927297e-01,
        7.31058578630004896e-01,
        1.76159415595576463e+00,
        2.85772238046730020e+00,
        3.92805516015163381e+00,
        7.99731719895626902e+00,
        1.49999954114665943e+01,
    ];
    let r = run(OpCode::Silu,INPUT,None,ExecBudget::unlimited())?;
    ulp_close(&values(&r)?,expected);
    Ok(())
}

#[test]
fn tanh_matches_independent_golden_values() -> TestResult {
    let expected: &[f64] = &[
        -9.99999999999812816e-01,
        -9.99999995877692727e-01,
        -9.99999774929675844e-01,
        -9.99987711650795585e-01,
        -9.99329299739067034e-01,
        -9.95054753686730464e-01,
        -9.64027580075816903e-01,
        -7.61594155955764851e-01,
        -4.62117157260009737e-01,
        -9.99999971404542069e-05,
        -9.99999993922529029e-09,
        0.00000000000000000e+00,
        9.99999993922529029e-09,
        4.62117157260009737e-01,
        7.61594155955764851e-01,
        9.64027580075816903e-01,
        9.95054753686730464e-01,
        9.99329299739067034e-01,
        9.99999774929675844e-01,
        9.99999999999812816e-01,
    ];
    let r = run(OpCode::Tanh,INPUT,None,ExecBudget::unlimited())?;
    ulp_close(&values(&r)?,expected);
    Ok(())
}

#[test]
fn gelu_default_matches_independent_golden_values() -> TestResult {
    let expected: &[f64] = &[
        -5.50644929896904767e-50,
        -7.61985302416046991e-23,
        -4.97676845941739239e-15,
        -5.91952587022616704e-09,
        -1.26684967332479453e-04,
        -4.04969409489028005e-03,
        -4.55002638963583894e-02,
        -1.58655253931457074e-01,
        -1.54268769362993441e-01,
        -4.99960093142979566e-05,
        -4.99999992971841738e-09,
        0.00000000000000000e+00,
        5.00000000950687291e-09,
        3.45731230637006559e-01,
        8.41344746068542926e-01,
        1.95449973610364158e+00,
        2.99595030590510980e+00,
        3.99987331503266752e+00,
        7.99999999999999467e+00,
        1.50000000000000000e+01,
    ];
    let r = run(OpCode::Gelu,INPUT,None,ExecBudget::unlimited())?;
    ulp_close(&values(&r)?,expected);
    Ok(())
}

#[test]
fn gelu_tanh_matches_independent_golden_values() -> TestResult {
    let expected: &[f64] = &[
        -1.55847699372738710e-114,
        -1.20409234820980233e-37,
        -3.10778293750111307e-21,
        -8.43964670076231124e-11,
        -7.02459481923726570e-05,
        -3.63739208177301905e-03,
        -4.54023059122249661e-02,
        -1.58808009391723265e-01,
        -1.54285990174856086e-01,
        -4.99960093142979905e-05,
        -4.99999992971841821e-09,
        0.00000000000000000e+00,
        5.00000000950687291e-09,
        3.45714009825143942e-01,
        8.41191990608276763e-01,
        1.95459769408777517e+00,
        2.99636260791822728e+00,
        3.99992975405180751e+00,
        8.00000000000000000e+00,
        1.50000000000000000e+01,
    ];
    let r = run(OpCode::Gelu,INPUT,Some("tanh"),ExecBudget::unlimited())?;
    ulp_close(&values(&r)?,expected);
    Ok(())
}

#[test]
fn gelu_default_and_none_are_identical_but_tanh_mode_is_distinct() -> TestResult {
    let x = [-3_f32,-1.,0.,1.,3.];
    let implicit = run(OpCode::Gelu,&x,None,ExecBudget::unlimited())?;
    let explicit = run(OpCode::Gelu,&x,Some("none"),ExecBudget::unlimited())?;
    let approximate = run(OpCode::Gelu,&x,Some("tanh"),ExecBudget::unlimited())?;
    assert_eq!(values(&implicit)?,values(&explicit)?);
    assert_ne!(values(&implicit)?,values(&approximate)?);
    assert_eq!(graph(OpCode::Gelu,&[5],None)?.content_digest()?,graph(OpCode::Gelu,&[5],Some("none"))?.content_digest()?);
    Ok(())
}

#[test]
fn signed_zero_and_tanh_subnormals_are_preserved() -> TestResult {
    for (op,mode) in [(OpCode::Silu,None),(OpCode::Tanh,None),(OpCode::Gelu,None),(OpCode::Gelu,Some("tanh"))] {
        let r = values(&run(op,&[0.,-0.],mode,ExecBudget::unlimited())?)?;
        assert_eq!(r[0].to_bits(),0); assert_eq!(r[1].to_bits(),0x8000_0000);
    }
    let tiny = f32::from_bits(1);
    let r = values(&run(OpCode::Tanh,&[tiny,-tiny,1e-10,-1e-10],None,ExecBudget::unlimited())?)?;
    assert_eq!(r,vec![tiny,-tiny,1e-10,-1e-10]);
    Ok(())
}

#[test]
fn large_finite_values_saturate_without_intermediate_overflow() -> TestResult {
    for op in [OpCode::Silu,OpCode::Gelu] {
        let r = values(&run(op,&[-f32::MAX,f32::MAX],None,ExecBudget::unlimited())?)?;
        assert_eq!(r[0].to_bits(),0x8000_0000); assert_eq!(r[1],f32::MAX);
    }
    let r = values(&run(OpCode::Gelu,&[-f32::MAX,f32::MAX],Some("tanh"),ExecBudget::unlimited())?)?;
    assert_eq!(r[0].to_bits(),0x8000_0000); assert_eq!(r[1],f32::MAX);
    assert_eq!(values(&run(OpCode::Tanh,&[-f32::MAX,f32::MAX],None,ExecBudget::unlimited())?)?,vec![-1.,1.]);
    // A float32 exp(-105) would underflow before multiplication, losing this tail.
    let r = values(&run(OpCode::Silu,&[-105.],None,ExecBudget::unlimited())?)?;
    ulp_close(&r,&[-2.63189584969495076e-44]);
    Ok(())
}

#[test]
fn nonfinite_propagation_is_explicit_and_canonical() -> TestResult {
    for (op,mode) in [(OpCode::Silu,None),(OpCode::Gelu,None),(OpCode::Gelu,Some("tanh"))] {
        let r = values(&run(op,&[f32::NEG_INFINITY,f32::INFINITY,f32::from_bits(0xffc0_0123)],mode,ExecBudget::unlimited())?)?;
        assert_eq!(r[0].to_bits(),0x7fc0_0000); assert_eq!(r[1],f32::INFINITY);
        assert_eq!(r[2].to_bits(),0x7fc0_0000);
    }
    let r = values(&run(OpCode::Tanh,&[f32::NEG_INFINITY,f32::INFINITY,f32::NAN],None,ExecBudget::unlimited())?)?;
    assert_eq!(&r[..2],&[-1.,1.]); assert_eq!(r[2].to_bits(),0x7fc0_0000);
    Ok(())
}

#[test]
fn exact_work_and_byte_limits_apply_to_each_formula() -> TestResult {
    for (op,mode,cost) in [(OpCode::Silu,None,80),(OpCode::Tanh,None,80),
        (OpCode::Gelu,None,896),(OpCode::Gelu,Some("tanh"),96)] {
        let r = run(op,&[-1.,1.],mode,ExecBudget::new(2*cost,16))?;
        assert_eq!(r.executed_macs(),2*cost); assert_eq!(r.allocated_bytes(),16);
        for budget in [ExecBudget::new(2*cost-1,16),ExecBudget::new(2*cost,15)] {
            assert!(matches!(run(op,&[-1.,1.],mode,budget),Err(ExecError::BudgetExceeded{..})));
        }
    }
    Ok(())
}

#[test]
fn unknown_modes_and_attributes_fail_before_execution() {
    for mode in ["auto","fast","TANH",""] {
        assert!(matches!(run(OpCode::Gelu,&[1.],Some(mode),ExecBudget::unlimited()),Err(ExecError::Ir(_))));
    }
    assert!(run(OpCode::Silu,&[1.],Some("none"),ExecBudget::unlimited()).is_err());
}

#[test]
fn empty_shapes_and_scalar_inputs_are_not_reinterpreted() -> TestResult {
    for op in [OpCode::Silu,OpCode::Tanh,OpCode::Gelu] {
        let empty = run(op,&[],None,ExecBudget::new(0,0))?;
        assert!(values(&empty)?.is_empty()); assert_eq!(empty.executed_macs(),0);
        let g = graph(op,&[],None)?;
        let x = Tensor::from_values(Shape::new(vec![])?,&[1_f32],GEN)?;
        let result = ScalarExecutor::run(&g,&[("x",x)],ExecBudget::unlimited(),&ScalarExecCx::new())?;
        assert!(result.get_output("out").ok_or("out")?.shape().dims().is_empty());
        assert_eq!(values(&result)?.len(),1);
    }
    Ok(())
}

#[test]
fn cancellation_dtype_and_generation_checks_remain_strict() -> TestResult {
    let g = graph(OpCode::Gelu,&[2],None)?;
    let cx = ScalarExecCx::new(); cx.request_cancellation();
    let x = Tensor::from_values(Shape::new(vec![2])?,&[1_f32,2.],GEN)?;
    assert!(matches!(ScalarExecutor::run(&g,&[("x",x)],ExecBudget::unlimited(),&cx),Err(ExecError::CancellationRequested{..})));
    assert!(cx.is_drain_completed());
    let x = Tensor::from_values(Shape::new(vec![2])?,&[1_f32,2.],Generation(8))?;
    assert!(matches!(ScalarExecutor::run(&g,&[("x",x)],ExecBudget::unlimited(),&ScalarExecCx::new()),Err(ExecError::GenerationMismatch{..})));
    let x = Tensor::from_values(Shape::new(vec![2])?,&[1_f64,2.],GEN)?;
    assert!(matches!(ScalarExecutor::run(&g,&[("x",x)],ExecBudget::unlimited(),&ScalarExecCx::new()),Err(ExecError::UnsupportedDType{..})));
    Ok(())
}

#[test]
fn normalized_feedforward_graph_executes_all_new_operators() -> TestResult {
    let port = |name:&str,dims:Vec<usize>| TensorPort::new(name,DType::F32,Shape::new(dims)?,GEN);
    let node = |id:&str,op,ins:Vec<&str>,out:&str| GraphNode::new(id,op,id,
        ins.into_iter().map(str::to_owned).collect(),vec![out.to_owned()],AttributeMap::new());
    let g = ModelIrGraph::new_validated("normalized-feedforward",ModelIrVersion::V1,GEN,
        vec![port("x",vec![2,3])?,port("w",vec![3,2])?],vec![port("out",vec![2,2])?],
        vec![node("a",OpCode::LayerNorm,vec!["x"],"n")?,
            node("b",OpCode::MatMul,vec!["n","w"],"m")?,
            node("c",OpCode::Gelu,vec!["m"],"g")?,
            node("d",OpCode::Silu,vec!["g"],"s")?,
            node("e",OpCode::RMSNorm,vec!["s"],"r")?,
            node("f",OpCode::Tanh,vec!["r"],"out")?])?;
    let inputs = [("x",Tensor::from_values(Shape::new(vec![2,3])?,&[1_f32,2.,3.,3.,2.,1.],GEN)?),
        ("w",Tensor::from_values(Shape::new(vec![3,2])?,&[1_f32,0.,0.,1.,1.,1.],GEN)?)];
    let a = ScalarExecutor::run(&g,&inputs,ExecBudget::new(4332,152),&ScalarExecCx::new())?;
    let b = ScalarExecutor::run(&g,&inputs,ExecBudget::new(4332,152),&ScalarExecCx::new())?;
    assert_eq!(a.nodes_executed(),6); assert_eq!(a.executed_macs(),4332); assert_eq!(a.allocated_bytes(),152);
    assert_eq!(values(&a)?.iter().map(|v|v.to_bits()).collect::<Vec<_>>(),values(&b)?.iter().map(|v|v.to_bits()).collect::<Vec<_>>());
    let actual = values(&a)?;
    assert!(actual.iter().all(|v|v.is_finite()));
    assert_eq!(actual[0],0.); assert_eq!(actual[2],0.);
    assert!((actual[1]-0.888381064).abs()<2e-6);
    assert!((actual[3]+0.887635231).abs()<2e-6);
    assert!(matches!(ScalarExecutor::run(&g,&inputs,ExecBudget::new(4331,152),&ScalarExecCx::new()),Err(ExecError::BudgetExceeded{..})));
    Ok(())
}

#[test]
fn frozen_normalized_model_runs_and_replays_from_retained_jpeg() -> TestResult {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;
    use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};
    use fss_core::region::{ContextAuthority, RootAuthoritySpec};
    use fss_reference::{ReferenceDeployment, ReplayCx};
    use fss_reference::ingest::{FileIngestAdapter, FileIngestRequest, RetainedReadLimits};
    use fss_reference::ingest::recorded_decode::{
        ComponentInterpretation, DecodeBudget, DecodeLimits, RecordedDecodeRequest, RecordedFrame,
    };
    use fss_reference::ingest::inference::{RecordedInference, RecordedModel};
    struct OwnedDirectory(PathBuf);
    impl Drop for OwnedDirectory {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }
    let mut directory = None;
    for attempt in 0..100 {
        let path = std::env::temp_dir().join(format!("fss-nonlinear-retained-{}-{attempt}",std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => { directory = Some(OwnedDirectory(path)); break; },
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {},
            Err(e) => return Err(e.into()),
        }
    }
    let directory = directory.ok_or("temporary directory capacity")?;
    let root = directory.0.join("deployment");
    let input_path = directory.0.join("source.jpg");
    fs::write(&input_path,include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg"))?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:nonlinear-retained".into(), operation_id: OperationId::parse("operation:nonlinear-retained")?,
        principal: "principal:test".into(), capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None, priority: 10, budgets: BudgetVector::builder().bytes(64*1024*1024).build()?,
        privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"site:nonlinear"), generation: 1,
    })?;
    authority.validate()?;
    let cx = ReplayCx::from_context_authority(&authority,root.clone())?;
    let mut deployment = ReferenceDeployment::open(&root,"site:nonlinear",&cx)?;
    let imported = FileIngestAdapter::ingest(FileIngestRequest::new(&input_path,
        SensorId::parse("sensor:nonlinear")?,StreamId::parse("stream:nonlinear")?)
        .with_receive_time(TimestampNs(1_000_000_000)),&cx,&mut deployment)?;
    let source = RecordedDecodeRequest {
        import_identity: imported.import_identity, segment_index: 0,
        interpretation: ComponentInterpretation::Grayscale,
        read_limits: RetainedReadLimits::default(), decode_limits: DecodeLimits::default(),
    };
    let frame = RecordedFrame::decode_and_publish(&mut deployment,&source,&mut DecodeBudget::new(100_000_000),&cx)?;
    let [w,h] = frame.receipt().dimensions();
    let shape = Shape::new(vec![1,1,h as usize,w as usize])?;
    let mut nodes = Vec::new();
    let mut predecessor = "image".to_owned();
    for (i,op) in [OpCode::LayerNorm,OpCode::Gelu,OpCode::Silu,OpCode::RMSNorm,OpCode::Tanh].into_iter().enumerate() {
        let out = format!("out{i}");
        nodes.push(GraphNode::new(format!("n{i}"),op,"retained nonlinear numeric fixture",
            vec![predecessor],vec![out.clone()],AttributeMap::new())?);
        predecessor = out;
    }
    let graph = ModelIrGraph::new_validated("retained-nonlinear",ModelIrVersion::V1,GEN,
        vec![TensorPort::new("image",DType::F32,shape.clone(),GEN)?],
        vec![TensorPort::new("out4",DType::F32,shape,GEN)?],nodes)?;
    let model = RecordedModel::publish(&graph,"image",true,BTreeMap::new())?;
    let budget = ExecBudget::new(100_000_000,64*1024*1024);
    let first = RecordedInference::run_and_publish(&mut deployment,&source,&model,budget,&ScalarExecCx::new(),&cx)?;
    assert!(first.outputs().values().flatten().all(|v|v.is_finite()));
    assert_eq!(first.model().graph().node_count(),5);
    let identity = first.identity();
    let output = first.output_bytes().to_vec();
    let anchor = deployment.current_anchor().clone();
    fs::remove_file(&input_path)?;
    drop(first); drop(model); drop(deployment);
    let mut reopened = ReferenceDeployment::open(&root,"site:nonlinear",&cx)?;
    let restored = RecordedInference::open(&reopened,identity,&source,&cx)?;
    assert_eq!(restored.output_bytes(),output);
    restored.verify_by_replay(&reopened,&source,budget,&ScalarExecCx::new(),&cx)?;
    let reused = RecordedInference::run_and_publish(&mut reopened,&source,restored.model(),
        ExecBudget::new(0,64*1024*1024),&ScalarExecCx::new(),&cx)?;
    assert_eq!(reused.identity(),identity); assert_eq!(*reopened.current_anchor(),anchor);
    cx.drain_and_finalize();
    Ok(())
}
