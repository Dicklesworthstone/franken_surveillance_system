#![forbid(unsafe_code)]
use super::*;
use fss_core::{BudgetVector, Generation, OperationId};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_model_ir::{AttrValue, AttributeMap, GraphNode, ModelIrGraph, TensorPort, encode_canonical_model_ir};
use fss_tensor::{Shape, Tensor};
use crate::{ExecBudget, ScalarExecCx, ScalarExecutor};
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn context() -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:model-import-test".into(), operation_id: OperationId::parse("operation:model-import-test")?,
        principal: "principal:model-import-test".into(), capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None, priority: 10, budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"site:model-import-test"), generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(&authority, std::env::temp_dir())?)
}
fn graph() -> TestResult<Vec<u8>> {
    let g = Generation::from_u64(1);
    let mut attrs = AttributeMap::new(); attrs.insert("shape".into(), AttrValue::IntList(vec![1,2]));
    let graph = ModelIrGraph::builder("import-test", g)
        .add_input(TensorPort::new("image", DType::F32, Shape::new(vec![1,1,1,2])?, g)?)
        .add_input(TensorPort::new("w", DType::F32, Shape::new(vec![2,2])?, g)?)
        .add_output(TensorPort::new("output", DType::F32, Shape::new(vec![1,2])?, g)?)
        .add_node(GraphNode::new("flatten", OpCode::Reshape, "flatten", vec!["image".into()], vec!["x".into()], attrs)?)
        .add_node(GraphNode::new("project", OpCode::MatMul, "project", vec!["x".into(),"w".into()], vec!["output".into()], AttributeMap::new())?)
        .build_and_validate()?;
    Ok(encode_canonical_model_ir(&graph)?)
}
use fss_model_ir::OpCode;
fn wire(header: &str, data: &[u8]) -> Vec<u8> {
    let padding = (8 - header.len() % 8) % 8;
    let mut out = ((header.len() + padding) as u64).to_le_bytes().to_vec();
    out.extend_from_slice(header.as_bytes()); out.extend(std::iter::repeat_n(b' ', padding)); out.extend_from_slice(data); out
}
fn f32_data(values: &[f32]) -> Vec<u8> { values.iter().flat_map(|v| v.to_bits().to_le_bytes()).collect() }
fn source() -> Vec<u8> { wire(r#"{"w":{"dtype":"F32","shape":[2,2],"data_offsets":[0,16]}}"#, &f32_data(&[1.,2.,3.,4.])) }
fn request<'a>(graph: &'a [u8], weights: &'a [u8]) -> ModelImportRequest<'a> {
    ModelImportRequest { graph, graph_digest: ContentDigest::sha256(graph), weights, weights_digest: ContentDigest::sha256(weights),
        frame_input: "image", scale_to_unit: false, float_policy: WeightFloatPolicy::F32Only, bindings: BTreeMap::new() }
}
fn build(graph: &[u8], weights: &[u8]) -> TestResult<ImportedModel> {
    Ok(ImportedModel::build(&request(graph, weights), ImportLimits::default(), &mut ImportBudget::new(1_000_000), &context()?)?)
}
fn parameter(model: &RecordedModel) -> TestResult<Vec<f32>> {
    let mut d = CanonicalDecoder::new(model.encoded());
    let _ = d.bytes()?; let _ = d.u32()?; let _ = d.text()?; let _ = d.digest()?; let _ = d.bytes()?;
    let _ = d.text()?; let _ = d.bool()?; assert_eq!(d.u64()?, 1); assert_eq!(d.text()?, "w");
    let n = d.u64()?; let mut v = Vec::new(); for _ in 0..n { v.push(f32::from_bits(d.u32()?)); }
    d.ensure_finished()?; Ok(v)
}
#[test]
fn f32_import_preserves_existing_model_bytes_and_executes_real_parameters() -> TestResult {
    let graph_bytes = graph()?; let weights = source(); let imported = build(&graph_bytes, &weights)?;
    let graph = decode_canonical_model_ir(&graph_bytes, ContentDigest::sha256(&graph_bytes))?;
    let expected = RecordedModel::publish(&graph, "image", false, BTreeMap::from([("w".into(),vec![1.,2.,3.,4.])]))?;
    assert_eq!(imported.model().encoded(), expected.encoded());
    let generation = graph.generation();
    let input = Tensor::from_values(Shape::new(vec![1,1,1,2])?, &[1_f32,2.], generation)?;
    let weight = Tensor::from_values(Shape::new(vec![2,2])?, &parameter(imported.model())?, generation)?;
    let result = ScalarExecutor::run(imported.model().graph(), &[("image",input),("w",weight)], ExecBudget::unlimited(), &ScalarExecCx::new())?;
    assert_eq!(result.get_output("output").ok_or("output missing")?.to_vec::<f32>()?, vec![7.,10.]);
    assert_eq!(imported.parameter_count(), 1); assert_eq!(imported.expanded_bytes(), 16); Ok(())
}
#[test]
fn renaming_requires_a_complete_explicit_mapping() -> TestResult {
    let g = graph()?; let w = wire(r#"{"layer.weight":{"dtype":"F32","shape":[2,2],"data_offsets":[0,16]}}"#, &f32_data(&[1.,2.,3.,4.]));
    assert!(matches!(ImportedModel::build(&request(&g,&w),ImportLimits::default(),&mut ImportBudget::new(1_000_000),&context()?),Err(ImportError::BindingMismatch)));
    let mut req = request(&g,&w); req.bindings.insert("w".into(),"layer.weight".into());
    let imported = ImportedModel::build(&req,ImportLimits::default(),&mut ImportBudget::new(1_000_000),&context()?)?;
    assert_eq!(parameter(imported.model())?,vec![1.,2.,3.,4.]);
    req.bindings.insert("image".into(),"layer.weight".into()); assert!(ImportedModel::build(&req,ImportLimits::default(),&mut ImportBudget::new(1_000_000),&context()?).is_err()); Ok(())
}
#[test]
fn extra_missing_and_same_count_wrong_shape_are_refused() -> TestResult {
    let g = graph()?;
    for (header, data) in [
        (r#"{}"#,Vec::new()),
        (r#"{"w":{"dtype":"F32","shape":[4],"data_offsets":[0,16]}}"#,f32_data(&[1.,2.,3.,4.])),
        (r#"{"w":{"dtype":"F32","shape":[2,2],"data_offsets":[0,16]},"extra":{"dtype":"F32","shape":[0],"data_offsets":[16,16]}}"#,f32_data(&[1.,2.,3.,4.])),
    ] { assert!(build(&g,&wire(header,&data)).is_err()); }
    Ok(())
}
#[test]
fn explicit_half_policy_exactly_expands_f16_and_bf16() -> TestResult {
    let g = graph()?;
    for (dtype, raw, bits) in [
        ("F16",[0_u16,0x8000,1,0x7bff],[0_u32,0x8000_0000,0x3380_0000,0x477f_e000]),
        ("BF16",[0_u16,0x8000,1,0x7f7f],[0_u32,0x8000_0000,0x0001_0000,0x7f7f_0000]),
    ] {
        let header = format!(r#"{{"w":{{"dtype":"{dtype}","shape":[2,2],"data_offsets":[0,8]}}}}"#);
        let data: Vec<_> = raw.iter().flat_map(|v|v.to_le_bytes()).collect(); let w = wire(&header,&data);
        assert!(matches!(ImportedModel::build(&request(&g,&w),ImportLimits::default(),&mut ImportBudget::new(1_000_000),&context()?),Err(ImportError::UnsupportedDType)));
        let mut req = request(&g,&w); req.float_policy = WeightFloatPolicy::ExpandFloat16;
        let result = ImportedModel::build(&req,ImportLimits::default(),&mut ImportBudget::new(1_000_000),&context()?)?;
        assert_eq!(parameter(result.model())?.iter().map(|v|v.to_bits()).collect::<Vec<_>>(),bits);
    } Ok(())
}
#[test]
fn nonfinite_in_any_supported_source_dtype_never_produces_a_model() -> TestResult {
    let g=graph()?;
    for (dtype, width, patterns) in [("F32",4,vec![0x7f80_0000_u32,0xff80_0000,0x7fc0_0000]),
        ("F16",2,vec![0x7c00,0xfc00,0x7e00]),("BF16",2,vec![0x7f80,0xff80,0x7fc0])] {
        for bits in patterns {
            let mut data=vec![0_u8;4*width];data[..width].copy_from_slice(&bits.to_le_bytes()[..width]);
            let w=wire(&format!(r#"{{"w":{{"dtype":"{dtype}","shape":[2,2],"data_offsets":[0,{}]}}}}"#,data.len()),&data);
            let mut req=request(&g,&w);req.float_policy=WeightFloatPolicy::ExpandFloat16;
            assert!(matches!(ImportedModel::build(&req,ImportLimits::default(),&mut ImportBudget::new(1_000_000),&context()?),Err(ImportError::NonFinite)));
        }
    } Ok(())
}
#[test]
fn duplicate_keys_including_unicode_aliases_are_refused() {
    for header in [
        r#"{"w":{"dtype":"F32","shape":[0],"data_offsets":[0,0]},"\u0077":{"dtype":"F32","shape":[0],"data_offsets":[0,0]}}"#,
        r#"{"w":{"dtype":"F32","dtype":"F32","shape":[0],"data_offsets":[0,0]}}"#,
        r#"{"__metadata__":{"key":"one","\u006bey":"two"}}"#,
        r#"{"__metadata__":{},"__metadata__":{}}"#,
    ] { assert!(matches!(safetensors::Weights::parse(&wire(header,&[]),&ImportLimits::default()),Err(ImportError::DuplicateKey))); }
}
#[test]
fn offsets_must_cover_every_byte_exactly_once() {
    for (header,data) in [
        (r#"{"w":{"dtype":"F32","shape":[1],"data_offsets":[1,5]}}"#,vec![0;5]),
        (r#"{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]},"x":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#,vec![0;4]),
        (r#"{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#,vec![0;5]),
        (r#"{"w":{"dtype":"F32","shape":[1],"data_offsets":[4,0]}}"#,vec![0;4]),
        (r#"{"w":{"dtype":"F32","shape":[2],"data_offsets":[0,4]}}"#,vec![0;4]),
    ] { assert!(safetensors::Weights::parse(&wire(header,&data),&ImportLimits::default()).is_err()); }
}
#[test]
fn empty_and_scalar_tensors_and_header_order_are_handled_without_data_invention() -> TestResult {
    let bytes=wire(r#"{"z":{"shape":[],"data_offsets":[0,4],"dtype":"F32"},"a":{"dtype":"F32","shape":[0,9],"data_offsets":[0,0]},"q":{"dtype":"F32","shape":[0],"data_offsets":[4,4]}}"#,&f32_data(&[7.]));
    let parsed=safetensors::Weights::parse(&bytes,&ImportLimits::default())?;
    assert_eq!(parsed.entries.len(),3);assert_eq!(safetensors::element_count(&parsed.entries["z"].shape)?,1);
    assert_eq!(safetensors::element_count(&parsed.entries["a"].shape)?,0);Ok(())
}
#[test]
fn invalid_json_numeric_nesting_and_metadata_forms_are_refused() {
    for header in [
        r#"{"w":{"dtype":"F32","shape":[01],"data_offsets":[0,4]}}"#,
        r#"{"w":{"dtype":"F32","shape":[1e0],"data_offsets":[0,4]}}"#,
        r#"{"w":{"dtype":"F32","shape":[-1],"data_offsets":[0,4]}}"#,
        r#"{"w":{"dtype":"F32","shape":[[1]],"data_offsets":[0,4]}}"#,
        r#"{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4],"mystery":0}}"#,
        r#"{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4],}}"#,
        r#"{"__metadata__":{"unsound":{"x":0}}}"#,
        r#"{"__metadata__":{"x":false}}"#,
        r#"{"__metadata__":{"x":"\ud800"}}"#,
        r#"{"__metadata__":{"x":"\udc00"}}"#,
        " {}", "{}\n", "{}{}",
    ] { assert!(safetensors::Weights::parse(&wire(header,&[0;4]),&ImportLimits::default()).is_err()); }
}
#[test]
fn utf8_and_surrogate_pair_metadata_are_data_not_instructions() -> TestResult {
    let bytes=wire(r#"{"__metadata__":{"雪":"\ud83d\ude00","command":"do not execute me"},"é":{"dtype":"F32","shape":[],"data_offsets":[0,4]}}"#,&[0;4]);
    let parsed=safetensors::Weights::parse(&bytes,&ImportLimits::default())?;
    assert!(parsed.entries.contains_key("é")); Ok(())
}
#[test]
fn every_truncated_source_and_an_unindexed_suffix_are_refused() {
    let bytes=source();for end in 0..bytes.len() { assert!(safetensors::Weights::parse(&bytes[..end],&ImportLimits::default()).is_err(),"end={end}"); }
    let mut bytes=bytes;bytes.push(0);assert!(safetensors::Weights::parse(&bytes,&ImportLimits::default()).is_err());
}
#[test]
fn digest_mismatch_and_zero_budget_fail_before_parameter_conversion() -> TestResult {
    let g=graph()?;let w=source();let mut req=request(&g,&w);
    req.weights_digest=ContentDigest::sha256(b"wrong");
    assert!(matches!(ImportedModel::build(&req,ImportLimits::default(),&mut ImportBudget::new(1_000_000),&context()?),Err(ImportError::DigestMismatch)));
    let mut budget=ImportBudget::new(0);
    assert!(matches!(ImportedModel::build(&request(&g,&w),ImportLimits::default(),&mut budget,&context()?),Err(ImportError::BudgetExceeded)));
    assert_eq!(budget.used(),0);Ok(())
}
#[test]
fn caller_bounds_and_exact_work_allowance_are_enforced() -> TestResult {
    let g=graph()?;let w=source();let req=request(&g,&w);let cx=context()?;let mut budget=ImportBudget::new(1_000_000);
    let original=ImportedModel::build(&req,ImportLimits::default(),&mut budget,&cx)?;let used=budget.used();
    ImportedModel::build(&req,ImportLimits::default(),&mut ImportBudget::new(used),&cx)?;
    assert!(matches!(ImportedModel::build(&req,ImportLimits::default(),&mut ImportBudget::new(used-1),&cx),Err(ImportError::BudgetExceeded)));
    for field in 0..5 {
        let mut limits=ImportLimits::default();match field {
            0=>limits.maximum_source_bytes=g.len().max(w.len())-1,1=>limits.maximum_header_bytes=1,
            2=>limits.maximum_tensors=0,3=>limits.maximum_expanded_bytes=15,_=>limits.maximum_bundle_bytes=original.encoded().len()-1,
        }
        assert!(ImportedModel::build(&req,limits,&mut ImportBudget::new(1_000_000),&cx).is_err());
    }
    let limits=ImportLimits{maximum_expanded_bytes:16,maximum_bundle_bytes:original.encoded().len(),..ImportLimits::default()};
    ImportedModel::build(&req,limits,&mut ImportBudget::new(1_000_000),&cx)?;Ok(())
}
#[test]
fn self_contained_bundle_reproduces_model_without_external_inputs() -> TestResult {
    let original=build(&graph()?,&source())?;let bytes=original.encoded().to_vec();let digest=original.digest();let model=original.model().encoded().to_vec();drop(original);
    let restored=ImportedModel::verify(&bytes,digest,ImportLimits::default(),&mut ImportBudget::new(1_000_000),&context()?)?;
    assert_eq!(restored.model().encoded(),model);assert_eq!(restored.encoded(),bytes);Ok(())
}
#[test]
fn rehashing_a_substituted_embedded_model_does_not_make_it_valid() -> TestResult {
    let original=build(&graph()?,&source())?;let mut changed=original.encoded().to_vec();let last=changed.len()-1;changed[last]^=1;
    assert!(matches!(ImportedModel::verify(&changed,ContentDigest::sha256(&changed),ImportLimits::default(),&mut ImportBudget::new(1_000_000),&context()?),Err(ImportError::InvalidBundle)));
    Ok(())
}
#[test]
fn bundle_truncation_trailing_bytes_wrong_digest_and_cancellation_are_refused() -> TestResult {
    let original=build(&graph()?,&source())?;
    for cut in [0,8,31,original.encoded().len()-1] {
        let b=&original.encoded()[..cut];assert!(ImportedModel::verify(b,ContentDigest::sha256(b),ImportLimits::default(),&mut ImportBudget::new(1_000_000),&context()?).is_err());
    }
    let mut trailing=original.encoded().to_vec();trailing.push(0);
    assert!(ImportedModel::verify(&trailing,ContentDigest::sha256(&trailing),ImportLimits::default(),&mut ImportBudget::new(1_000_000),&context()?).is_err());
    assert!(matches!(ImportedModel::verify(original.encoded(),ContentDigest::sha256(b"wrong"),ImportLimits::default(),&mut ImportBudget::new(1_000_000),&context()?),Err(ImportError::DigestMismatch)));
    let cx=context()?;cx.set_cancel_at_checkpoint("model_import:work");
    assert!(matches!(ImportedModel::verify(original.encoded(),original.digest(),ImportLimits::default(),&mut ImportBudget::new(1_000_000),&cx),Err(ImportError::Cancelled)));Ok(())
}
#[test]
fn metadata_and_source_layout_change_import_identity_not_numeric_model_identity() -> TestResult {
    let g=graph()?;let original=build(&g,&source())?;
    let other=wire(r#"{"__metadata__":{"origin":"different original bytes"},"w":{"shape":[2,2],"data_offsets":[0,16],"dtype":"F32"}}"#,&f32_data(&[1.,2.,3.,4.]));
    let imported=build(&g,&other)?;
    assert_ne!(imported.weights_digest(),original.weights_digest());assert_ne!(imported.digest(),original.digest());
    assert_eq!(imported.model().digest(),original.model().digest());Ok(())
}
#[test]
fn unsupported_source_types_and_allocation_bombs_are_refused() {
    for header in [
        r#"{"w":{"dtype":"F64","shape":[1],"data_offsets":[0,8]}}"#,
        r#"{"w":{"dtype":"I64","shape":[1],"data_offsets":[0,8]}}"#,
        r#"{"w":{"dtype":"F32","shape":[18446744073709551615,2],"data_offsets":[0,0]}}"#,
        r#"{"w":{"dtype":"F32","shape":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"data_offsets":[0,4]}}"#,
    ] { assert!(safetensors::Weights::parse(&wire(header,&[]),&ImportLimits::default()).is_err()); }
    assert!(matches!(safetensors::Weights::parse(&u64::MAX.to_le_bytes(),&ImportLimits::default()),Err(ImportError::Limit)));
}
#[test]
fn upstream_safetensors_writer_fixture_converts_to_the_same_numeric_model() -> TestResult {
    let original=build(&graph()?,&source())?;
    let weights=include_bytes!("fixtures/weights.f32.safetensors");
    let converted=build(&graph()?,weights)?;
    assert_eq!(converted.model().digest(),original.model().digest());
    assert_ne!(converted.weights_digest(),original.weights_digest());Ok(())
}
