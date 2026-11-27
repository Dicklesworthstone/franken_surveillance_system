#![forbid(unsafe_code)]
//! Normative model-runtime invariant proof contracts:
//! - `MODEL-INV-002` (`fss-x4a.14.23.8`): one versioned preprocessing program (no undocumented side channel).
//! - `MODEL-INV-003` (`fss-x4a.14.23.9`): explicit typed tensor semantics (identical bytes with
//!   different shape, dtype, layout, or generation are strictly distinct inputs).
//! - `MODEL-INV-005` (`fss-x4a.14.23.11`): model outputs are derived evidence only, never source
//!   custody or effect authority.
//! - `MODEL-INV-007` (`fss-x4a.14.23.13`): offline immutable model artifacts, zero runtime download
//!   or arbitrary code execution.

use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;

use fss_core::{ContentDigest, Generation, ResourcePressure, TimestampNs};
use fss_model_ir::quotas::{
    EnvelopeDimension, JobResourceAdmissionLedger, JobResourceEnvelope, JobResourceRequest,
    MemoryAdmission, ResourceEnvelopeViolation,
};
use fss_model_ir::{
    MemoryPlanLimits, OnnxExportLimits, OnnxLimits, decode_canonical_model_ir,
    export_onnx_artifacts, import_onnx,
};
use fss_reference::planned_scalar::{CompiledScalarPlan, PeakExecBudget, PlannedExecError};
use fss_reference::{
    ChannelTransform, ExecBudget, PreprocessProgram, ReceiptOutcome, ReceiptRecordContext,
    ScalarExecCx, execute_and_record_receipt, is_latest_generation,
};
use fss_tensor::canonical::tensor_canonical_digest;
use fss_tensor::{
    DType, DerivativePublicationState, DerivativeReceiptRequest, MediaDerivativeKind,
    MediaDerivativeReceipt, ReproducibilityClass, Shape, SourceByteSpan, SourceCustodyBinding,
    SourceToTensorLineage, Strides, Tensor, TensorStorage, TensorView, TransformStep,
};

type TestResult = Result<(), Box<dyn Error>>;

const DETECTOR_ONNX: &[u8] =
    include_bytes!("../../fss-model-ir/tests/fixtures/onnx/detector_split_pool.onnx");
const GEN: Generation = Generation(23);

fn tensor_from_raw(
    dtype: DType,
    shape: Shape,
    raw: Vec<u8>,
    generation: Generation,
) -> Result<Tensor, Box<dyn Error>> {
    let storage = Arc::new(TensorStorage::from_vec(raw, generation)?);
    let strides = Strides::from_shape_row_major(&shape)?;
    let view = TensorView::new(storage, 0, dtype, shape, strides, generation)?;
    Ok(Tensor::from_view(view))
}

#[test]
fn model_inv_002_one_versioned_preprocessing_program_and_lineage() -> TestResult {
    // Versioned pure-Rust PreprocessProgram is bit-reproducible and bound in SourceToTensorLineage
    // and ModelInvocationReceipt (no side-channel script!).
    let raw_rgb: Vec<u8> = (0..48_u8).map(|i| i.wrapping_mul(5)).collect();
    let p_rgb = PreprocessProgram::new(4, 4, ChannelTransform::Rgb, true);
    let p_luma = PreprocessProgram::new(4, 4, ChannelTransform::LumaOnly, true);

    let t1 = p_rgb.execute_bytes(&raw_rgb, 4, 4, 3, GEN)?;
    let t2 = p_rgb.execute_bytes(&raw_rgb, 4, 4, 3, GEN)?;
    let t_luma = p_luma.execute_bytes(&raw_rgb, 4, 4, 3, GEN)?;

    assert_eq!(tensor_canonical_digest(&t1)?, tensor_canonical_digest(&t2)?);
    // Different channel transform (RGB vs LumaOnly) over identical raw bytes MUST produce distinct digest!
    assert_ne!(
        tensor_canonical_digest(&t1)?,
        tensor_canonical_digest(&t_luma)?
    );

    let lineage = SourceToTensorLineage::seal_for_tensor(
        "lineage:model-inv-002",
        vec![SourceByteSpan {
            source_object_digest: ContentDigest::sha256(&raw_rgb),
            byte_offset: 0,
            byte_len: 48,
            pts_ns: 1_000,
            dts_ns: 1_000,
            stream_generation: GEN,
        }],
        ContentDigest::sha256(&raw_rgb),
        vec![
            TransformStep::Decode {
                codec_id: "fss.codec.mjpeg.scalar.v1".to_owned(),
                decoder_generation: GEN,
            },
            TransformStep::ColorConvert {
                from_space: "rgb8-hwc".to_owned(),
                to_space: "rgb-nchw".to_owned(),
            },
            TransformStep::Normalize {
                scale_q16: 257,
                offset_q16: 0,
                output_dtype: DType::F32,
            },
        ],
        &t1,
        || false,
    )?;
    lineage.verify_against_tensor(&t1)?;
    assert!(lineage.verify_against_tensor(&t_luma).is_err());

    println!(
        "CAPLOG {{\"invariant\":\"MODEL-INV-002\",\"lineage_digest\":\"{}\",\"verdict\":\"ok\"}}",
        lineage.lineage_digest
    );
    Ok(())
}

#[test]
fn model_inv_003_explicit_typed_tensor_semantics_distinguish_shape_dtype_and_generation()
-> TestResult {
    // Identical 16 raw bytes interpreted with different Shape, DType, or Generation MUST yield
    // distinct canonical digests and refuse mismatched storage/view generations!
    let raw16 = [0x3F_u8, 0x80, 0x00, 0x00].repeat(4); // 16 bytes
    let f32_1x4_g1 = tensor_from_raw(
        DType::F32,
        Shape::new(vec![1, 4])?,
        raw16.clone(),
        Generation(1),
    )?;
    let f32_2x2_g1 = tensor_from_raw(
        DType::F32,
        Shape::new(vec![2, 2])?,
        raw16.clone(),
        Generation(1),
    )?;
    let u8_16_g1 = tensor_from_raw(
        DType::U8,
        Shape::new(vec![16])?,
        raw16.clone(),
        Generation(1),
    )?;
    let f32_1x4_g2 = tensor_from_raw(
        DType::F32,
        Shape::new(vec![1, 4])?,
        raw16.clone(),
        Generation(2),
    )?;

    // Cross-generation view creation over Generation(1) storage MUST fail closed!
    let storage_g1 = Arc::new(TensorStorage::from_vec(raw16, Generation(1))?);
    let shape_1x4 = Shape::new(vec![1, 4])?;
    let strides_1x4 = Strides::from_shape_row_major(&shape_1x4)?;
    assert!(
        TensorView::new(
            storage_g1,
            0,
            DType::F32,
            shape_1x4,
            strides_1x4,
            Generation(2)
        )
        .is_err()
    );
    assert!(f32_1x4_g1.assert_same_generation(&f32_1x4_g2).is_err());

    let d_1x4_g1 = tensor_canonical_digest(&f32_1x4_g1)?;
    let d_2x2_g1 = tensor_canonical_digest(&f32_2x2_g1)?;
    let d_u8_g1 = tensor_canonical_digest(&u8_16_g1)?;
    let d_1x4_g2 = tensor_canonical_digest(&f32_1x4_g2)?;

    assert_ne!(d_1x4_g1, d_2x2_g1, "shape must affect canonical identity");
    assert_ne!(d_1x4_g1, d_u8_g1, "dtype must affect canonical identity");
    assert_ne!(
        d_1x4_g1, d_1x4_g2,
        "generation must affect canonical identity"
    );

    println!(
        "CAPLOG {{\"invariant\":\"MODEL-INV-003\",\"distinct_digests\":4,\"verdict\":\"ok\"}}"
    );
    Ok(())
}

#[test]
fn model_inv_005_and_007_outputs_are_derived_evidence_and_offline_immutable_only() -> TestResult {
    // Offline import + canonical decode of pinned ONNX graph (no network, no runtime download).
    let imported = import_onnx(
        DETECTOR_ONNX,
        ContentDigest::sha256(DETECTOR_ONNX),
        GEN,
        OnnxLimits::default(),
        &|| false,
    )?;
    let artifacts = export_onnx_artifacts(&imported, OnnxExportLimits::default(), &|| false)?;
    let graph = decode_canonical_model_ir(artifacts.graph_bytes(), artifacts.graph_digest())?;

    // Mutable "latest" alias is strictly rejected (MODEL-INV-007).
    assert!(is_latest_generation("latest"));
    assert!(is_latest_generation("detector/latest.fmpk"));

    // Run deterministic scalar executor and seal ModelInvocationReceipt.
    let preprocess = PreprocessProgram::new(4, 4, ChannelTransform::Rgb, true);
    let raw_rgb = vec![100_u8; 48];
    let img = preprocess.execute_bytes(&raw_rgb, 4, 4, 3, GEN)?;
    let params: BTreeMap<String, Tensor> = imported.parameters().clone();
    let mut all_inputs: Vec<(String, Tensor)> =
        params.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    all_inputs.push(("image".to_owned(), img));
    let borrowed: Vec<(&str, Tensor)> = all_inputs
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();

    let (res, rec) = execute_and_record_receipt(
        &graph,
        &borrowed,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
        ReceiptRecordContext {
            job_id: "job:model-inv-005-007",
            preprocess_program: Some(&preprocess),
            model_package_root: Some(artifacts.graph_digest()),
            virtual_clock: None,
            source_roots: &[ContentDigest::sha256(&raw_rgb)],
            preprocess_resize: None,
        },
    );
    assert!(res.is_ok());
    assert_eq!(rec.outcome, ReceiptOutcome::Ok);
    assert!(rec.is_reference_only()); // Never grants effect authority!
    rec.verify(GEN, &rec.compute_canonical_digest())?;

    // Derived model input/output receipts strictly keep is_source_custody == false (MODEL-INV-005).
    let deriv = MediaDerivativeReceipt::seal(
        DerivativeReceiptRequest {
            receipt_id: "deriv:model-inv-005".to_owned(),
            kind: MediaDerivativeKind::ModelTensorInput,
            derivative_digest: rec.compute_canonical_digest(),
            derivative_bytes: 192,
            format_profile: "tensor/f32;nchw-1x3x4x4".to_owned(),
            source_binding: SourceCustodyBinding::RetainedAnchor {
                evidence_anchor_digest: ContentDigest::sha256(&raw_rgb),
                source_spans: vec![SourceByteSpan {
                    source_object_digest: ContentDigest::sha256(&raw_rgb),
                    byte_offset: 0,
                    byte_len: 48,
                    pts_ns: 1_000,
                    dts_ns: 1_000,
                    stream_generation: GEN,
                }],
            },
            parent_receipts: Vec::new(),
            transforms: vec![TransformStep::Decode {
                codec_id: "fss.codec.mjpeg.scalar.v1".to_owned(),
                decoder_generation: GEN,
            }],
            implementation_identity: "fss-reference:scalar-v1".to_owned(),
            generation: GEN,
            privacy_policy_digest: ContentDigest::sha256(b"privacy:v1"),
            retention_group_digest: ContentDigest::sha256(b"retention:30d"),
            is_lossy: false,
            reproducibility: ReproducibilityClass::BitExactScalar,
            publication_state: DerivativePublicationState::RootPublished,
            created_at_ns: TimestampNs(5_000),
            clock_uncertainty_ns: 0,
        },
        || false,
    )?;
    assert!(!deriv.is_source_custody);

    println!(
        "CAPLOG {{\"invariants\":[\"MODEL-INV-005\",\"MODEL-INV-007\"],\"is_source_custody\":{},\"reference_only\":{},\"verdict\":\"ok\"}}",
        deriv.is_source_custody,
        rec.is_reference_only()
    );
    Ok(())
}

#[test]
fn model_inv_008_hard_resource_envelopes_enforce_all_eight_dimensions_and_bounded_queue()
-> TestResult {
    // 1. All 8 MODEL-INV-008 dimensions + bounded queue depth + pressure abstention enforced!
    let env = JobResourceEnvelope {
        max_input_bytes: 1_024,
        max_decoded_pixels: 4_096,
        max_tokens: 128,
        max_activation_memory_bytes: 8_192,
        max_scratch_memory_bytes: 4_096,
        max_operator_work: 50_000,
        max_deadline_ns: 25_000_000,
        max_output_bytes: 2_048,
        max_queued_jobs: 2,
    };
    let mut ledger = JobResourceAdmissionLedger::new(env, MemoryAdmission::RefuseConstrained)?;
    let ok_req = JobResourceRequest {
        input_bytes: 512,
        decoded_pixels: 1_024,
        tokens: 32,
        activation_memory_bytes: 4_096,
        scratch_memory_bytes: 2_048,
        operator_work: 10_000,
        deadline_ns: 10_000_000,
        output_bytes: 1_024,
    };

    // Every single one of the 8 dimensions fails closed with exact EnvelopeDimension & zero debit!
    let violation_cases: [(EnvelopeDimension, JobResourceRequest); 8] = [
        (
            EnvelopeDimension::InputBytes,
            JobResourceRequest {
                input_bytes: 1_025,
                ..ok_req
            },
        ),
        (
            EnvelopeDimension::DecodedPixels,
            JobResourceRequest {
                decoded_pixels: 4_097,
                ..ok_req
            },
        ),
        (
            EnvelopeDimension::Tokens,
            JobResourceRequest {
                tokens: 129,
                ..ok_req
            },
        ),
        (
            EnvelopeDimension::ActivationMemoryBytes,
            JobResourceRequest {
                activation_memory_bytes: 8_193,
                ..ok_req
            },
        ),
        (
            EnvelopeDimension::ScratchMemoryBytes,
            JobResourceRequest {
                scratch_memory_bytes: 4_097,
                ..ok_req
            },
        ),
        (
            EnvelopeDimension::OperatorWork,
            JobResourceRequest {
                operator_work: 50_001,
                ..ok_req
            },
        ),
        (
            EnvelopeDimension::DeadlineNs,
            JobResourceRequest {
                deadline_ns: 25_000_001,
                ..ok_req
            },
        ),
        (
            EnvelopeDimension::OutputBytes,
            JobResourceRequest {
                output_bytes: 2_049,
                ..ok_req
            },
        ),
    ];
    for (dim, bad_req) in violation_cases {
        let err = ledger.reserve_job(bad_req, ResourcePressure::Nominal);
        assert!(matches!(
            err,
            Err(ResourceEnvelopeViolation::BoundExceeded { dimension, .. }) if dimension == dim
        ));
        assert_eq!(ledger.active_jobs(), 0);
        assert_eq!(ledger.reserved_activation_bytes(), 0);
    }

    // Critical pressure abstains cleanly without mutating reservations!
    assert_eq!(
        ledger.reserve_job(ok_req, ResourcePressure::Critical),
        Err(ResourceEnvelopeViolation::PressureAbstained(
            ResourcePressure::Critical
        ))
    );

    // Bounded queueing + aggregate memory ceiling: 2 jobs succeed, 3rd is refused (no unbounded queue)!
    let r1 = ledger.reserve_job(ok_req, ResourcePressure::Nominal)?;
    let r2 = ledger.reserve_job(ok_req, ResourcePressure::Nominal)?;
    assert_ne!(r1.reservation_id(), r2.reservation_id());
    assert_eq!(ledger.active_jobs(), 2);
    assert_eq!(ledger.reserved_activation_bytes(), 8_192);
    assert!(matches!(
        ledger.reserve_job(ok_req, ResourcePressure::Nominal),
        Err(ResourceEnvelopeViolation::BoundExceeded {
            dimension: EnvelopeDimension::QueuedJobs,
            ..
        })
    ));

    // A linear reservation from another ledger (different byte amounts) cannot corrupt this ledger!
    let mut other_ledger = JobResourceAdmissionLedger::new(env, MemoryAdmission::NominalOnly)?;
    let foreign_res = other_ledger.reserve_job(
        JobResourceRequest {
            activation_memory_bytes: 1_024,
            scratch_memory_bytes: 512,
            ..ok_req
        },
        ResourcePressure::Nominal,
    )?;
    assert_eq!(
        ledger.release_job(foreign_res),
        Err(ResourceEnvelopeViolation::ReservationNotFound(1))
    );
    assert_eq!(ledger.active_jobs(), 2);
    assert_eq!(ledger.reserved_activation_bytes(), 8_192);

    ledger.release_job(r1)?;
    ledger.release_job(r2)?;
    assert_eq!(ledger.active_jobs(), 0);
    assert_eq!(ledger.reserved_activation_bytes(), 0);
    assert_eq!(ledger.reserved_scratch_bytes(), 0);

    // 2. Real compiled scalar plan enforces exact activation peak & scratch ceilings before running!
    let imported = import_onnx(
        DETECTOR_ONNX,
        ContentDigest::sha256(DETECTOR_ONNX),
        GEN,
        OnnxLimits::default(),
        &|| false,
    )?;
    let artifacts = export_onnx_artifacts(&imported, OnnxExportLimits::default(), &|| false)?;
    let graph = decode_canonical_model_ir(artifacts.graph_bytes(), artifacts.graph_digest())?;
    let cx = ScalarExecCx::new();
    let plan = CompiledScalarPlan::compile(&graph, MemoryPlanLimits::default(), &cx)?;

    let preprocess = PreprocessProgram::new(4, 4, ChannelTransform::Rgb, true);
    let img = preprocess.execute_bytes(&[90_u8; 48], 4, 4, 3, GEN)?;
    let params: BTreeMap<String, Tensor> = imported.parameters().clone();
    let mut all_inputs: Vec<(String, Tensor)> =
        params.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    all_inputs.push(("image".to_owned(), img));
    let borrowed: Vec<(&str, Tensor)> = all_inputs
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();

    let reqs = plan.minimum_requirements();
    let tight_scratch = PeakExecBudget::new(
        reqs.macs,
        reqs.peak_bytes,
        reqs.scratch_bytes.saturating_sub(1),
    );
    assert!(matches!(
        plan.run(&borrowed, tight_scratch, &cx),
        Err(PlannedExecError::BudgetExceeded { .. })
    ));
    let exact_ok = PeakExecBudget::new(reqs.macs, reqs.peak_bytes, reqs.scratch_bytes);
    assert!(plan.run(&borrowed, exact_ok, &cx).is_ok());

    println!(
        "CAPLOG {{\"invariant\":\"MODEL-INV-008\",\"dimensions_enforced\":9,\"plan_macs\":{},\"plan_peak_bytes\":{},\"verdict\":\"ok\"}}",
        reqs.macs, reqs.peak_bytes
    );
    Ok(())
}
