#![forbid(unsafe_code)]
//! Contract & fault suite for `DOC-041` (`fss-x4a.5.41`): canonical `MediaDerivativeReceipt` lineage.

use std::error::Error;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    Generation, TimestampNs,
};
use fss_tensor::{
    DType, DerivativePublicationState, DerivativeReceiptError, DerivativeReceiptRequest,
    MediaDerivativeKind, MediaDerivativeReceipt, ReproducibilityClass, SourceByteSpan,
    SourceCustodyBinding, TransformStep,
};

type TestResult = Result<(), Box<dyn Error>>;

fn digest(label: &str) -> ContentDigest {
    ContentDigest::sha256(label.as_bytes())
}

fn valid_span(generation: u64) -> SourceByteSpan {
    SourceByteSpan {
        source_object_digest: digest("source-segment-001"),
        byte_offset: 128,
        byte_len: 4096,
        pts_ns: 1_000_000_000,
        dts_ns: 966_666_667,
        stream_generation: Generation(generation),
    }
}

fn base_request(kind: MediaDerivativeKind) -> DerivativeReceiptRequest {
    DerivativeReceiptRequest {
        receipt_id: "deriv:cam01:0001".to_owned(),
        kind,
        derivative_digest: digest("derivative-payload-001"),
        derivative_bytes: 16_384,
        format_profile: "image/jpeg;baseline-q85".to_owned(),
        source_binding: SourceCustodyBinding::RetainedAnchor {
            evidence_anchor_digest: digest("anchor:seg001"),
            source_spans: vec![valid_span(1)],
        },
        parent_receipts: Vec::new(),
        transforms: vec![
            TransformStep::Decode {
                codec_id: "fss.codec.h264.scalar.v1".to_owned(),
                decoder_generation: Generation(1),
            },
            TransformStep::Crop {
                x: 32,
                y: 16,
                width: 320,
                height: 240,
            },
        ],
        implementation_identity: "fss-tensor:scalar-v1".to_owned(),
        generation: Generation(1),
        privacy_policy_digest: digest("privacy-policy:v1"),
        retention_group_digest: digest("retention-group:30d"),
        is_lossy: true,
        reproducibility: ReproducibilityClass::BitExactScalar,
        publication_state: DerivativePublicationState::RootPublished,
        created_at_ns: TimestampNs(1_000_050_000),
        clock_uncertainty_ns: 500_000,
    }
}

#[test]
fn doc_041_multi_stage_derivative_chain_mask_before_egress_and_canonical_roundtrip() -> TestResult {
    // Stage 1: spatial crop (unmasked, RootPublished).
    let crop = MediaDerivativeReceipt::seal(base_request(MediaDerivativeKind::Crop), || false)?;
    assert!(!crop.is_source_custody);
    assert!(!crop.privacy_masked);
    assert!(crop.verify_digest());
    // Egress with mask requirement MUST fail closed on unmasked crop!
    assert_eq!(
        crop.verify_egress_eligible(true),
        Err(DerivativeReceiptError::EgressDenied(
            "privacy_mask_required"
        ))
    );
    // Internal egress without mask requirement succeeds only because RootPublished.
    assert!(crop.verify_egress_eligible(false).is_ok());

    // Stage 2: privacy redaction chained from crop.
    let mut redact_req = base_request(MediaDerivativeKind::PrivacyRedaction);
    redact_req.receipt_id = "deriv:cam01:0002-masked".to_owned();
    redact_req.derivative_digest = digest("masked-crop-bytes");
    redact_req.parent_receipts = vec![crop.clone()];
    redact_req.transforms = vec![TransformStep::PrivacyMask {
        mask_policy_digest: digest("privacy-policy:v1"),
        masked_region_count: 2,
    }];
    let masked = MediaDerivativeReceipt::seal(redact_req, || false)?;
    assert!(!masked.is_source_custody);
    assert!(masked.privacy_masked);
    assert_eq!(masked.parent_derivative_digests, vec![crop.receipt_digest]);
    assert!(masked.verify_egress_eligible(true).is_ok());

    // Stage 3: model tensor input chained from masked redaction -> inherits privacy_masked == true!
    let mut tensor_req = base_request(MediaDerivativeKind::ModelTensorInput);
    tensor_req.receipt_id = "deriv:cam01:0003-tensor".to_owned();
    tensor_req.format_profile = "tensor/f32;nhwc-224x224".to_owned();
    tensor_req.derivative_digest = digest("tensor-bytes");
    tensor_req.parent_receipts = vec![masked.clone()];
    tensor_req.transforms = vec![
        TransformStep::Resize {
            dst_width: 224,
            dst_height: 224,
            kernel_id: "bilinear-q16-v1".to_owned(),
        },
        TransformStep::Normalize {
            scale_q16: 257,
            offset_q16: 0,
            output_dtype: DType::F32,
        },
    ];
    tensor_req.reproducibility = ReproducibilityClass::BoundedTolerance;
    let tensor_receipt = MediaDerivativeReceipt::seal(tensor_req, || false)?;
    assert!(!tensor_receipt.is_source_custody);
    assert!(tensor_receipt.privacy_masked);
    assert_eq!(
        tensor_receipt.parent_derivative_digests,
        vec![masked.receipt_digest]
    );
    assert!(tensor_receipt.verify_egress_eligible(true).is_ok());

    // Explicit omission binding works for ephemeral live-preview thumbnails.
    let mut ephemeral_req = base_request(MediaDerivativeKind::Thumbnail);
    ephemeral_req.receipt_id = "deriv:cam01:0004-thumb".to_owned();
    ephemeral_req.source_binding = SourceCustodyBinding::ExplicitOmission {
        omission_reason: "ephemeral_live_preview_policy".to_owned(),
        omission_policy_digest: digest("retention-policy:ephemeral"),
    };
    let ephemeral = MediaDerivativeReceipt::seal(ephemeral_req, || false)?;
    assert!(!ephemeral.is_source_custody);

    // Canonical binary round-trip across retained-anchor and explicit-omission receipts.
    for receipt in [&crop, &masked, &tensor_receipt, &ephemeral] {
        let mut enc = CanonicalEncoder::new();
        receipt.encode_canonical(&mut enc);
        let bytes = enc.finish();
        let decoded = MediaDerivativeReceipt::decode_canonical(&mut CanonicalDecoder::new(&bytes))?;
        assert_eq!(&decoded, receipt);
    }

    println!(
        "CAPLOG {{\"step\":\"doc_041_chain\",\"stages\":3,\"final_kind\":\"{}\",\"masked\":{},\"source_custody\":{},\"verdict\":\"ok\"}}",
        tensor_receipt.kind.as_str(),
        tensor_receipt.privacy_masked,
        tensor_receipt.is_source_custody
    );
    Ok(())
}

#[test]
fn doc_041_refuses_forged_source_custody_staged_egress_latest_alias_deleted_parent_and_cancel()
-> TestResult {
    // 1. Staged derivative refused at egress (root-last publication discipline).
    let mut staged_req = base_request(MediaDerivativeKind::Clip);
    staged_req.publication_state = DerivativePublicationState::Staged;
    let staged = MediaDerivativeReceipt::seal(staged_req, || false)?;
    assert_eq!(
        staged.verify_egress_eligible(false),
        Err(DerivativeReceiptError::EgressDenied("not_root_published"))
    );

    // 2. PrivacyRedaction without PrivacyMask transform step refused.
    let bad_redact = base_request(MediaDerivativeKind::PrivacyRedaction);
    assert_eq!(
        MediaDerivativeReceipt::seal(bad_redact, || false),
        Err(DerivativeReceiptError::InvalidLineage(
            "privacy_redaction_requires_mask_step"
        ))
    );

    // 3. Mutable "latest" alias refused in implementation_identity and omission_reason.
    let mut latest_req = base_request(MediaDerivativeKind::Resize);
    latest_req.implementation_identity = "fss-tensor:latest".to_owned();
    assert_eq!(
        MediaDerivativeReceipt::seal(latest_req, || false),
        Err(DerivativeReceiptError::InvalidField(
            "implementation_identity"
        ))
    );
    let mut latest_omit = base_request(MediaDerivativeKind::Thumbnail);
    latest_omit.source_binding = SourceCustodyBinding::ExplicitOmission {
        omission_reason: "policy:latest".to_owned(),
        omission_policy_digest: digest("p"),
    };
    assert_eq!(
        MediaDerivativeReceipt::seal(latest_omit, || false),
        Err(DerivativeReceiptError::InvalidField("omission_reason"))
    );

    // 4. Tombstoned/deleted parent refused for child derivation.
    let mut deleted_parent_req = base_request(MediaDerivativeKind::Crop);
    deleted_parent_req.publication_state = DerivativePublicationState::DeletedTombstone;
    let deleted_parent = MediaDerivativeReceipt::seal(deleted_parent_req, || false)?;
    let mut child_req = base_request(MediaDerivativeKind::Transcode);
    child_req.parent_receipts = vec![deleted_parent];
    assert_eq!(
        MediaDerivativeReceipt::seal(child_req, || false),
        Err(DerivativeReceiptError::InvalidLineage(
            "deleted_parent_receipt"
        ))
    );

    // 5. Cooperative cancellation fails closed before sealing.
    assert_eq!(
        MediaDerivativeReceipt::seal(base_request(MediaDerivativeKind::Enhancement), || true),
        Err(DerivativeReceiptError::Cancelled)
    );

    // 6. Wire-level forgery claiming `is_source_custody = true` (even with recomputed SHA-256!)
    //    MUST be refused by CanonicalDecode AND verify_egress_eligible.
    let mut forged =
        MediaDerivativeReceipt::seal(base_request(MediaDerivativeKind::Crop), || false)?;
    forged.is_source_custody = true;
    forged.receipt_digest = forged.computed_digest();
    assert_eq!(
        forged.verify_egress_eligible(false),
        Err(DerivativeReceiptError::EgressDenied(
            "corrupt_or_forged_receipt"
        ))
    );
    let mut enc = CanonicalEncoder::new();
    forged.encode_canonical(&mut enc);
    let forged_bytes = enc.finish();
    assert!(
        MediaDerivativeReceipt::decode_canonical(&mut CanonicalDecoder::new(&forged_bytes))
            .is_err()
    );

    // 7. Wire-level forgery claiming `privacy_masked = true` with no mask step & no parent refused.
    let mut forged_mask =
        MediaDerivativeReceipt::seal(base_request(MediaDerivativeKind::Crop), || false)?;
    forged_mask.privacy_masked = true;
    forged_mask.receipt_digest = forged_mask.computed_digest();
    let mut enc2 = CanonicalEncoder::new();
    forged_mask.encode_canonical(&mut enc2);
    let forged_mask_bytes = enc2.finish();
    assert!(
        MediaDerivativeReceipt::decode_canonical(&mut CanonicalDecoder::new(&forged_mask_bytes))
            .is_err()
    );

    // 8. Privacy policy rotation invalidates inherited privacy_masked AND mismatched PrivacyMask
    //    policy digest is refused cleanly.
    let mut masked_v1_req = base_request(MediaDerivativeKind::PrivacyRedaction);
    masked_v1_req.receipt_id = "deriv:cam01:masked-v1".to_owned();
    masked_v1_req.transforms = vec![TransformStep::PrivacyMask {
        mask_policy_digest: digest("privacy-policy:v1"),
        masked_region_count: 1,
    }];
    let masked_v1 = MediaDerivativeReceipt::seal(masked_v1_req, || false)?;
    assert!(masked_v1.privacy_masked);

    // Child under newer privacy-policy:v2 MUST NOT inherit privacy_masked from v1 parent!
    let mut rotated_child_req = base_request(MediaDerivativeKind::Resize);
    rotated_child_req.receipt_id = "deriv:cam01:rotated-v2".to_owned();
    rotated_child_req.privacy_policy_digest = digest("privacy-policy:v2");
    rotated_child_req.parent_receipts = vec![masked_v1.clone()];
    let rotated_child = MediaDerivativeReceipt::seal(rotated_child_req, || false)?;
    assert!(!rotated_child.privacy_masked);
    assert_eq!(
        rotated_child.verify_egress_eligible(true),
        Err(DerivativeReceiptError::EgressDenied(
            "privacy_mask_required"
        ))
    );

    // Duplicate parent receipts refused.
    let mut dup_parent_req = base_request(MediaDerivativeKind::Resize);
    dup_parent_req.parent_receipts = vec![masked_v1.clone(), masked_v1];
    assert_eq!(
        MediaDerivativeReceipt::seal(dup_parent_req, || false),
        Err(DerivativeReceiptError::InvalidLineage(
            "duplicate_parent_receipt"
        ))
    );

    // PrivacyMask transform citing a different policy digest than receipt.privacy_policy_digest refused.
    let mut mismatch_mask_req = base_request(MediaDerivativeKind::PrivacyRedaction);
    mismatch_mask_req.privacy_policy_digest = digest("privacy-policy:v2");
    mismatch_mask_req.transforms = vec![TransformStep::PrivacyMask {
        mask_policy_digest: digest("privacy-policy:v1"),
        masked_region_count: 1,
    }];
    assert_eq!(
        MediaDerivativeReceipt::seal(mismatch_mask_req, || false),
        Err(DerivativeReceiptError::InvalidLineage(
            "privacy_mask_policy_mismatch"
        ))
    );
    Ok(())
}
