#![forbid(unsafe_code)]
//! Contract, canonical round-trip, tensor-digest binding, source-custody non-inheritance,
//! forbidden-latest refusal, overflow/bounds, and cooperative cancellation tests for
//! `FSS-120` (`fss-x4a.12.19`: source-to-tensor span and transform lineage).

use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest, Generation,
};
use fss_tensor::source_lineage::{
    LineageError, SourceByteSpan, SourceToTensorLineage, TransformStep,
};
use fss_tensor::{Shape, Tensor};

type TestResult = Result<(), Box<dyn Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn sample_tensor(gen_num: u64, fill: u8) -> Result<Tensor, Box<dyn Error>> {
    let shape = Shape::new(vec![1, 3, 16, 16])?;
    let data = vec![fill; 16 * 16 * 3];
    Ok(Tensor::from_values(shape, &data, Generation(gen_num))?)
}

fn sample_spans() -> Vec<SourceByteSpan> {
    vec![
        SourceByteSpan {
            source_object_digest: ContentDigest::sha256(b"rtp-batch-1"),
            byte_offset: 128,
            byte_len: 1_400,
            pts_ns: 1_000_000,
            dts_ns: 990_000,
            stream_generation: Generation(5),
        },
        SourceByteSpan {
            source_object_digest: ContentDigest::sha256(b"rtp-batch-1"),
            byte_offset: 1_528,
            byte_len: 820,
            pts_ns: 1_000_000,
            dts_ns: 990_000,
            stream_generation: Generation(5),
        },
    ]
}

fn sample_transforms() -> Vec<TransformStep> {
    vec![
        TransformStep::Decode {
            codec_id: "fss.codec.h264.scalar.v1".to_owned(),
            decoder_generation: Generation(5),
        },
        TransformStep::Crop {
            x: 8,
            y: 4,
            width: 32,
            height: 32,
        },
        TransformStep::Resize {
            dst_width: 16,
            dst_height: 16,
            kernel_id: "bilinear-q16-v1".to_owned(),
        },
        TransformStep::ColorConvert {
            from_space: "yuv420p-bt709".to_owned(),
            to_space: "rgb8-full".to_owned(),
        },
        TransformStep::PrivacyMask {
            mask_policy_digest: ContentDigest::sha256(b"mask-policy-v1"),
            masked_region_count: 2,
        },
    ]
}

#[test]
fn fss_120_lineage_sealing_tensor_verification_and_non_custody_enforced() -> TestResult {
    let tensor = sample_tensor(5, 0x42)?;
    let lineage = SourceToTensorLineage::seal_for_tensor(
        "lineage:cam-front:frame-1",
        sample_spans(),
        ContentDigest::sha256(b"decoded-frame-pixels"),
        sample_transforms(),
        &tensor,
        || false,
    )?;

    assert!(!lineage.is_source_custody);
    assert!(lineage.privacy_masked);
    assert!(lineage.verify_digest());
    lineage.verify_against_tensor(&tensor)?;

    // Mutated tensor bytes or generation MUST fail verify_against_tensor.
    let diff_bytes = sample_tensor(5, 0x43)?;
    assert_eq!(
        lineage.verify_against_tensor(&diff_bytes),
        Err(LineageError::TensorMismatch("canonical_digest"))
    );
    let diff_gen = sample_tensor(6, 0x42)?;
    assert_eq!(
        lineage.verify_against_tensor(&diff_gen),
        Err(LineageError::TensorMismatch("generation"))
    );

    // Canonical binary round-trip preserves exact lineage and digest.
    let mut enc = CanonicalEncoder::new();
    lineage.encode_canonical(&mut enc);
    let bytes = enc.finish();
    let decoded = SourceToTensorLineage::decode_canonical(&mut CanonicalDecoder::new(&bytes))?;
    assert_eq!(decoded, lineage);

    // Forged lineage claiming is_source_custody=true (even with recomputed SHA-256!) MUST fail decode.
    let mut forged = lineage.clone();
    forged.is_source_custody = true;
    forged.lineage_digest = forged.computed_digest();
    let mut bad_enc = CanonicalEncoder::new();
    forged.encode_canonical(&mut bad_enc);
    assert!(
        SourceToTensorLineage::decode_canonical(&mut CanonicalDecoder::new(&bad_enc.finish()))
            .is_err()
    );

    emit_caplog(
        "fss_120_lineage_sealing_and_verification",
        "source_spans_transforms_tensor_digest_and_non_custody_verified",
        "source_spans_transforms_tensor_digest_and_non_custody_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn fss_120_hostile_spans_latest_alias_missing_decode_and_cancellation_fail_closed() -> TestResult {
    let tensor = sample_tensor(5, 0x10)?;

    // 1. Missing Decode as first step fails closed.
    let no_decode = vec![TransformStep::Crop {
        x: 0,
        y: 0,
        width: 16,
        height: 16,
    }];
    assert_eq!(
        SourceToTensorLineage::seal_for_tensor(
            "lin:bad-start",
            sample_spans(),
            ContentDigest::sha256(b"frame"),
            no_decode,
            &tensor,
            || false,
        )
        .unwrap_err(),
        LineageError::InvalidTransform("must_begin_with_decode_step")
    );

    // 2. Forbidden "latest" alias in lineage_id or codec_id fails closed.
    assert_eq!(
        SourceToTensorLineage::seal_for_tensor(
            "lin:latest",
            sample_spans(),
            ContentDigest::sha256(b"frame"),
            sample_transforms(),
            &tensor,
            || false,
        )
        .unwrap_err(),
        LineageError::ForbiddenLatestAlias("lineage_id")
    );
    let mut latest_steps = sample_transforms();
    latest_steps[0] = TransformStep::Decode {
        codec_id: "fss.codec.h264:latest".to_owned(),
        decoder_generation: Generation(5),
    };
    assert_eq!(
        SourceToTensorLineage::seal_for_tensor(
            "lin:check-codec",
            sample_spans(),
            ContentDigest::sha256(b"frame"),
            latest_steps,
            &tensor,
            || false,
        )
        .unwrap_err(),
        LineageError::ForbiddenLatestAlias("codec_id")
    );

    // 3. Overflowing source span fails closed.
    let overflow_span = vec![SourceByteSpan {
        source_object_digest: ContentDigest::sha256(b"src"),
        byte_offset: u64::MAX - 10,
        byte_len: 100,
        pts_ns: 0,
        dts_ns: 0,
        stream_generation: Generation(5),
    }];
    assert_eq!(
        SourceToTensorLineage::seal_for_tensor(
            "lin:overflow",
            overflow_span,
            ContentDigest::sha256(b"frame"),
            sample_transforms(),
            &tensor,
            || false,
        )
        .unwrap_err(),
        LineageError::ArithmeticOverflow
    );

    // 4. Cooperative cancellation at every checkpoint fails closed.
    let total = AtomicUsize::new(0);
    assert!(
        SourceToTensorLineage::seal_for_tensor(
            "lin:count",
            sample_spans(),
            ContentDigest::sha256(b"frame"),
            sample_transforms(),
            &tensor,
            || {
                total.fetch_add(1, Ordering::Relaxed);
                false
            },
        )
        .is_ok()
    );
    let checks = total.load(Ordering::Relaxed);
    assert!(checks >= 3);
    for cancel_at in [0, checks / 2, checks - 1] {
        let seen = AtomicUsize::new(0);
        let res = SourceToTensorLineage::seal_for_tensor(
            "lin:cancel",
            sample_spans(),
            ContentDigest::sha256(b"frame"),
            sample_transforms(),
            &tensor,
            || seen.fetch_add(1, Ordering::Relaxed) >= cancel_at,
        );
        assert_eq!(res.unwrap_err(), LineageError::Cancelled);
    }

    emit_caplog(
        "fss_120_hostile_and_cancellation",
        "missing_decode_latest_alias_overflow_and_cancellation_fail_closed",
        "missing_decode_latest_alias_overflow_and_cancellation_fail_closed",
        "pass",
    );
    Ok(())
}
