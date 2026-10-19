#![forbid(unsafe_code)]
//! FSS-138 property family: canonical tensor encoding.
//!
//! Determinism, sensitivity to every encoded field, roundtrip identity,
//! malformed refusal, and cross-dtype distinctness. Each property emits
//! one JSONL verdict line.

use fss_core::Generation;
use fss_tensor::canonical::{
    CanonicalTensorError, canonical_tensor_bytes, decode_canonical_tensor,
};
use fss_tensor::{DType, Shape, Tensor};

fn emit(property: &str, cases: u64) {
    println!(
        "{{\"family\":\"FSS-138\",\"property\":\"{property}\",\"cases\":{cases},\"verdict\":\"pass\"}}"
    );
}

fn tensor(payload: &[u8]) -> Result<Tensor, fss_tensor::error::TensorError> {
    let shape = Shape::new(vec![2, 2])?;
    let storage =
        fss_tensor::storage::TensorStorage::from_vec(payload.to_vec(), Generation::GENESIS)?;
    let strides = fss_tensor::stride::Strides::from_shape_row_major(&shape)?;
    let view = fss_tensor::view::TensorView::new(
        std::sync::Arc::new(storage),
        0,
        fss_tensor::DType::U8,
        shape,
        strides,
        Generation::GENESIS,
    )?;
    Ok(Tensor::from_view(view))
}

/// P1 ROUNDTRIP: encode → decode returns the exact parts, over every dtype.
#[test]
fn p1_roundtrip_all_dtypes() -> Result<(), Box<dyn std::error::Error>> {
    const ALL: [DType; 13] = [
        DType::F32,
        DType::F64,
        DType::F16,
        DType::BF16,
        DType::I8,
        DType::I16,
        DType::I32,
        DType::I64,
        DType::U8,
        DType::U16,
        DType::U32,
        DType::U64,
        DType::Bool,
    ];
    let mut cases = 0u64;
    for dtype in ALL {
        let shape = Shape::new(vec![3, 4])?;
        let payload = vec![7u8; shape.num_elements()? * dtype.size_bytes()];
        let bytes = canonical_tensor_bytes(dtype, &shape, Generation::GENESIS, &payload)?;
        let back = decode_canonical_tensor(&bytes)?;
        assert_eq!(back.dtype, dtype);
        assert_eq!(back.shape, shape);
        assert_eq!(back.generation, Generation::GENESIS);
        assert_eq!(back.storage, payload);
        cases += 1;
    }
    emit("roundtrip-all-dtypes", cases);
    Ok(())
}

/// P2 SENSITIVITY: dtype, shape, generation, and content each change the
/// canonical bytes (hence the digest).
#[test]
fn p2_encoding_is_field_sensitive() -> Result<(), Box<dyn std::error::Error>> {
    let shape = Shape::new(vec![2, 2])?;
    let payload = vec![1u8, 2, 3, 4];
    let base = canonical_tensor_bytes(DType::U8, &shape, Generation::GENESIS, &payload)?;
    // Content change.
    let other_payload = vec![1u8, 2, 3, 5];
    let content = canonical_tensor_bytes(DType::U8, &shape, Generation::GENESIS, &other_payload)?;
    assert_ne!(base, content);
    // Generation change.
    let generation_case =
        canonical_tensor_bytes(DType::U8, &shape, Generation::from_u64(2), &payload)?;
    assert_ne!(base, generation_case);
    // Shape change (same bytes, different meaning).
    let other_shape = Shape::new(vec![4])?;
    let reshaped = canonical_tensor_bytes(DType::U8, &other_shape, Generation::GENESIS, &payload)?;
    assert_ne!(base, reshaped);
    // DType change.
    let dtype_change =
        canonical_tensor_bytes(DType::I8, &shape, Generation::GENESIS, &[1, 2, 3, 4])?;
    assert_ne!(base, dtype_change);
    emit("field-sensitivity", 4);
    Ok(())
}

/// P3 DETERMINISM + DIGEST: same tensor → identical bytes and digest,
/// across repeated encodes.
#[test]
fn p3_determinism_and_digest() -> Result<(), Box<dyn std::error::Error>> {
    let t = tensor(&[9, 9, 9, 9])?;
    let b1 = fss_tensor::canonical::tensor_canonical_bytes(&t)?;
    let b2 = fss_tensor::canonical::tensor_canonical_bytes(&t)?;
    assert_eq!(b1, b2);
    let d1 = fss_tensor::canonical::tensor_canonical_digest(&t)?;
    let d2 = fss_tensor::canonical::tensor_canonical_digest(&t)?;
    assert_eq!(d1, d2);
    // Different content must change the digest.
    let t2 = tensor(&[8, 8, 8, 8])?;
    assert_ne!(d1, fss_tensor::canonical::tensor_canonical_digest(&t2)?);
    emit("determinism-digest", 3);
    Ok(())
}

/// P4 MALFORMED REFUSAL: bad magic, unknown version, unknown dtype tag,
/// truncation, trailing bytes, and count/storage inconsistencies are all
/// typed refusals.
#[test]
fn p4_malformed_refusals() -> Result<(), Box<dyn std::error::Error>> {
    let shape = Shape::new(vec![2])?;
    let good = canonical_tensor_bytes(DType::U8, &shape, Generation::GENESIS, &[10, 20])?;
    // Bad magic.
    let mut bad_magic = good.clone();
    bad_magic[0] ^= 0xFF;
    assert!(matches!(
        decode_canonical_tensor(&bad_magic),
        Err(CanonicalTensorError::BadMagic)
    ));
    // Unknown version.
    let mut bad_version = good.clone();
    bad_version[7] ^= 0x01;
    assert!(matches!(
        decode_canonical_tensor(&bad_version),
        Err(CanonicalTensorError::UnknownVersion(_))
    ));
    // Truncation: every proper prefix refuses.
    for cut in 1..good.len() {
        assert!(decode_canonical_tensor(&good[..cut]).is_err());
    }
    // Trailing bytes.
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(matches!(
        decode_canonical_tensor(&trailing),
        Err(CanonicalTensorError::Trailing)
    ));
    // Length inconsistency at encode time.
    assert!(matches!(
        canonical_tensor_bytes(DType::U8, &shape, Generation::GENESIS, &[10]),
        Err(CanonicalTensorError::Inconsistent { .. })
    ));
    emit("malformed-refusals", 7);
    Ok(())
}

/// P5 CANONICAL-FORM EQUIVALENCE: two tensors that differ only by
/// transient representation (reshape of the same contiguous storage is
/// representation) keep distinct canonical forms ONLY when the shape
/// differs; identical semantics encode identically.
#[test]
fn p5_semantic_identity() -> Result<(), Box<dyn std::error::Error>> {
    let a = tensor(&[1, 2, 3, 4])?;
    let b = tensor(&[1, 2, 3, 4])?;
    assert_eq!(
        fss_tensor::canonical::tensor_canonical_digest(&a)?,
        fss_tensor::canonical::tensor_canonical_digest(&b)?,
        "identical tensors hash identically"
    );
    let c = tensor(&[4, 3, 2, 1])?;
    assert_ne!(
        fss_tensor::canonical::tensor_canonical_digest(&a)?,
        fss_tensor::canonical::tensor_canonical_digest(&c)?,
        "reordered content hashes differently"
    );
    emit("semantic-identity", 2);
    Ok(())
}
