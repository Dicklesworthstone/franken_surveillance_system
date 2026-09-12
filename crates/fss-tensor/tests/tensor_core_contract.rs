//! Contract tests for tensor dtype, shape, stride, storage, view, and version core.
//!
//! Ref: fss-x4a.14.7 / FSS-136

#![forbid(unsafe_code)]

use std::error::Error;
use std::sync::Arc;

use fss_core::Generation;
use fss_tensor::{
    BF16, DType, F16, MAX_STORAGE_BYTES, MAX_TENSOR_RANK, Shape, Strides, Tensor, TensorError,
    TensorStorage, TensorView,
};

#[test]
fn test_rank_overflow_hostile_metadata() -> Result<(), Box<dyn Error>> {
    let hostile_dims = vec![2; MAX_TENSOR_RANK + 1];
    let result = Shape::new(hostile_dims);
    match result {
        Err(TensorError::RankOverflow { rank, max_rank }) => {
            assert_eq!(rank, MAX_TENSOR_RANK + 1);
            assert_eq!(max_rank, MAX_TENSOR_RANK);
        }
        other => return Err(format!("expected RankOverflow, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_dimension_multiplication_overflow() -> Result<(), Box<dyn Error>> {
    let hostile_shape = Shape::new(vec![usize::MAX, 2])?;
    match hostile_shape.num_elements() {
        Err(TensorError::ArithmeticOverflow { operation }) => {
            assert_eq!(operation, "shape element count");
        }
        other => return Err(format!("expected ArithmeticOverflow, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_byte_size_overflow() -> Result<(), Box<dyn Error>> {
    // 64-bit float is 8 bytes. A shape of (usize::MAX / 4) elements will overflow when multiplied by 8.
    let big_dim = (usize::MAX / 4) + 1;
    let hostile_shape = Shape::new(vec![big_dim])?;
    match hostile_shape.size_bytes(DType::F64) {
        Err(TensorError::ArithmeticOverflow { operation }) => {
            assert_eq!(operation, "shape byte size");
        }
        other => return Err(format!("expected ArithmeticOverflow, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_storage_allocation_limit_hostile_size() -> Result<(), Box<dyn Error>> {
    let over_limit = MAX_STORAGE_BYTES + 1;
    match TensorStorage::zeros(over_limit, Generation::GENESIS) {
        Err(TensorError::AllocationLimitExceeded {
            requested_bytes,
            max_bytes,
        }) => {
            assert_eq!(requested_bytes, over_limit);
            assert_eq!(max_bytes, MAX_STORAGE_BYTES);
        }
        other => return Err(format!("expected AllocationLimitExceeded, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_storage_length_mismatch() -> Result<(), Box<dyn Error>> {
    let shape = Shape::new(vec![2, 3])?; // 6 elements
    let values = vec![1.0f32, 2.0, 3.0]; // only 3 elements
    match Tensor::from_values(shape, &values, Generation::GENESIS) {
        Err(TensorError::StorageLengthMismatch {
            expected_bytes,
            actual_bytes,
        }) => {
            assert_eq!(expected_bytes, 6 * 4);
            assert_eq!(actual_bytes, 3 * 4);
        }
        other => return Err(format!("expected StorageLengthMismatch, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_misaligned_view_offset() -> Result<(), Box<dyn Error>> {
    let storage = Arc::new(TensorStorage::zeros(64, Generation::GENESIS)?);
    let shape = Shape::new(vec![2, 2])?;
    let strides = Strides::from_shape_row_major(&shape)?;

    // Offset 3 is not aligned to 4-byte boundary for F32
    match TensorView::new(storage, 3, DType::F32, shape, strides, Generation::GENESIS) {
        Err(TensorError::MisalignedOffset { offset, alignment }) => {
            assert_eq!(offset, 3);
            assert_eq!(alignment, 4);
        }
        other => return Err(format!("expected MisalignedOffset, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_view_aliasing_out_of_bounds_rejected() -> Result<(), Box<dyn Error>> {
    // Storage has only 8 bytes
    let storage = Arc::new(TensorStorage::zeros(8, Generation::GENESIS)?);
    // Shape requires 3 * 4 = 12 bytes
    let shape = Shape::new(vec![3])?;
    let strides = Strides::from_shape_row_major(&shape)?;

    match TensorView::new(storage, 0, DType::F32, shape, strides, Generation::GENESIS) {
        Err(TensorError::StorageOutOfBounds {
            required_bytes,
            storage_bytes,
        }) => {
            assert_eq!(required_bytes, 12);
            assert_eq!(storage_bytes, 8);
        }
        other => return Err(format!("expected StorageOutOfBounds, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_slice_bounds_and_zero_step() -> Result<(), Box<dyn Error>> {
    let shape = Shape::new(vec![4, 4])?;
    let tensor = Tensor::zeros(shape, DType::I32, Generation::GENESIS)?;

    // Zero step slice rejection
    match tensor.slice(0, 0, 2, 0) {
        Err(TensorError::ZeroStepSlice) => {}
        other => return Err(format!("expected ZeroStepSlice, got {other:?}").into()),
    }

    // Invalid slice: start > end
    match tensor.slice(0, 3, 2, 1) {
        Err(TensorError::InvalidSlice {
            dim,
            start,
            end,
            bound,
        }) => {
            assert_eq!(dim, 0);
            assert_eq!(start, 3);
            assert_eq!(end, 2);
            assert_eq!(bound, 4);
        }
        other => return Err(format!("expected InvalidSlice, got {other:?}").into()),
    }

    // Invalid slice: end > bound
    match tensor.slice(1, 0, 5, 1) {
        Err(TensorError::InvalidSlice {
            dim,
            start,
            end,
            bound,
        }) => {
            assert_eq!(dim, 1);
            assert_eq!(start, 0);
            assert_eq!(end, 5);
            assert_eq!(bound, 4);
        }
        other => return Err(format!("expected InvalidSlice, got {other:?}").into()),
    }

    // Dimension out of bounds
    match tensor.slice(2, 0, 1, 1) {
        Err(TensorError::DimensionOutOfBounds { dim, rank }) => {
            assert_eq!(dim, 2);
            assert_eq!(rank, 2);
        }
        other => return Err(format!("expected DimensionOutOfBounds, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_non_contiguous_reshape_rejected() -> Result<(), Box<dyn Error>> {
    let shape = Shape::new(vec![3, 3])?;
    let tensor = Tensor::zeros(shape, DType::F32, Generation::GENESIS)?;

    // Slice row 0..2 with step 2 -> non-contiguous view
    let sliced = tensor.slice(0, 0, 3, 2)?;
    assert!(!sliced.is_c_contiguous());

    let target_shape = Shape::new(vec![sliced.num_elements()?])?;
    match sliced.reshape(target_shape) {
        Err(TensorError::NonContiguousReshape) => {}
        other => return Err(format!("expected NonContiguousReshape, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_compatible_reshape_succeeds() -> Result<(), Box<dyn Error>> {
    let shape = Shape::new(vec![2, 3])?;
    let values = vec![1.0f32, 2.0, 3.0, 4.0, 5.0, 6.0];
    let tensor = Tensor::from_values(shape, &values, Generation::GENESIS)?;

    let reshaped = tensor.reshape(Shape::new(vec![3, 2])?)?;
    assert_eq!(reshaped.shape().dims(), &[3, 2]);
    assert_eq!(reshaped.to_vec::<f32>()?, values);

    let flat = tensor.reshape(Shape::new(vec![6])?)?;
    assert_eq!(flat.shape().dims(), &[6]);
    assert_eq!(flat.to_vec::<f32>()?, values);
    Ok(())
}

#[test]
fn test_generation_mismatch_fails_closed() -> Result<(), Box<dyn Error>> {
    let gen1 = Generation::from_u64(1);
    let gen2 = Generation::from_u64(2);

    let t1 = Tensor::zeros(Shape::new(vec![2])?, DType::F32, gen1)?;
    let t2 = Tensor::zeros(Shape::new(vec![2])?, DType::F32, gen2)?;

    match t1.assert_same_generation(&t2) {
        Err(TensorError::GenerationMismatch { expected, actual }) => {
            assert_eq!(expected, gen1);
            assert_eq!(actual, gen2);
        }
        other => return Err(format!("expected GenerationMismatch, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_view_storage_generation_consistency() -> Result<(), Box<dyn Error>> {
    let gen1 = Generation::from_u64(10);
    let gen2 = Generation::from_u64(20);

    let storage = Arc::new(TensorStorage::zeros(16, gen1)?);
    let shape = Shape::new(vec![4])?;
    let strides = Strides::from_shape_row_major(&shape)?;

    match TensorView::new(storage, 0, DType::F32, shape, strides, gen2) {
        Err(TensorError::GenerationMismatch { expected, actual }) => {
            assert_eq!(expected, gen1);
            assert_eq!(actual, gen2);
        }
        other => return Err(format!("expected GenerationMismatch, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_type_mismatch_rejected() -> Result<(), Box<dyn Error>> {
    let tensor = Tensor::from_values(Shape::new(vec![2])?, &[1.0f32, 2.0f32], Generation::GENESIS)?;
    match tensor.read_element::<f64>(&[0]) {
        Err(TensorError::TypeMismatch { expected, actual }) => {
            assert_eq!(expected, DType::F32);
            assert_eq!(actual, DType::F64);
        }
        other => return Err(format!("expected TypeMismatch, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_coordinate_index_out_of_bounds() -> Result<(), Box<dyn Error>> {
    let tensor = Tensor::zeros(Shape::new(vec![2, 3])?, DType::I32, Generation::GENESIS)?;
    match tensor.read_element::<i32>(&[2, 0]) {
        Err(TensorError::IndexOutOfBounds { dim, index, bound }) => {
            assert_eq!(dim, 0);
            assert_eq!(index, 2);
            assert_eq!(bound, 2);
        }
        other => return Err(format!("expected IndexOutOfBounds, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_rank_mismatch_coordinates() -> Result<(), Box<dyn Error>> {
    let tensor = Tensor::zeros(Shape::new(vec![2, 3])?, DType::I32, Generation::GENESIS)?;
    match tensor.read_element::<i32>(&[0]) {
        Err(TensorError::RankMismatch {
            shape_rank,
            other_rank,
        }) => {
            assert_eq!(shape_rank, 2);
            assert_eq!(other_rank, 1);
        }
        other => return Err(format!("expected RankMismatch, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_deterministic_reference_element_access() -> Result<(), Box<dyn Error>> {
    // 2x3 matrix:
    // [ 10.0, 20.0, 30.0 ]
    // [ 40.0, 50.0, 60.0 ]
    let values = vec![10.0f32, 20.0, 30.0, 40.0, 50.0, 60.0];
    let tensor = Tensor::from_values(Shape::new(vec![2, 3])?, &values, Generation::GENESIS)?;

    assert_eq!(tensor.read_element::<f32>(&[0, 0])?, 10.0);
    assert_eq!(tensor.read_element::<f32>(&[0, 1])?, 20.0);
    assert_eq!(tensor.read_element::<f32>(&[0, 2])?, 30.0);
    assert_eq!(tensor.read_element::<f32>(&[1, 0])?, 40.0);
    assert_eq!(tensor.read_element::<f32>(&[1, 1])?, 50.0);
    assert_eq!(tensor.read_element::<f32>(&[1, 2])?, 60.0);

    // Slice row 1: [40.0, 50.0, 60.0]
    let row1 = tensor.slice(0, 1, 2, 1)?;
    assert_eq!(row1.shape().dims(), &[1, 3]);
    assert_eq!(row1.to_vec::<f32>()?, vec![40.0, 50.0, 60.0]);

    // Transpose: 3x2 matrix:
    // [ 10.0, 40.0 ]
    // [ 20.0, 50.0 ]
    // [ 30.0, 60.0 ]
    let transposed = tensor.transpose(0, 1)?;
    assert_eq!(transposed.shape().dims(), &[3, 2]);
    assert_eq!(transposed.read_element::<f32>(&[0, 0])?, 10.0);
    assert_eq!(transposed.read_element::<f32>(&[0, 1])?, 40.0);
    assert_eq!(transposed.read_element::<f32>(&[1, 0])?, 20.0);
    assert_eq!(transposed.read_element::<f32>(&[1, 1])?, 50.0);
    assert_eq!(transposed.read_element::<f32>(&[2, 0])?, 30.0);
    assert_eq!(transposed.read_element::<f32>(&[2, 1])?, 60.0);

    let transposed_elements = transposed.to_vec::<f32>()?;
    assert_eq!(
        transposed_elements,
        vec![10.0, 40.0, 20.0, 50.0, 30.0, 60.0]
    );

    Ok(())
}

#[test]
fn test_to_contiguous_roundtrip() -> Result<(), Box<dyn Error>> {
    let values = vec![1.0f32, 2.0, 3.0, 4.0, 5.0, 6.0];
    let tensor = Tensor::from_values(Shape::new(vec![2, 3])?, &values, Generation::GENESIS)?;

    let transposed = tensor.transpose(0, 1)?;
    assert!(!transposed.is_c_contiguous());

    let contiguous = transposed.to_contiguous()?;
    assert!(contiguous.is_c_contiguous());
    assert_eq!(contiguous.generation(), Generation::GENESIS);
    assert_eq!(
        contiguous.to_vec::<f32>()?,
        vec![1.0, 4.0, 2.0, 5.0, 3.0, 6.0]
    );

    Ok(())
}

#[test]
fn test_content_digest_determinism() -> Result<(), Box<dyn Error>> {
    let values = vec![10i64, 20, 30, 40];
    let t1 = Tensor::from_values(Shape::new(vec![2, 2])?, &values, Generation::GENESIS)?;
    let t2 = Tensor::from_values(Shape::new(vec![2, 2])?, &values, Generation::GENESIS)?;

    let digest1 = t1.content_digest()?;
    let digest2 = t2.content_digest()?;
    assert_eq!(digest1, digest2);

    // Differing values produce different digest
    let different_values = vec![10i64, 20, 30, 41];
    let t_diff_val = Tensor::from_values(
        Shape::new(vec![2, 2])?,
        &different_values,
        Generation::GENESIS,
    )?;
    assert_ne!(digest1, t_diff_val.content_digest()?);

    // Differing generation produces different digest
    let gen2 = Generation::from_u64(2);
    let t_diff_gen = Tensor::from_values(Shape::new(vec![2, 2])?, &values, gen2)?;
    assert_ne!(digest1, t_diff_gen.content_digest()?);

    Ok(())
}

#[test]
fn test_scalar_tensor() -> Result<(), Box<dyn Error>> {
    let scalar = Tensor::from_values(Shape::scalar(), &[42.5f32], Generation::GENESIS)?;
    assert!(scalar.shape().is_scalar());
    assert_eq!(scalar.rank(), 0);
    assert_eq!(scalar.num_elements()?, 1);
    assert_eq!(scalar.read_element::<f32>(&[])?, 42.5);
    assert_eq!(scalar.to_vec::<f32>()?, vec![42.5]);

    let contiguous = scalar.to_contiguous()?;
    assert_eq!(contiguous.read_element::<f32>(&[])?, 42.5);

    let digest = scalar.content_digest()?;
    assert_eq!(digest, contiguous.content_digest()?);
    Ok(())
}

#[test]
fn test_f16_bf16_dtypes() -> Result<(), Box<dyn Error>> {
    let f16_val = F16::from_bits(0x3c00); // 1.0 in IEEE 754 half-float
    let bf16_val = BF16::from_bits(0x3f80); // 1.0 in bfloat16

    let f16_tensor = Tensor::from_values(Shape::new(vec![1])?, &[f16_val], Generation::GENESIS)?;
    assert_eq!(f16_tensor.read_element::<F16>(&[0])?, f16_val);

    let bf16_tensor = Tensor::from_values(Shape::new(vec![1])?, &[bf16_val], Generation::GENESIS)?;
    assert_eq!(bf16_tensor.read_element::<BF16>(&[0])?, bf16_val);
    Ok(())
}

#[test]
fn test_squeeze_unsqueeze() -> Result<(), Box<dyn Error>> {
    let tensor = Tensor::zeros(
        Shape::new(vec![1, 3, 1, 2])?,
        DType::U8,
        Generation::GENESIS,
    )?;

    // Squeeze specific dim 0
    let sq0 = tensor.squeeze(Some(0))?;
    assert_eq!(sq0.shape().dims(), &[3, 1, 2]);

    // Squeeze all size 1 dims
    let sq_all = tensor.squeeze(None)?;
    assert_eq!(sq_all.shape().dims(), &[3, 2]);

    // Unsqueeze at dim 1
    let unsq = sq_all.unsqueeze(1)?;
    assert_eq!(unsq.shape().dims(), &[3, 1, 2]);
    Ok(())
}

#[test]
fn test_dtype_parsing() -> Result<(), Box<dyn Error>> {
    assert_eq!(DType::parse("f32")?, DType::F32);
    assert_eq!(DType::parse("float32")?, DType::F32);
    assert_eq!(DType::parse("f64")?, DType::F64);
    assert_eq!(DType::parse("f16")?, DType::F16);
    assert_eq!(DType::parse("bf16")?, DType::BF16);
    assert_eq!(DType::parse("i8")?, DType::I8);
    assert_eq!(DType::parse("i32")?, DType::I32);
    assert_eq!(DType::parse("u8")?, DType::U8);
    assert_eq!(DType::parse("bool")?, DType::Bool);

    match DType::parse("unsupported_type") {
        Err(TensorError::InvalidDTypeName { name }) => {
            assert_eq!(name, "unsupported_type");
        }
        other => return Err(format!("expected InvalidDTypeName, got {other:?}").into()),
    }
    Ok(())
}
