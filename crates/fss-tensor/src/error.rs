//! Error types for deterministic tensor operations.

use core::fmt;
use std::error::Error;

use fss_core::Generation;

use crate::dtype::DType;

/// Errors arising from tensor metadata, allocation, layout, or operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TensorError {
    /// Tensor rank exceeds maximum allowed rank.
    RankOverflow {
        /// Requested rank.
        rank: usize,
        /// Maximum permitted rank.
        max_rank: usize,
    },
    /// An arithmetic calculation (count, stride, offset, byte size) overflowed.
    ArithmeticOverflow {
        /// Description of the arithmetic operation that overflowed.
        operation: &'static str,
    },
    /// Storage allocation requested exceeds safe pre-allocation limits.
    AllocationLimitExceeded {
        /// Requested byte count.
        requested_bytes: usize,
        /// Maximum allowed byte allocation.
        max_bytes: usize,
    },
    /// Storage byte buffer length does not match expected size for shape and dtype.
    StorageLengthMismatch {
        /// Expected byte length.
        expected_bytes: usize,
        /// Actual byte length in buffer.
        actual_bytes: usize,
    },
    /// Dimension index is out of bounds for the tensor rank.
    DimensionOutOfBounds {
        /// Dimension index requested.
        dim: usize,
        /// Tensor rank.
        rank: usize,
    },
    /// Coordinate index along a dimension is out of bounds.
    IndexOutOfBounds {
        /// Dimension index.
        dim: usize,
        /// Coordinate requested.
        index: usize,
        /// Upper bound (dimension size).
        bound: usize,
    },
    /// Required memory span for view exceeds available storage capacity.
    StorageOutOfBounds {
        /// Required byte span.
        required_bytes: usize,
        /// Actual storage bytes available.
        storage_bytes: usize,
    },
    /// View byte offset violates the alignment requirement of the data type.
    MisalignedOffset {
        /// Requested byte offset.
        offset: usize,
        /// Required alignment in bytes.
        alignment: usize,
    },
    /// Shape rank does not match strides rank or index coordinate count.
    RankMismatch {
        /// Shape rank.
        shape_rank: usize,
        /// Strides or indices rank.
        other_rank: usize,
    },
    /// Reshape target shape has a different number of elements than the source.
    IncompatibleReshape {
        /// Source element count.
        source_elements: usize,
        /// Target element count.
        target_elements: usize,
    },
    /// View is not C-contiguous and cannot be reshaped without a contiguous copy.
    NonContiguousReshape,
    /// Slice parameters are invalid (start > end or end > bound).
    InvalidSlice {
        /// Dimension being sliced.
        dim: usize,
        /// Start index.
        start: usize,
        /// End index.
        end: usize,
        /// Upper bound (dimension size).
        bound: usize,
    },
    /// Slice step cannot be zero.
    ZeroStepSlice,
    /// Generation mismatch: tensor views or tensors from different generations cannot mix.
    GenerationMismatch {
        /// Expected generation.
        expected: Generation,
        /// Actual generation encountered.
        actual: Generation,
    },
    /// Element data type does not match requested or expected type.
    TypeMismatch {
        /// Expected data type.
        expected: DType,
        /// Actual data type.
        actual: DType,
    },
    /// Unrecognized or invalid data type name.
    InvalidDTypeName {
        /// The invalid string identifier.
        name: String,
    },
    /// Squeeze dimension size is greater than 1.
    InvalidSqueezeDimension {
        /// Dimension index requested to squeeze.
        dim: usize,
        /// Actual size of the dimension.
        size: usize,
    },
}

impl fmt::Display for TensorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RankOverflow { rank, max_rank } => {
                write!(
                    f,
                    "tensor rank {rank} exceeds maximum allowed rank {max_rank}"
                )
            }
            Self::ArithmeticOverflow { operation } => {
                write!(f, "arithmetic overflow during {operation}")
            }
            Self::AllocationLimitExceeded {
                requested_bytes,
                max_bytes,
            } => {
                write!(
                    f,
                    "requested allocation of {requested_bytes} bytes exceeds maximum limit of {max_bytes} bytes"
                )
            }
            Self::StorageLengthMismatch {
                expected_bytes,
                actual_bytes,
            } => {
                write!(
                    f,
                    "storage buffer length {actual_bytes} bytes does not match expected {expected_bytes} bytes"
                )
            }
            Self::DimensionOutOfBounds { dim, rank } => {
                write!(f, "dimension index {dim} is out of bounds for rank {rank}")
            }
            Self::IndexOutOfBounds { dim, index, bound } => {
                write!(
                    f,
                    "index {index} at dimension {dim} is out of bounds (bound {bound})"
                )
            }
            Self::StorageOutOfBounds {
                required_bytes,
                storage_bytes,
            } => {
                write!(
                    f,
                    "view memory span requires {required_bytes} bytes, but storage has only {storage_bytes} bytes"
                )
            }
            Self::MisalignedOffset { offset, alignment } => {
                write!(
                    f,
                    "byte offset {offset} is not aligned to required boundary of {alignment} bytes"
                )
            }
            Self::RankMismatch {
                shape_rank,
                other_rank,
            } => {
                write!(
                    f,
                    "rank mismatch: shape has rank {shape_rank}, other has rank {other_rank}"
                )
            }
            Self::IncompatibleReshape {
                source_elements,
                target_elements,
            } => {
                write!(
                    f,
                    "cannot reshape tensor with {source_elements} elements to shape with {target_elements} elements"
                )
            }
            Self::NonContiguousReshape => {
                write!(
                    f,
                    "cannot reshape a non-contiguous tensor view without copying"
                )
            }
            Self::InvalidSlice {
                dim,
                start,
                end,
                bound,
            } => {
                write!(
                    f,
                    "invalid slice on dimension {dim}: start={start}, end={end}, bound={bound}"
                )
            }
            Self::ZeroStepSlice => {
                write!(f, "slice step cannot be zero")
            }
            Self::GenerationMismatch { expected, actual } => {
                write!(
                    f,
                    "generation mismatch: expected generation {expected:?}, but got {actual:?}"
                )
            }
            Self::TypeMismatch { expected, actual } => {
                write!(
                    f,
                    "type mismatch: expected {expected:?}, but got {actual:?}"
                )
            }
            Self::InvalidDTypeName { name } => {
                write!(f, "invalid data type name: '{name}'")
            }
            Self::InvalidSqueezeDimension { dim, size } => {
                write!(
                    f,
                    "cannot squeeze dimension {dim} with size {size} (must be 1)"
                )
            }
        }
    }
}

impl Error for TensorError {}
