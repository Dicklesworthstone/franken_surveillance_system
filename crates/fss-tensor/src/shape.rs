//! Multi-dimensional tensor shapes with rank bounds and checked arithmetic.

use core::fmt;

use crate::dtype::DType;
use crate::error::TensorError;

/// Maximum tensor rank supported by the deterministic tensor runtime.
pub const MAX_TENSOR_RANK: usize = 8;

/// Tensor dimensions with bounded rank and checked arithmetic.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Shape {
    dims: Vec<usize>,
}

impl Shape {
    /// Constructs a new `Shape` from dimension sizes.
    ///
    /// # Errors
    /// Returns [`TensorError::RankOverflow`] if the number of dimensions exceeds [`MAX_TENSOR_RANK`].
    pub fn new(dims: impl Into<Vec<usize>>) -> Result<Self, TensorError> {
        let dims = dims.into();
        if dims.len() > MAX_TENSOR_RANK {
            return Err(TensorError::RankOverflow {
                rank: dims.len(),
                max_rank: MAX_TENSOR_RANK,
            });
        }
        Ok(Self { dims })
    }

    /// Constructs a scalar shape (rank 0).
    #[must_use]
    pub fn scalar() -> Self {
        Self { dims: Vec::new() }
    }

    /// Returns the rank (number of dimensions) of the shape.
    #[must_use]
    pub fn rank(&self) -> usize {
        self.dims.len()
    }

    /// Returns a slice of the dimension sizes.
    #[must_use]
    pub fn dims(&self) -> &[usize] {
        &self.dims
    }

    /// Returns `true` if this shape represents a scalar (rank 0).
    #[must_use]
    pub fn is_scalar(&self) -> bool {
        self.dims.is_empty()
    }

    /// Returns the size of the specified dimension.
    ///
    /// # Errors
    /// Returns [`TensorError::DimensionOutOfBounds`] if `idx >= rank`.
    pub fn dim(&self, idx: usize) -> Result<usize, TensorError> {
        self.dims
            .get(idx)
            .copied()
            .ok_or(TensorError::DimensionOutOfBounds {
                dim: idx,
                rank: self.dims.len(),
            })
    }

    /// Computes the total number of elements represented by this shape.
    ///
    /// Rank 0 scalars contain 1 element.
    /// If any dimension is 0, the element count is 0.
    ///
    /// # Errors
    /// Returns [`TensorError::ArithmeticOverflow`] if multiplying dimensions overflows `usize`.
    pub fn num_elements(&self) -> Result<usize, TensorError> {
        let mut count: usize = 1;
        for &d in &self.dims {
            count = count
                .checked_mul(d)
                .ok_or(TensorError::ArithmeticOverflow {
                    operation: "shape element count",
                })?;
        }
        Ok(count)
    }

    /// Computes the total byte size required to store elements of `dtype`.
    ///
    /// # Errors
    /// Returns [`TensorError::ArithmeticOverflow`] on calculation overflow.
    pub fn size_bytes(&self, dtype: DType) -> Result<usize, TensorError> {
        let elements = self.num_elements()?;
        elements
            .checked_mul(dtype.size_bytes())
            .ok_or(TensorError::ArithmeticOverflow {
                operation: "shape byte size",
            })
    }
}

impl fmt::Display for Shape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        for (i, d) in self.dims.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{d}")?;
        }
        write!(f, "]")
    }
}
