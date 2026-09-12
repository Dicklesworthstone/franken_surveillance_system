//! Typed tensor views enforcing alignment, bound safety, and generation integrity.

use std::sync::Arc;

use fss_core::Generation;

use crate::dtype::{DType, TensorScalar};
use crate::error::TensorError;
use crate::shape::{MAX_TENSOR_RANK, Shape};
use crate::storage::TensorStorage;
use crate::stride::Strides;

/// A typed view over a backing storage buffer.
///
/// Invariants enforced at construction:
/// 1. Generation: The view's generation strictly matches the storage buffer's generation.
/// 2. Rank: `shape.rank() == strides.rank()`.
/// 3. Alignment: `offset_bytes` is a multiple of `dtype.alignment()`.
/// 4. Out-of-bounds aliasing prohibition: The memory span `offset_bytes + strides.span_bytes()`
///    is strictly within the bounds of `storage.len()`.
#[derive(Debug, Clone)]
pub struct TensorView {
    storage: Arc<TensorStorage>,
    offset_bytes: usize,
    dtype: DType,
    shape: Shape,
    strides: Strides,
    generation: Generation,
}

impl TensorView {
    /// Constructs a validated `TensorView`.
    ///
    /// # Errors
    /// - [`TensorError::GenerationMismatch`] if `generation != storage.generation()`.
    /// - [`TensorError::RankMismatch`] if `shape.rank() != strides.rank()`.
    /// - [`TensorError::MisalignedOffset`] if `offset_bytes` is not aligned to `dtype.alignment()`.
    /// - [`TensorError::StorageOutOfBounds`] if the view's memory span exceeds storage capacity.
    /// - [`TensorError::ArithmeticOverflow`] if span calculations overflow.
    pub fn new(
        storage: Arc<TensorStorage>,
        offset_bytes: usize,
        dtype: DType,
        shape: Shape,
        strides: Strides,
        generation: Generation,
    ) -> Result<Self, TensorError> {
        if generation != storage.generation() {
            return Err(TensorError::GenerationMismatch {
                expected: storage.generation(),
                actual: generation,
            });
        }
        if shape.rank() != strides.rank() {
            return Err(TensorError::RankMismatch {
                shape_rank: shape.rank(),
                other_rank: strides.rank(),
            });
        }
        let align = dtype.alignment();
        if !offset_bytes.is_multiple_of(align) {
            return Err(TensorError::MisalignedOffset {
                offset: offset_bytes,
                alignment: align,
            });
        }

        // Bounded aliasing check: compute the span required by the view layout.
        let required_bytes = strides.span_bytes(&shape, dtype)?;
        let total_upper_bound =
            offset_bytes
                .checked_add(required_bytes)
                .ok_or(TensorError::ArithmeticOverflow {
                    operation: "view storage upper bound calculation",
                })?;

        if total_upper_bound > storage.len() {
            return Err(TensorError::StorageOutOfBounds {
                required_bytes: total_upper_bound,
                storage_bytes: storage.len(),
            });
        }

        Ok(Self {
            storage,
            offset_bytes,
            dtype,
            shape,
            strides,
            generation,
        })
    }

    /// Returns a reference to the underlying backing storage.
    #[must_use]
    pub fn storage(&self) -> &Arc<TensorStorage> {
        &self.storage
    }

    /// Returns the byte offset into the storage where this view begins.
    #[must_use]
    pub const fn offset_bytes(&self) -> usize {
        self.offset_bytes
    }

    /// Returns the data type of the view.
    #[must_use]
    pub const fn dtype(&self) -> DType {
        self.dtype
    }

    /// Returns a reference to the shape.
    #[must_use]
    pub fn shape(&self) -> &Shape {
        &self.shape
    }

    /// Returns a reference to the strides.
    #[must_use]
    pub fn strides(&self) -> &Strides {
        &self.strides
    }

    /// Returns the generation of the view.
    #[must_use]
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    /// Returns the rank of the tensor.
    #[must_use]
    pub fn rank(&self) -> usize {
        self.shape.rank()
    }

    /// Returns the total number of elements in the view.
    ///
    /// # Errors
    /// Returns [`TensorError::ArithmeticOverflow`] on overflow.
    pub fn num_elements(&self) -> Result<usize, TensorError> {
        self.shape.num_elements()
    }

    /// Returns `true` if the view layout is row-major (C-contiguous).
    #[must_use]
    pub fn is_c_contiguous(&self) -> bool {
        self.strides.is_c_contiguous(&self.shape)
    }

    /// Creates a strided slice view along dimension `dim`.
    ///
    /// Range `[start, end)` with stride `step`.
    ///
    /// # Errors
    /// Returns [`TensorError::DimensionOutOfBounds`] if `dim >= rank`.
    /// Returns [`TensorError::ZeroStepSlice`] if `step == 0`.
    /// Returns [`TensorError::InvalidSlice`] if `start > end` or `end > shape[dim]`.
    /// Returns [`TensorError::ArithmeticOverflow`] on index/offset overflow.
    pub fn slice(
        &self,
        dim: usize,
        start: usize,
        end: usize,
        step: usize,
    ) -> Result<Self, TensorError> {
        if dim >= self.shape.rank() {
            return Err(TensorError::DimensionOutOfBounds {
                dim,
                rank: self.shape.rank(),
            });
        }
        if step == 0 {
            return Err(TensorError::ZeroStepSlice);
        }
        let dim_size = self.shape.dims()[dim];
        if start > end || end > dim_size {
            return Err(TensorError::InvalidSlice {
                dim,
                start,
                end,
                bound: dim_size,
            });
        }

        let slice_len = end - start;
        let new_dim_size = if slice_len == 0 {
            0
        } else {
            slice_len.div_ceil(step)
        };

        let old_stride = self.strides.as_slice()[dim];
        let added_elem_offset =
            start
                .checked_mul(old_stride)
                .ok_or(TensorError::ArithmeticOverflow {
                    operation: "slice offset element multiplication",
                })?;
        let added_bytes = added_elem_offset
            .checked_mul(self.dtype.size_bytes())
            .ok_or(TensorError::ArithmeticOverflow {
                operation: "slice offset byte multiplication",
            })?;
        let new_offset_bytes =
            self.offset_bytes
                .checked_add(added_bytes)
                .ok_or(TensorError::ArithmeticOverflow {
                    operation: "slice new offset bytes accumulation",
                })?;

        let new_stride = old_stride
            .checked_mul(step)
            .ok_or(TensorError::ArithmeticOverflow {
                operation: "slice stride step multiplication",
            })?;

        let mut new_dims = self.shape.dims().to_vec();
        new_dims[dim] = new_dim_size;
        let new_shape = Shape::new(new_dims)?;

        let mut new_strides = self.strides.as_slice().to_vec();
        new_strides[dim] = new_stride;
        let new_strides = Strides::new(new_strides);

        Self::new(
            Arc::clone(&self.storage),
            new_offset_bytes,
            self.dtype,
            new_shape,
            new_strides,
            self.generation,
        )
    }

    /// Transposes two dimensions of the view without copying backing data.
    ///
    /// # Errors
    /// Returns [`TensorError::DimensionOutOfBounds`] if either index exceeds rank.
    pub fn transpose(&self, dim0: usize, dim1: usize) -> Result<Self, TensorError> {
        let rank = self.shape.rank();
        if dim0 >= rank {
            return Err(TensorError::DimensionOutOfBounds { dim: dim0, rank });
        }
        if dim1 >= rank {
            return Err(TensorError::DimensionOutOfBounds { dim: dim1, rank });
        }

        let mut new_dims = self.shape.dims().to_vec();
        new_dims.swap(dim0, dim1);
        let new_shape = Shape::new(new_dims)?;

        let mut new_strides = self.strides.as_slice().to_vec();
        new_strides.swap(dim0, dim1);
        let new_strides = Strides::new(new_strides);

        Self::new(
            Arc::clone(&self.storage),
            self.offset_bytes,
            self.dtype,
            new_shape,
            new_strides,
            self.generation,
        )
    }

    /// Reshapes the view into `new_shape` without copying.
    ///
    /// Note: Non-contiguous views cannot be reshaped without copying and will return
    /// [`TensorError::NonContiguousReshape`].
    ///
    /// # Errors
    /// Returns [`TensorError::IncompatibleReshape`] if element counts do not match.
    /// Returns [`TensorError::NonContiguousReshape`] if the view is not C-contiguous.
    pub fn reshape(&self, new_shape: Shape) -> Result<Self, TensorError> {
        let source_elements = self.num_elements()?;
        let target_elements = new_shape.num_elements()?;
        if source_elements != target_elements {
            return Err(TensorError::IncompatibleReshape {
                source_elements,
                target_elements,
            });
        }
        if !self.is_c_contiguous() {
            return Err(TensorError::NonContiguousReshape);
        }

        let new_strides = Strides::from_shape_row_major(&new_shape)?;
        Self::new(
            Arc::clone(&self.storage),
            self.offset_bytes,
            self.dtype,
            new_shape,
            new_strides,
            self.generation,
        )
    }

    /// Removes a dimension of size 1.
    ///
    /// If `dim` is `None`, removes all dimensions of size 1.
    ///
    /// # Errors
    /// Returns [`TensorError::DimensionOutOfBounds`] if specified `dim >= rank`.
    /// Returns [`TensorError::InvalidSlice`] if specified `dim` does not have size 1.
    pub fn squeeze(&self, dim: Option<usize>) -> Result<Self, TensorError> {
        let rank = self.shape.rank();
        let dims = self.shape.dims();
        let strides = self.strides.as_slice();

        let mut new_dims = Vec::new();
        let mut new_strides = Vec::new();

        if let Some(target_dim) = dim {
            if target_dim >= rank {
                return Err(TensorError::DimensionOutOfBounds {
                    dim: target_dim,
                    rank,
                });
            }
            if dims[target_dim] != 1 {
                return Err(TensorError::InvalidSlice {
                    dim: target_dim,
                    start: 0,
                    end: dims[target_dim],
                    bound: 1,
                });
            }
            for (i, (&d, &s)) in dims.iter().zip(strides).enumerate() {
                if i != target_dim {
                    new_dims.push(d);
                    new_strides.push(s);
                }
            }
        } else {
            for (&d, &s) in dims.iter().zip(strides) {
                if d != 1 {
                    new_dims.push(d);
                    new_strides.push(s);
                }
            }
        }

        let new_shape = Shape::new(new_dims)?;
        let new_strides = Strides::new(new_strides);
        Self::new(
            Arc::clone(&self.storage),
            self.offset_bytes,
            self.dtype,
            new_shape,
            new_strides,
            self.generation,
        )
    }

    /// Inserts a new dimension of size 1 at `dim`.
    ///
    /// # Errors
    /// Returns [`TensorError::DimensionOutOfBounds`] if `dim > rank`.
    /// Returns [`TensorError::RankOverflow`] if `rank + 1 > MAX_TENSOR_RANK`.
    pub fn unsqueeze(&self, dim: usize) -> Result<Self, TensorError> {
        let rank = self.shape.rank();
        if dim > rank {
            return Err(TensorError::DimensionOutOfBounds { dim, rank });
        }
        if rank + 1 > MAX_TENSOR_RANK {
            return Err(TensorError::RankOverflow {
                rank: rank + 1,
                max_rank: MAX_TENSOR_RANK,
            });
        }

        let mut new_dims = self.shape.dims().to_vec();
        new_dims.insert(dim, 1);
        let new_shape = Shape::new(new_dims)?;

        let mut new_strides = self.strides.as_slice().to_vec();
        // The stride for dimension of size 1: if followed by another dimension, stride of that dimension, else 1.
        let inserted_stride = if dim < self.strides.rank() {
            self.strides.as_slice()[dim]
        } else {
            1
        };
        new_strides.insert(dim, inserted_stride);
        let new_strides = Strides::new(new_strides);

        Self::new(
            Arc::clone(&self.storage),
            self.offset_bytes,
            self.dtype,
            new_shape,
            new_strides,
            self.generation,
        )
    }

    /// Reads a scalar element at the specified coordinate.
    ///
    /// # Errors
    /// Returns [`TensorError::TypeMismatch`] if `T::DTYPE != self.dtype`.
    /// Returns [`TensorError::RankMismatch`] if coordinate count does not match rank.
    /// Returns [`TensorError::IndexOutOfBounds`] if any coordinate is `>=` dimension size.
    /// Returns [`TensorError::StorageOutOfBounds`] if linear index is out of buffer.
    pub fn read_element<T: TensorScalar>(&self, indices: &[usize]) -> Result<T, TensorError> {
        if T::DTYPE != self.dtype {
            return Err(TensorError::TypeMismatch {
                expected: self.dtype,
                actual: T::DTYPE,
            });
        }
        let elem_offset = self.strides.element_offset(indices, &self.shape)?;
        let byte_offset = elem_offset.checked_mul(self.dtype.size_bytes()).ok_or(
            TensorError::ArithmeticOverflow {
                operation: "element byte offset multiplication",
            },
        )?;
        let absolute_offset =
            self.offset_bytes
                .checked_add(byte_offset)
                .ok_or(TensorError::ArithmeticOverflow {
                    operation: "absolute element byte offset accumulation",
                })?;

        let bytes = self
            .storage
            .slice_range(absolute_offset, self.dtype.size_bytes())?;
        T::from_ne_bytes(bytes)
    }
}
