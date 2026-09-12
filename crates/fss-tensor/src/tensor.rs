//! High-level deterministic tensor representation with generation and content digest support.

use core::fmt;
use std::sync::Arc;

use fss_core::{ContentDigest, DigestAlgorithm, Generation, Sha256Hasher};

use crate::dtype::{DType, TensorScalar};
use crate::error::TensorError;
use crate::shape::Shape;
use crate::storage::{MAX_STORAGE_BYTES, TensorStorage};
use crate::stride::Strides;
use crate::view::TensorView;

/// A deterministic multi-dimensional tensor backed by an immutable storage buffer.
#[derive(Debug, Clone)]
pub struct Tensor {
    view: TensorView,
}

impl Tensor {
    /// Constructs a contiguous tensor from a typed slice of scalar values.
    ///
    /// # Errors
    /// Returns [`TensorError::StorageLengthMismatch`] if the number of values does not match `shape.num_elements()`.
    /// Returns [`TensorError::ArithmeticOverflow`] on calculation overflow.
    /// Returns [`TensorError::AllocationLimitExceeded`] if memory exceeds storage limits.
    pub fn from_values<T: TensorScalar>(
        shape: Shape,
        values: &[T],
        generation: Generation,
    ) -> Result<Self, TensorError> {
        let expected_elements = shape.num_elements()?;
        if values.len() != expected_elements {
            return Err(TensorError::StorageLengthMismatch {
                expected_bytes: expected_elements.checked_mul(T::DTYPE.size_bytes()).ok_or(
                    TensorError::ArithmeticOverflow {
                        operation: "expected bytes multiplication",
                    },
                )?,
                actual_bytes: values.len().checked_mul(T::DTYPE.size_bytes()).ok_or(
                    TensorError::ArithmeticOverflow {
                        operation: "actual bytes multiplication",
                    },
                )?,
            });
        }

        let total_bytes = shape.size_bytes(T::DTYPE)?;
        let mut buffer = Vec::with_capacity(total_bytes);
        for val in values {
            val.append_ne_bytes(&mut buffer);
        }

        let storage = Arc::new(TensorStorage::from_vec(buffer, generation)?);
        let strides = Strides::from_shape_row_major(&shape)?;
        let view = TensorView::new(storage, 0, T::DTYPE, shape, strides, generation)?;
        Ok(Self { view })
    }

    /// Constructs a contiguous tensor filled with zero-bytes.
    ///
    /// # Errors
    /// Returns [`TensorError::ArithmeticOverflow`] on calculation overflow.
    /// Returns [`TensorError::AllocationLimitExceeded`] if memory exceeds storage limits.
    pub fn zeros(shape: Shape, dtype: DType, generation: Generation) -> Result<Self, TensorError> {
        let total_bytes = shape.size_bytes(dtype)?;
        let storage = Arc::new(TensorStorage::zeros(total_bytes, generation)?);
        let strides = Strides::from_shape_row_major(&shape)?;
        let view = TensorView::new(storage, 0, dtype, shape, strides, generation)?;
        Ok(Self { view })
    }

    /// Constructs a tensor directly from a pre-validated `TensorView`.
    #[must_use]
    pub fn from_view(view: TensorView) -> Self {
        Self { view }
    }

    /// Asserts that two tensors belong to the identical generation, failing closed otherwise.
    ///
    /// # Errors
    /// Returns [`TensorError::GenerationMismatch`] if the generations differ.
    pub fn assert_same_generation(&self, other: &Self) -> Result<(), TensorError> {
        if self.generation() != other.generation() {
            return Err(TensorError::GenerationMismatch {
                expected: self.generation(),
                actual: other.generation(),
            });
        }
        Ok(())
    }

    /// Returns a reference to the inner `TensorView`.
    #[must_use]
    pub const fn view(&self) -> &TensorView {
        &self.view
    }

    /// Returns the data type of the tensor.
    #[must_use]
    pub const fn dtype(&self) -> DType {
        self.view.dtype()
    }

    /// Returns the shape of the tensor.
    #[must_use]
    pub fn shape(&self) -> &Shape {
        self.view.shape()
    }

    /// Returns the strides of the tensor.
    #[must_use]
    pub fn strides(&self) -> &Strides {
        self.view.strides()
    }

    /// Returns the generation of the tensor.
    #[must_use]
    pub const fn generation(&self) -> Generation {
        self.view.generation()
    }

    /// Returns the rank of the tensor.
    #[must_use]
    pub fn rank(&self) -> usize {
        self.view.rank()
    }

    /// Returns the total number of elements.
    ///
    /// # Errors
    /// Returns [`TensorError::ArithmeticOverflow`] on overflow.
    pub fn num_elements(&self) -> Result<usize, TensorError> {
        self.view.num_elements()
    }

    /// Returns `true` if the layout is row-major C-contiguous.
    #[must_use]
    pub fn is_c_contiguous(&self) -> bool {
        self.view.is_c_contiguous()
    }

    /// Returns a strided slice along dimension `dim`.
    ///
    /// # Errors
    /// Returns [`TensorError::DimensionOutOfBounds`] or [`TensorError::InvalidSlice`].
    pub fn slice(
        &self,
        dim: usize,
        start: usize,
        end: usize,
        step: usize,
    ) -> Result<Self, TensorError> {
        let sliced_view = self.view.slice(dim, start, end, step)?;
        Ok(Self { view: sliced_view })
    }

    /// Transposes two dimensions without copying backing storage.
    ///
    /// # Errors
    /// Returns [`TensorError::DimensionOutOfBounds`] if either index exceeds rank.
    pub fn transpose(&self, dim0: usize, dim1: usize) -> Result<Self, TensorError> {
        let transposed_view = self.view.transpose(dim0, dim1)?;
        Ok(Self {
            view: transposed_view,
        })
    }

    /// Reshapes a C-contiguous tensor to `new_shape` without copying.
    ///
    /// # Errors
    /// Returns [`TensorError::NonContiguousReshape`] if the tensor is not contiguous.
    /// Returns [`TensorError::IncompatibleReshape`] if element counts differ.
    pub fn reshape(&self, new_shape: Shape) -> Result<Self, TensorError> {
        let reshaped_view = self.view.reshape(new_shape)?;
        Ok(Self {
            view: reshaped_view,
        })
    }

    /// Removes a dimension of size 1.
    ///
    /// # Errors
    /// Returns [`TensorError::DimensionOutOfBounds`] or [`TensorError::InvalidSlice`].
    pub fn squeeze(&self, dim: Option<usize>) -> Result<Self, TensorError> {
        let squeezed_view = self.view.squeeze(dim)?;
        Ok(Self {
            view: squeezed_view,
        })
    }

    /// Inserts a new dimension of size 1 at `dim`.
    ///
    /// # Errors
    /// Returns [`TensorError::DimensionOutOfBounds`] or [`TensorError::RankOverflow`].
    pub fn unsqueeze(&self, dim: usize) -> Result<Self, TensorError> {
        let unsqueezed_view = self.view.unsqueeze(dim)?;
        Ok(Self {
            view: unsqueezed_view,
        })
    }

    /// Reads a scalar element at coordinate `indices`.
    ///
    /// # Errors
    /// Returns [`TensorError::TypeMismatch`], [`TensorError::RankMismatch`], or [`TensorError::IndexOutOfBounds`].
    pub fn read_element<T: TensorScalar>(&self, indices: &[usize]) -> Result<T, TensorError> {
        self.view.read_element(indices)
    }

    /// Extracts all elements in row-major logical coordinate order as a `Vec<T>`.
    ///
    /// # Errors
    /// Returns [`TensorError::TypeMismatch`] if `T::DTYPE != self.dtype()`.
    /// Returns [`TensorError::ArithmeticOverflow`] on calculation overflow.
    /// Returns [`TensorError::AllocationLimitExceeded`] if memory required exceeds [`MAX_STORAGE_BYTES`].
    /// Returns reading or index errors.
    pub fn to_vec<T: TensorScalar>(&self) -> Result<Vec<T>, TensorError> {
        if T::DTYPE != self.dtype() {
            return Err(TensorError::TypeMismatch {
                expected: self.dtype(),
                actual: T::DTYPE,
            });
        }

        let total_elements = self.num_elements()?;
        let elem_size = core::mem::size_of::<T>();
        let total_bytes =
            total_elements
                .checked_mul(elem_size)
                .ok_or(TensorError::ArithmeticOverflow {
                    operation: "to_vec byte allocation",
                })?;

        if total_bytes > MAX_STORAGE_BYTES {
            return Err(TensorError::AllocationLimitExceeded {
                requested_bytes: total_bytes,
                max_bytes: MAX_STORAGE_BYTES,
            });
        }

        let mut result = Vec::with_capacity(total_elements);

        if self.shape().is_scalar() {
            let val: T = self.read_element(&[])?;
            result.push(val);
            return Ok(result);
        }

        let rank = self.rank();
        let dims = self.shape().dims();
        if dims.contains(&0) {
            return Ok(result);
        }

        let mut coords = vec![0; rank];
        for _ in 0..total_elements {
            let val: T = self.read_element(&coords)?;
            result.push(val);

            // Increment coordinates in row-major (odometer) order
            for i in (0..rank).rev() {
                coords[i] += 1;
                if coords[i] < dims[i] {
                    break;
                }
                coords[i] = 0;
            }
        }

        Ok(result)
    }

    /// Returns a new C-contiguous tensor containing identical logical elements.
    ///
    /// If this tensor is already C-contiguous and begins at offset 0 with exact storage length,
    /// this clones the view (sharing storage). Otherwise, it copies logical elements into a new buffer.
    ///
    /// # Errors
    /// Returns [`TensorError::ArithmeticOverflow`] or [`TensorError::AllocationLimitExceeded`].
    pub fn to_contiguous(&self) -> Result<Self, TensorError> {
        if self.is_c_contiguous() && self.view.offset_bytes() == 0 {
            let expected_bytes = self.shape().size_bytes(self.dtype())?;
            if self.view.storage().len() == expected_bytes {
                return Ok(self.clone());
            }
        }

        let total_elements = self.num_elements()?;
        let elem_size = self.dtype().size_bytes();
        let total_bytes =
            total_elements
                .checked_mul(elem_size)
                .ok_or(TensorError::ArithmeticOverflow {
                    operation: "contiguous buffer size multiplication",
                })?;

        if total_bytes > MAX_STORAGE_BYTES {
            return Err(TensorError::AllocationLimitExceeded {
                requested_bytes: total_bytes,
                max_bytes: MAX_STORAGE_BYTES,
            });
        }

        let mut buffer = Vec::with_capacity(total_bytes);

        if self.shape().is_scalar() {
            let bytes = self
                .view
                .storage()
                .slice_range(self.view.offset_bytes(), elem_size)?;
            buffer.extend_from_slice(bytes);
        } else {
            let rank = self.rank();
            let dims = self.shape().dims();
            if !dims.contains(&0) {
                let mut coords = vec![0; rank];
                for _ in 0..total_elements {
                    let elem_offset = self.strides().element_offset(&coords, self.shape())?;
                    let byte_offset = elem_offset.checked_mul(elem_size).ok_or(
                        TensorError::ArithmeticOverflow {
                            operation: "element byte offset multiplication",
                        },
                    )?;
                    let abs_offset = self.view.offset_bytes().checked_add(byte_offset).ok_or(
                        TensorError::ArithmeticOverflow {
                            operation: "absolute byte offset accumulation",
                        },
                    )?;
                    let bytes = self.view.storage().slice_range(abs_offset, elem_size)?;
                    buffer.extend_from_slice(bytes);

                    for i in (0..rank).rev() {
                        coords[i] += 1;
                        if coords[i] < dims[i] {
                            break;
                        }
                        coords[i] = 0;
                    }
                }
            }
        }

        let storage = Arc::new(TensorStorage::from_vec(buffer, self.generation())?);
        let new_strides = Strides::from_shape_row_major(self.shape())?;
        let new_view = TensorView::new(
            storage,
            0,
            self.dtype(),
            self.shape().clone(),
            new_strides,
            self.generation(),
        )?;
        Ok(Self { view: new_view })
    }

    /// Computes a deterministic SHA-256 content digest of metadata and logical payload bytes.
    ///
    /// # Errors
    /// Returns [`TensorError::ArithmeticOverflow`] on calculation overflow.
    pub fn content_digest(&self) -> Result<ContentDigest, TensorError> {
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"fss.tensor.v1\0");
        hasher.update(&[self.dtype().type_tag()]);
        hasher.update(&self.generation().get().to_be_bytes());
        hasher.update(&[self.rank() as u8]);
        for &d in self.shape().dims() {
            hasher.update(&(d as u64).to_be_bytes());
        }

        // Hash contiguous logical payload bytes
        let elem_size = self.dtype().size_bytes();
        let total_elements = self.num_elements()?;

        if self.shape().is_scalar() {
            let bytes = self
                .view
                .storage()
                .slice_range(self.view.offset_bytes(), elem_size)?;
            hasher.update(bytes);
        } else {
            let rank = self.rank();
            let dims = self.shape().dims();
            if !dims.contains(&0) {
                let mut coords = vec![0; rank];
                for _ in 0..total_elements {
                    let elem_offset = self.strides().element_offset(&coords, self.shape())?;
                    let byte_offset = elem_offset.checked_mul(elem_size).ok_or(
                        TensorError::ArithmeticOverflow {
                            operation: "digest byte offset multiplication",
                        },
                    )?;
                    let abs_offset = self.view.offset_bytes().checked_add(byte_offset).ok_or(
                        TensorError::ArithmeticOverflow {
                            operation: "digest absolute offset accumulation",
                        },
                    )?;
                    let bytes = self.view.storage().slice_range(abs_offset, elem_size)?;
                    hasher.update(bytes);

                    for i in (0..rank).rev() {
                        coords[i] += 1;
                        if coords[i] < dims[i] {
                            break;
                        }
                        coords[i] = 0;
                    }
                }
            }
        }

        let digest_bytes = hasher
            .finalize()
            .map_err(|_| TensorError::ArithmeticOverflow {
                operation: "sha256 digest finalization",
            })?;
        Ok(ContentDigest::new(DigestAlgorithm::Sha256, digest_bytes))
    }
}

impl fmt::Display for Tensor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Tensor(dtype={}, shape={}, strides={}, gen={})",
            self.dtype(),
            self.shape(),
            self.strides(),
            self.generation().get()
        )
    }
}
