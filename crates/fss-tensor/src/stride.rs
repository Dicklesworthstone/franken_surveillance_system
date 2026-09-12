//! Tensor strides, layout calculations, and checked coordinate-to-offset mapping.

use core::fmt;

use crate::dtype::DType;
use crate::error::TensorError;
use crate::shape::Shape;

/// Multi-dimensional element strides with checked arithmetic.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Strides {
    strides: Vec<usize>,
}

impl Strides {
    /// Constructs `Strides` directly from a vector of per-dimension element strides.
    #[must_use]
    pub fn new(strides: impl Into<Vec<usize>>) -> Self {
        Self {
            strides: strides.into(),
        }
    }

    /// Computes standard row-major (C-contiguous) strides for a given shape.
    ///
    /// # Errors
    /// Returns [`TensorError::ArithmeticOverflow`] if stride calculation overflows `usize`.
    pub fn from_shape_row_major(shape: &Shape) -> Result<Self, TensorError> {
        let rank = shape.rank();
        if rank == 0 {
            return Ok(Self {
                strides: Vec::new(),
            });
        }
        let dims = shape.dims();
        let mut strides = vec![0; rank];
        let mut running_stride: usize = 1;

        for i in (0..rank).rev() {
            strides[i] = running_stride;
            if i > 0 {
                running_stride =
                    running_stride
                        .checked_mul(dims[i])
                        .ok_or(TensorError::ArithmeticOverflow {
                            operation: "row-major stride calculation",
                        })?;
            }
        }
        Ok(Self { strides })
    }

    /// Returns a slice of the per-dimension element strides.
    #[must_use]
    pub fn as_slice(&self) -> &[usize] {
        &self.strides
    }

    /// Returns the rank (number of dimensions) of the strides.
    #[must_use]
    pub fn rank(&self) -> usize {
        self.strides.len()
    }

    /// Returns `true` if these strides represent a row-major (C-contiguous) layout for `shape`.
    #[must_use]
    pub fn is_c_contiguous(&self, shape: &Shape) -> bool {
        if self.rank() != shape.rank() {
            return false;
        }
        match Self::from_shape_row_major(shape) {
            Ok(expected) => self.strides == expected.strides,
            Err(_) => false,
        }
    }

    /// Computes the bounding span in elements required by `shape` with these strides.
    ///
    /// For empty shapes or shapes with any 0-sized dimension, the span is 0 elements.
    /// For rank-0 scalars, the span is 1 element.
    /// For non-empty shapes, the span is `max_element_offset + 1`.
    ///
    /// # Errors
    /// Returns [`TensorError::RankMismatch`] if shape rank does not match strides rank.
    /// Returns [`TensorError::ArithmeticOverflow`] if stride span calculation overflows.
    pub fn span_elements(&self, shape: &Shape) -> Result<usize, TensorError> {
        if self.rank() != shape.rank() {
            return Err(TensorError::RankMismatch {
                shape_rank: shape.rank(),
                other_rank: self.rank(),
            });
        }
        if shape.dims().contains(&0) {
            return Ok(0);
        }
        if shape.is_scalar() {
            return Ok(1);
        }

        let mut max_offset: usize = 0;
        for (&dim, &stride) in shape.dims().iter().zip(&self.strides) {
            let dim_max = (dim - 1)
                .checked_mul(stride)
                .ok_or(TensorError::ArithmeticOverflow {
                    operation: "stride span element multiplication",
                })?;
            max_offset =
                max_offset
                    .checked_add(dim_max)
                    .ok_or(TensorError::ArithmeticOverflow {
                        operation: "stride span element addition",
                    })?;
        }

        max_offset
            .checked_add(1)
            .ok_or(TensorError::ArithmeticOverflow {
                operation: "stride span upper bound",
            })
    }

    /// Computes the bounding span in bytes required by `shape` and `dtype` with these strides.
    ///
    /// # Errors
    /// Returns [`TensorError::ArithmeticOverflow`] if multiplication overflows.
    pub fn span_bytes(&self, shape: &Shape, dtype: DType) -> Result<usize, TensorError> {
        let elements = self.span_elements(shape)?;
        elements
            .checked_mul(dtype.size_bytes())
            .ok_or(TensorError::ArithmeticOverflow {
                operation: "stride byte span calculation",
            })
    }

    /// Computes the linear element offset for a given multi-dimensional coordinate.
    ///
    /// # Errors
    /// Returns [`TensorError::RankMismatch`] if the number of coordinate indices does not match shape rank.
    /// Returns [`TensorError::IndexOutOfBounds`] if any coordinate is `>=` dimension size.
    /// Returns [`TensorError::ArithmeticOverflow`] if offset arithmetic overflows.
    pub fn element_offset(&self, indices: &[usize], shape: &Shape) -> Result<usize, TensorError> {
        if indices.len() != shape.rank() {
            return Err(TensorError::RankMismatch {
                shape_rank: shape.rank(),
                other_rank: indices.len(),
            });
        }
        if self.rank() != shape.rank() {
            return Err(TensorError::RankMismatch {
                shape_rank: shape.rank(),
                other_rank: self.rank(),
            });
        }

        let mut offset: usize = 0;
        for (i, (&coord, (&dim_size, &stride))) in indices
            .iter()
            .zip(shape.dims().iter().zip(&self.strides))
            .enumerate()
        {
            if coord >= dim_size {
                return Err(TensorError::IndexOutOfBounds {
                    dim: i,
                    index: coord,
                    bound: dim_size,
                });
            }
            let step = coord
                .checked_mul(stride)
                .ok_or(TensorError::ArithmeticOverflow {
                    operation: "coordinate offset multiplication",
                })?;
            offset = offset
                .checked_add(step)
                .ok_or(TensorError::ArithmeticOverflow {
                    operation: "coordinate offset accumulation",
                })?;
        }

        Ok(offset)
    }
}

impl fmt::Display for Strides {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "strides[")?;
        for (i, s) in self.strides.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{s}")?;
        }
        write!(f, "]")
    }
}
