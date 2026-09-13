//! Tensor port declarations for graph inputs, outputs, and intermediate activations.

use core::fmt;

use fss_core::Generation;
use fss_tensor::{DType, Shape};

use crate::error::ModelIrError;

/// A typed tensor port specifying name, data type, shape, and generation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TensorPort {
    name: String,
    dtype: DType,
    shape: Shape,
    generation: Generation,
}

impl TensorPort {
    /// Constructs a new validated `TensorPort`.
    ///
    /// # Errors
    /// Returns [`ModelIrError::InvalidAttribute`] if `name` is empty or whitespace-only.
    pub fn new(
        name: impl Into<String>,
        dtype: DType,
        shape: Shape,
        generation: Generation,
    ) -> Result<Self, ModelIrError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(ModelIrError::InvalidAttribute {
                node_id: "port".to_string(),
                attr_name: "name".to_string(),
                reason: "tensor port name cannot be empty".to_string(),
            });
        }
        for &d in shape.dims() {
            if d > i64::MAX as usize {
                return Err(ModelIrError::ArithmeticOverflow {
                    operation: "tensor dimension exceeds i64::MAX",
                });
            }
        }
        let has_zero = shape.dims().contains(&0);
        if !has_zero && !shape.dims().is_empty() {
            let mut product: usize = 1;
            for &d in shape.dims() {
                product = product
                    .checked_mul(d)
                    .ok_or(ModelIrError::ArithmeticOverflow {
                        operation: "tensor element count calculation",
                    })?;
                if product > i64::MAX as usize {
                    return Err(ModelIrError::ArithmeticOverflow {
                        operation: "tensor element count exceeds i64::MAX",
                    });
                }
            }
        }
        Ok(Self {
            name,
            dtype,
            shape,
            generation,
        })
    }

    /// Returns the port name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the element data type.
    #[must_use]
    pub fn dtype(&self) -> DType {
        self.dtype
    }

    /// Returns a reference to the tensor shape.
    #[must_use]
    pub fn shape(&self) -> &Shape {
        &self.shape
    }

    /// Returns the tensor rank.
    #[must_use]
    pub fn rank(&self) -> usize {
        self.shape.rank()
    }

    /// Returns the model generation this tensor belongs to.
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
    }
}

impl fmt::Display for TensorPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} {} (gen={})",
            self.name,
            self.dtype,
            self.shape,
            self.generation.get()
        )
    }
}
