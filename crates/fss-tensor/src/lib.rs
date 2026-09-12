#![forbid(unsafe_code)]
//! Deterministic reference tensor core for Franken Surveillance System.
//!
//! Provides fundamental data types, bounded shapes, checked strides, immutable
//! generation-pinned storage buffers, non-aliasing views, and generation-isolated tensors.
//!
//! Conforms to Frankentorch semantics:
//! - Separation of dtype, shape, stride, storage, view, and version/generation.
//! - Views cannot outlive or reinterpret backing generation.
//! - Checked arithmetic prevents panics and overflows on hostile metadata.
//! - Out-of-bounds aliasing is strictly prohibited.

pub mod dtype;
pub mod error;
pub mod shape;
pub mod storage;
pub mod stride;
pub mod tensor;
pub mod view;

pub use dtype::{BF16, DType, F16, TensorScalar};
pub use error::TensorError;
pub use shape::{MAX_TENSOR_RANK, Shape};
pub use storage::{MAX_STORAGE_BYTES, StorageId, TensorStorage};
pub use stride::Strides;
pub use tensor::Tensor;
pub use view::TensorView;
