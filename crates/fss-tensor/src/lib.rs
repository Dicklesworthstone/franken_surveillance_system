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

/// Deterministic decoded-frame and tensor buffer accounting (`FSS-058`).
pub mod buffer_accounting;
/// Canonical tensor byte encoding and digests (FSS-138).
pub mod canonical;
pub mod dtype;
pub mod error;
/// Generation-leased immutable decoded-frame pools (`FSS-119`).
pub mod frame_pool;
pub mod shape;
pub mod storage;
pub mod stride;
pub mod tensor;
pub mod view;

pub use buffer_accounting::{
    BUFFER_ACCOUNTING_SNAPSHOT_DOMAIN, BufferAccountant, BufferAccountingError,
    BufferAccountingPolicy, BufferAccountingSnapshot, BufferClass, BufferPressureTier,
    BufferReleaseReceipt, BufferReservationId, BufferReservationReceipt, BufferReservationRequest,
};
pub use dtype::{BF16, DType, F16, TensorScalar};
pub use error::TensorError;
pub use frame_pool::{
    FRAME_POOL_RECEIPT_DOMAIN, FrameDescriptor, FrameLease, FrameLeaseId, FramePool,
    FramePoolError, FramePoolPolicy, FramePoolReceipt, FrameSlotId,
};
pub use shape::{MAX_TENSOR_RANK, Shape};
pub use storage::{MAX_STORAGE_BYTES, StorageId, TensorStorage};
pub use stride::Strides;
pub use tensor::Tensor;
pub use view::TensorView;
