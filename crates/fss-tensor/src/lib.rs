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
/// Canonical `MediaDerivativeReceipt` lineage (`DOC-041`).
pub mod derivative_receipt;
pub mod dtype;
pub mod error;
/// Generation-leased immutable decoded-frame pools (`FSS-119`).
pub mod frame_pool;
/// Shared multi-scale frame pyramids, cache tiling, and accelerator isolation (`DOC-054`).
pub mod frame_pyramid;
/// Deterministic media movement, live delivery, archive tier, and portability card (`DOC-052`).
pub mod media_delivery_card;
/// Registered media pressure degradation ladder (`FSS-121`).
pub mod media_pressure;
/// Live preview bounded fan-out (`FSS-057`).
pub mod preview_fanout;
pub mod shape;
/// Source-to-tensor span and transform lineage (`FSS-120`).
pub mod source_lineage;
pub mod storage;
pub mod stride;
pub mod tensor;
pub mod view;

pub use buffer_accounting::{
    BUFFER_ACCOUNTING_SNAPSHOT_DOMAIN, BufferAccountant, BufferAccountingError,
    BufferAccountingPolicy, BufferAccountingSnapshot, BufferClass, BufferPressureTier,
    BufferReleaseReceipt, BufferReservationId, BufferReservationReceipt, BufferReservationRequest,
};
pub use derivative_receipt::{
    DerivativePublicationState, DerivativeReceiptError, DerivativeReceiptRequest,
    MEDIA_DERIVATIVE_RECEIPT_DOMAIN, MediaDerivativeKind, MediaDerivativeReceipt,
    ReproducibilityClass, SourceCustodyBinding,
};
pub use dtype::{BF16, DType, F16, TensorScalar};
pub use error::TensorError;
pub use frame_pool::{
    FRAME_POOL_RECEIPT_DOMAIN, FrameDescriptor, FrameLease, FrameLeaseId, FramePool,
    FramePoolError, FramePoolPolicy, FramePoolReceipt, FrameSlotId,
};
pub use frame_pyramid::{
    AcceleratorCandidate, AcceleratorGateDecision, FRAME_PYRAMID_RECEIPT_DOMAIN, FramePyramid,
    FramePyramidError, FramePyramidReceipt, PyramidLevelEntry, TilePlan, TileRegion,
    adjudicate_accelerator_against_scalar, downsample_2x_box_u8,
};
pub use media_delivery_card::{
    ArchiveStorageTier, BackendPlacementChild, ClampedDeliveryRejection, CodecSupportStatus,
    EvaluatedDeliveryOption, LiveDeliverySurface, LiveGatewaySpec,
    MEDIA_DELIVERY_DECISION_CARD_DOMAIN, MediaDeliveryCandidate, MediaDeliveryCardError,
    MediaDeliveryConstraints, MediaDeliveryDecisionCard, MediaMovementMode, TierPricingQuote,
    TranscodeJustification, evaluate_media_delivery_card,
};
pub use media_pressure::{
    MEDIA_PRESSURE_LADDER_RECEIPT_DOMAIN, MediaDegradationRung, MediaPressureController,
    MediaPressureDecisionReceipt, MediaPressureError, MediaPressurePolicy, MediaPressureSignals,
};
pub use preview_fanout::{
    FanoutPublishOutcome, PREVIEW_FANOUT_RECEIPT_DOMAIN, PreviewFanoutError, PreviewFanoutHub,
    PreviewFanoutPolicy, PreviewFanoutReceipt, PreviewFrameOffer, PreviewSubscriberSpec,
};
pub use shape::{MAX_TENSOR_RANK, Shape};
pub use source_lineage::{
    LineageError, SOURCE_TO_TENSOR_LINEAGE_DOMAIN, SourceByteSpan, SourceToTensorLineage,
    TransformStep,
};
pub use storage::{MAX_STORAGE_BYTES, StorageId, TensorStorage};
pub use stride::Strides;
pub use tensor::Tensor;
pub use view::TensorView;
