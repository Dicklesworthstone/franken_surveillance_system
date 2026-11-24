#![forbid(unsafe_code)]
//! Strictly typed canonical IPC request and response envelopes (zero Serde).

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, ErrorId, OperationId,
};

pub use crate::control::{
    BoundedControlOp, ControlOperationState, DeltaEventSummary, IPC_DELTA_SUMMARY_DIGEST_DOMAIN,
    StreamEndReason,
};
pub use crate::handshake::{
    HandshakeAccepted, HandshakeRejected, HandshakeRequest, HandshakeResponse,
    IPC_HANDSHAKE_DIGEST_DOMAIN, MAX_DEPLOYMENT_ID_BYTES, MAX_REASON_BYTES,
};
pub use crate::status::{
    ActiveScrubStatus, CameraLiveStatus, LiveDaemonStatus, MAX_CAMERA_ID_BYTES,
    MAX_CAMERAS_IN_STATUS, RingWatermarkStatus,
};
use crate::transport::MAX_REQUEST_PAYLOAD_BYTES;

/// Canonical digest domain for [`IpcRequest`].
pub const IPC_REQUEST_DIGEST_DOMAIN: &str = "fss.ipc.request.v1";

/// Canonical digest domain for [`IpcResponse`].
pub const IPC_RESPONSE_DIGEST_DOMAIN: &str = "fss.ipc.response.v1";

/// Maximum encoded delta batch bytes carried in [`IpcRequest::SubmitDeltaBatch`].
pub const MAX_DELTA_BATCH_WIRE_BYTES: usize = MAX_REQUEST_PAYLOAD_BYTES;

/// Maximum canonical summary bytes carried in a single [`IpcResponse::DeltaEvent`].
pub const MAX_DELTA_SUMMARY_BYTES: usize = 256 * 1024;

/// Strictly narrow, capability-scoped typed requests accepted over the local UDS channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpcRequest {
    /// Forward a canonical `EvidenceDeltaBatch` write to the owning single-writer daemon.
    SubmitDeltaBatch {
        /// Client-assigned correlation identifier.
        request_id: u64,
        /// Replay-safe idempotency digest.
        idempotency_key: ContentDigest,
        /// Canonical encoded `EvidenceDeltaBatch` payload bytes.
        batch_bytes: Vec<u8>,
        /// Optional operator approval digest when required by policy.
        approval_digest: Option<ContentDigest>,
    },
    /// Query live supervisor telemetry and ledger head state.
    QueryLiveStatus {
        /// Client-assigned correlation identifier.
        request_id: u64,
        /// Include per-camera FPS, reconnect counts, and queue depths.
        include_cameras: bool,
        /// Include retention ring byte watermark and percentage.
        include_ring: bool,
    },
    /// Subscribe to committed deltas after `since_commit_seq`, bounded by `max_batch`.
    SubscribeDeltas {
        /// Client-assigned correlation identifier.
        request_id: u64,
        /// Exclusive lower bound commit sequence.
        since_commit_seq: u64,
        /// Maximum number of `DeltaEvent` frames to deliver in this batch.
        max_batch: u32,
    },
    /// Submit one closed-enum bounded supervisor control operation with explicit approval digest.
    SubmitBoundedControl {
        /// Client-assigned correlation identifier.
        request_id: u64,
        /// Strictly closed bounded control operation.
        op: BoundedControlOp,
        /// Optional target camera identifier (required for camera-scoped ops).
        target_camera_id: Option<String>,
        /// Explicit approval digest pinning the planned control action.
        approval_digest: ContentDigest,
    },
    /// Cooperatively cancel an in-flight request by its target request identifier.
    CancelRequest {
        /// Identifier of the in-flight request to cancel.
        target_request_id: u64,
    },
}

impl IpcRequest {
    /// Returns the correlation identifier of this request.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        match self {
            Self::SubmitDeltaBatch { request_id, .. }
            | Self::QueryLiveStatus { request_id, .. }
            | Self::SubscribeDeltas { request_id, .. }
            | Self::SubmitBoundedControl { request_id, .. } => *request_id,
            Self::CancelRequest { target_request_id } => *target_request_id,
        }
    }

    /// Returns a stable operation label for JSONL tracing.
    #[must_use]
    pub const fn op_name(&self) -> &'static str {
        match self {
            Self::SubmitDeltaBatch { .. } => "submit_delta_batch",
            Self::QueryLiveStatus { .. } => "query_live_status",
            Self::SubscribeDeltas { .. } => "subscribe_deltas",
            Self::SubmitBoundedControl { .. } => "submit_bounded_control",
            Self::CancelRequest { .. } => "cancel_request",
        }
    }

    /// Computes the canonical domain-separated digest of this request.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        self.canonical_digest(IPC_REQUEST_DIGEST_DOMAIN)
    }
}

impl CanonicalEncode for IpcRequest {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::SubmitDeltaBatch {
                request_id,
                idempotency_key,
                batch_bytes,
                approval_digest,
            } => {
                encoder.tag(1);
                encoder.u64(*request_id);
                encoder.digest(*idempotency_key);
                encoder.bytes(batch_bytes);
                match approval_digest {
                    Some(digest) => {
                        encoder.bool(true);
                        encoder.digest(*digest);
                    }
                    None => encoder.bool(false),
                }
            }
            Self::QueryLiveStatus {
                request_id,
                include_cameras,
                include_ring,
            } => {
                encoder.tag(2);
                encoder.u64(*request_id);
                encoder.bool(*include_cameras);
                encoder.bool(*include_ring);
            }
            Self::SubscribeDeltas {
                request_id,
                since_commit_seq,
                max_batch,
            } => {
                encoder.tag(3);
                encoder.u64(*request_id);
                encoder.u64(*since_commit_seq);
                encoder.u32(*max_batch);
            }
            Self::SubmitBoundedControl {
                request_id,
                op,
                target_camera_id,
                approval_digest,
            } => {
                encoder.tag(4);
                encoder.u64(*request_id);
                op.encode_canonical(encoder);
                match target_camera_id {
                    Some(cam) => {
                        encoder.bool(true);
                        encoder.text(cam);
                    }
                    None => encoder.bool(false),
                }
                encoder.digest(*approval_digest);
            }
            Self::CancelRequest { target_request_id } => {
                encoder.tag(5);
                encoder.u64(*target_request_id);
            }
        }
    }
}

impl CanonicalDecode for IpcRequest {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.tag()? {
            1 => {
                let request_id = decoder.u64()?;
                let idempotency_key = decoder.digest()?;
                let raw_batch = decoder.bytes()?;
                if raw_batch.len() > MAX_DELTA_BATCH_WIRE_BYTES {
                    return Err(ContractError::InvalidDigest);
                }
                let approval_digest = if decoder.bool()? {
                    Some(decoder.digest()?)
                } else {
                    None
                };
                Ok(Self::SubmitDeltaBatch {
                    request_id,
                    idempotency_key,
                    batch_bytes: raw_batch.to_vec(),
                    approval_digest,
                })
            }
            2 => Ok(Self::QueryLiveStatus {
                request_id: decoder.u64()?,
                include_cameras: decoder.bool()?,
                include_ring: decoder.bool()?,
            }),
            3 => Ok(Self::SubscribeDeltas {
                request_id: decoder.u64()?,
                since_commit_seq: decoder.u64()?,
                max_batch: decoder.u32()?,
            }),
            4 => {
                let request_id = decoder.u64()?;
                let op = BoundedControlOp::decode_canonical(decoder)?;
                let target_camera_id = if decoder.bool()? {
                    let cam = decoder.text()?.to_owned();
                    if cam.is_empty() || cam.len() > MAX_CAMERA_ID_BYTES {
                        return Err(ContractError::InvalidIdentifier);
                    }
                    Some(cam)
                } else {
                    None
                };
                let approval_digest = decoder.digest()?;
                Ok(Self::SubmitBoundedControl {
                    request_id,
                    op,
                    target_camera_id,
                    approval_digest,
                })
            }
            5 => Ok(Self::CancelRequest {
                target_request_id: decoder.u64()?,
            }),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Strictly typed responses emitted by the local daemon over the UDS channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpcResponse {
    /// Confirms root-last commit of a forwarded `EvidenceDeltaBatch`.
    DeltaBatchCommitted {
        /// Correlated client request identifier.
        request_id: u64,
        /// Monotonic authoritative commit sequence assigned by the ledger.
        commit_sequence: u64,
        /// Updated canonical history root digest.
        history_root: ContentDigest,
        /// Updated canonical state root digest.
        state_root: ContentDigest,
    },
    /// Returns live daemon telemetry for `QueryLiveStatus`.
    LiveStatus(LiveDaemonStatus),
    /// Emits one committed delta event inside a `SubscribeDeltas` stream.
    DeltaEvent {
        /// Correlated subscription request identifier.
        request_id: u64,
        /// Commit sequence of the delivered delta.
        commit_sequence: u64,
        /// Content digest of the committed delta batch.
        delta_digest: ContentDigest,
        /// Canonical summary bytes (for example, an encoded [`DeltaEventSummary`]).
        summary_canonical: Vec<u8>,
    },
    /// Marks the deterministic end of a `SubscribeDeltas` stream.
    StreamEnd {
        /// Correlated subscription request identifier.
        request_id: u64,
        /// Terminal reason closing the stream.
        reason: StreamEndReason,
    },
    /// Confirms admission of a bounded control operation.
    ControlAccepted {
        /// Correlated client request identifier.
        request_id: u64,
        /// Stable operation identifier assigned by the supervisor.
        operation_id: OperationId,
        /// Current lifecycle state of the admitted operation.
        state: ControlOperationState,
    },
    /// Confirms cooperative cancellation of a request.
    Cancelled {
        /// Cancelled request identifier.
        request_id: u64,
    },
    /// Typed fail-closed refusal carrying a stable `ERR-...-NNN` error identity.
    Refused {
        /// Correlated client request identifier.
        request_id: u64,
        /// Stable machine-readable error identity.
        error_id: ErrorId,
        /// Non-secret diagnostic explanation.
        reason: String,
        /// Whether retry may succeed after backoff or state refresh.
        retryable: bool,
    },
}

impl IpcResponse {
    /// Returns the correlation identifier of this response.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        match self {
            Self::DeltaBatchCommitted { request_id, .. }
            | Self::DeltaEvent { request_id, .. }
            | Self::StreamEnd { request_id, .. }
            | Self::ControlAccepted { request_id, .. }
            | Self::Cancelled { request_id }
            | Self::Refused { request_id, .. } => *request_id,
            Self::LiveStatus(status) => status.request_id,
        }
    }

    /// Computes the canonical domain-separated digest of this response.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        self.canonical_digest(IPC_RESPONSE_DIGEST_DOMAIN)
    }
}

impl CanonicalEncode for IpcResponse {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::DeltaBatchCommitted {
                request_id,
                commit_sequence,
                history_root,
                state_root,
            } => {
                encoder.tag(1);
                encoder.u64(*request_id);
                encoder.u64(*commit_sequence);
                encoder.digest(*history_root);
                encoder.digest(*state_root);
            }
            Self::LiveStatus(status) => {
                encoder.tag(2);
                status.encode_canonical(encoder);
            }
            Self::DeltaEvent {
                request_id,
                commit_sequence,
                delta_digest,
                summary_canonical,
            } => {
                encoder.tag(3);
                encoder.u64(*request_id);
                encoder.u64(*commit_sequence);
                encoder.digest(*delta_digest);
                encoder.bytes(summary_canonical);
            }
            Self::StreamEnd { request_id, reason } => {
                encoder.tag(4);
                encoder.u64(*request_id);
                reason.encode_canonical(encoder);
            }
            Self::ControlAccepted {
                request_id,
                operation_id,
                state,
            } => {
                encoder.tag(5);
                encoder.u64(*request_id);
                operation_id.encode_canonical(encoder);
                state.encode_canonical(encoder);
            }
            Self::Cancelled { request_id } => {
                encoder.tag(6);
                encoder.u64(*request_id);
            }
            Self::Refused {
                request_id,
                error_id,
                reason,
                retryable,
            } => {
                encoder.tag(7);
                encoder.u64(*request_id);
                error_id.encode_canonical(encoder);
                encoder.text(reason);
                encoder.bool(*retryable);
            }
        }
    }
}

impl CanonicalDecode for IpcResponse {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.tag()? {
            1 => Ok(Self::DeltaBatchCommitted {
                request_id: decoder.u64()?,
                commit_sequence: decoder.u64()?,
                history_root: decoder.digest()?,
                state_root: decoder.digest()?,
            }),
            2 => Ok(Self::LiveStatus(LiveDaemonStatus::decode_canonical(
                decoder,
            )?)),
            3 => {
                let request_id = decoder.u64()?;
                let commit_sequence = decoder.u64()?;
                let delta_digest = decoder.digest()?;
                let summary_bytes = decoder.bytes()?;
                if summary_bytes.len() > MAX_DELTA_SUMMARY_BYTES {
                    return Err(ContractError::InvalidDigest);
                }
                Ok(Self::DeltaEvent {
                    request_id,
                    commit_sequence,
                    delta_digest,
                    summary_canonical: summary_bytes.to_vec(),
                })
            }
            4 => Ok(Self::StreamEnd {
                request_id: decoder.u64()?,
                reason: StreamEndReason::decode_canonical(decoder)?,
            }),
            5 => Ok(Self::ControlAccepted {
                request_id: decoder.u64()?,
                operation_id: OperationId::decode_canonical(decoder)?,
                state: ControlOperationState::decode_canonical(decoder)?,
            }),
            6 => Ok(Self::Cancelled {
                request_id: decoder.u64()?,
            }),
            7 => {
                let request_id = decoder.u64()?;
                let error_id = ErrorId::decode_canonical(decoder)?;
                let reason = decoder.text()?.to_owned();
                if reason.len() > MAX_REASON_BYTES {
                    return Err(ContractError::InvalidIdentifier);
                }
                let retryable = decoder.bool()?;
                Ok(Self::Refused {
                    request_id,
                    error_id,
                    reason,
                    retryable,
                })
            }
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}
