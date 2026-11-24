#![forbid(unsafe_code)]
//! Canonical wire protocol, framing bounds, and capability validation tests for `fss-ipc`.

use std::error::Error;
use std::io::Cursor;

use fss_core::{
    CanonicalDecode, CanonicalEncode, ContentDigest, DeltaPriority, MeaningfulDeltaClass,
    OperationId, PrincipalId, validate_error_id,
};
use fss_ipc::{
    ActiveScrubStatus, BoundedControlOp, CameraLiveStatus, ControlOperationState,
    DeltaEventSummary, ERR_DAEMON_OFFLINE_001, ERR_IPC_HANDSHAKE_MISMATCH_001, FrameFlags,
    HandshakeAccepted, HandshakeRejected, HandshakeRequest, HandshakeResponse, IPC_ERROR_IDS,
    IPC_PROTOCOL_VERSION, IpcError, IpcRequest, IpcResponse, LiveDaemonStatus,
    MAX_REQUEST_FRAME_BYTES, MAX_RESPONSE_FRAME_BYTES, RingWatermarkStatus, StreamEndReason,
    crc32c, decode_frame_from_slice, encode_frame_header, encode_frame_to_vec, parse_error_id,
    read_frame, validate_capabilities,
};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn all_ipc_error_ids_match_stable_registry_pattern() -> TestResult {
    assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    for id in IPC_ERROR_IDS {
        validate_error_id(id)?;
        let parsed = parse_error_id(id)?;
        assert_eq!(parsed.as_str(), *id);
    }
    Ok(())
}

#[test]
fn canonical_wire_round_trip_every_message_variant() -> TestResult {
    let digest_a = ContentDigest::sha256(b"digest-a");
    let digest_b = ContentDigest::sha256(b"digest-b");
    let principal = PrincipalId::parse("principal:local-operator")?;

    let handshake_req = HandshakeRequest {
        protocol_version: IPC_PROTOCOL_VERSION,
        deployment_id: "site:alpha".to_owned(),
        deployment_root_digest: digest_a,
        contract_basis_digest: digest_b,
        principal,
        capabilities: vec![
            "cap.observe.status".to_owned(),
            "cap.ledger.append".to_owned(),
        ],
    };
    handshake_req.validate()?;
    let frame = encode_frame_to_vec(
        FrameFlags::HANDSHAKE,
        &handshake_req.try_canonical_bytes()?,
        MAX_REQUEST_FRAME_BYTES,
    )?;
    let decoded_frame = decode_frame_from_slice(&frame, MAX_REQUEST_FRAME_BYTES)?;
    assert_eq!(
        HandshakeRequest::from_canonical_bytes(&decoded_frame.payload)?,
        handshake_req
    );

    let handshake_resps = [
        HandshakeResponse::Accepted(HandshakeAccepted {
            protocol_version: IPC_PROTOCOL_VERSION,
            deployment_id: "site:alpha".to_owned(),
            deployment_root_digest: digest_a,
            contract_basis_digest: digest_b,
            daemon_instance_id: "daemon:01".to_owned(),
            granted_capabilities: vec!["cap.observe.status".to_owned()],
            head_commit_sequence: 77,
        }),
        HandshakeResponse::Rejected(HandshakeRejected {
            error_id: parse_error_id(ERR_IPC_HANDSHAKE_MISMATCH_001)?,
            reason: "basis mismatch".to_owned(),
            expected_protocol_version: IPC_PROTOCOL_VERSION,
        }),
    ];
    for resp in &handshake_resps {
        let bytes = resp.try_canonical_bytes()?;
        assert_eq!(HandshakeResponse::from_canonical_bytes(&bytes)?, *resp);
    }

    let requests = vec![
        IpcRequest::SubmitDeltaBatch {
            request_id: 1,
            idempotency_key: digest_a,
            batch_bytes: b"canonical-batch-bytes".to_vec(),
            approval_digest: Some(digest_b),
        },
        IpcRequest::SubmitDeltaBatch {
            request_id: 2,
            idempotency_key: digest_b,
            batch_bytes: Vec::new(),
            approval_digest: None,
        },
        IpcRequest::QueryLiveStatus {
            request_id: 3,
            include_cameras: true,
            include_ring: false,
        },
        IpcRequest::SubscribeDeltas {
            request_id: 4,
            since_commit_seq: 99,
            max_batch: 64,
        },
        IpcRequest::SubmitBoundedControl {
            request_id: 5,
            op: BoundedControlOp::StartCamera,
            target_camera_id: Some("cam-01".to_owned()),
            approval_digest: digest_a,
        },
        IpcRequest::SubmitBoundedControl {
            request_id: 6,
            op: BoundedControlOp::StopCamera,
            target_camera_id: Some("cam-02".to_owned()),
            approval_digest: digest_a,
        },
        IpcRequest::SubmitBoundedControl {
            request_id: 7,
            op: BoundedControlOp::SnapshotCamera,
            target_camera_id: Some("cam-03".to_owned()),
            approval_digest: digest_a,
        },
        IpcRequest::SubmitBoundedControl {
            request_id: 8,
            op: BoundedControlOp::ReloadManifest,
            target_camera_id: None,
            approval_digest: digest_b,
        },
        IpcRequest::SubmitBoundedControl {
            request_id: 9,
            op: BoundedControlOp::ProbeDetect,
            target_camera_id: None,
            approval_digest: digest_b,
        },
        IpcRequest::SubmitBoundedControl {
            request_id: 10,
            op: BoundedControlOp::TriggerScrub,
            target_camera_id: None,
            approval_digest: digest_b,
        },
        IpcRequest::CancelRequest {
            target_request_id: 5,
        },
    ];
    for req in &requests {
        let framed = encode_frame_to_vec(
            FrameFlags::REQUEST,
            &req.try_canonical_bytes()?,
            MAX_REQUEST_FRAME_BYTES,
        )?;
        let wf = decode_frame_from_slice(&framed, MAX_REQUEST_FRAME_BYTES)?;
        assert_eq!(IpcRequest::from_canonical_bytes(&wf.payload)?, *req);
    }

    let summary = DeltaEventSummary {
        delta_class: MeaningfulDeltaClass::CoverageLoss,
        priority: DeltaPriority::Critical,
        summary: "camera feed lost".to_owned(),
    };
    let summary_bytes = summary.try_canonical_bytes()?;
    assert_eq!(
        DeltaEventSummary::from_canonical_bytes(&summary_bytes)?,
        summary
    );

    let err_id = parse_error_id(ERR_DAEMON_OFFLINE_001)?;
    let responses = vec![
        IpcResponse::DeltaBatchCommitted {
            request_id: 1,
            commit_sequence: 11,
            history_root: digest_a,
            state_root: digest_b,
        },
        IpcResponse::LiveStatus(LiveDaemonStatus {
            request_id: 2,
            daemon_uptime_ms: 99_999,
            head_commit_sequence: 11,
            history_root: digest_a,
            state_root: digest_b,
            active_connections: 4,
            cameras: vec![CameraLiveStatus {
                camera_id: "cam-01".to_owned(),
                running: true,
                fps_milli: 30_000,
                reconnect_count: 2,
                queue_depth: 5,
                frames_ingested: 1000,
            }],
            ring: Some(RingWatermarkStatus {
                used_bytes: 1234,
                capacity_bytes: 4096,
                watermark_percent: 30,
            }),
            scrub: ActiveScrubStatus::Running {
                checked_objects: 50,
                total_objects: 100,
            },
        }),
        IpcResponse::LiveStatus(LiveDaemonStatus {
            request_id: 20,
            daemon_uptime_ms: 1,
            head_commit_sequence: 0,
            history_root: digest_a,
            state_root: digest_b,
            active_connections: 0,
            cameras: Vec::new(),
            ring: None,
            scrub: ActiveScrubStatus::Completed {
                checked_objects: 100,
                anomalies_found: 0,
            },
        }),
        IpcResponse::LiveStatus(LiveDaemonStatus {
            request_id: 21,
            daemon_uptime_ms: 1,
            head_commit_sequence: 0,
            history_root: digest_a,
            state_root: digest_b,
            active_connections: 0,
            cameras: Vec::new(),
            ring: None,
            scrub: ActiveScrubStatus::Failed {
                error_id: err_id.clone(),
            },
        }),
        IpcResponse::DeltaEvent {
            request_id: 4,
            commit_sequence: 12,
            delta_digest: digest_a,
            summary_canonical: summary_bytes,
        },
        IpcResponse::StreamEnd {
            request_id: 4,
            reason: StreamEndReason::Completed,
        },
        IpcResponse::StreamEnd {
            request_id: 4,
            reason: StreamEndReason::BatchLimitReached,
        },
        IpcResponse::StreamEnd {
            request_id: 4,
            reason: StreamEndReason::Cancelled,
        },
        IpcResponse::StreamEnd {
            request_id: 4,
            reason: StreamEndReason::DaemonShuttingDown,
        },
        IpcResponse::StreamEnd {
            request_id: 4,
            reason: StreamEndReason::CursorStale,
        },
        IpcResponse::ControlAccepted {
            request_id: 5,
            operation_id: OperationId::parse("op:ctrl:5")?,
            state: ControlOperationState::Queued,
        },
        IpcResponse::ControlAccepted {
            request_id: 6,
            operation_id: OperationId::parse("op:ctrl:6")?,
            state: ControlOperationState::Executing,
        },
        IpcResponse::ControlAccepted {
            request_id: 7,
            operation_id: OperationId::parse("op:ctrl:7")?,
            state: ControlOperationState::Completed,
        },
        IpcResponse::Cancelled { request_id: 8 },
        IpcResponse::Refused {
            request_id: 9,
            error_id: err_id,
            reason: "refused for test".to_owned(),
            retryable: true,
        },
    ];
    for resp in &responses {
        let framed = encode_frame_to_vec(
            FrameFlags::RESPONSE,
            &resp.try_canonical_bytes()?,
            MAX_RESPONSE_FRAME_BYTES,
        )?;
        let wf = decode_frame_from_slice(&framed, MAX_RESPONSE_FRAME_BYTES)?;
        assert_eq!(IpcResponse::from_canonical_bytes(&wf.payload)?, *resp);
    }

    let mut corrupted = encode_frame_to_vec(FrameFlags::REQUEST, b"abc", MAX_REQUEST_FRAME_BYTES)?;
    if let Some(last) = corrupted.last_mut() {
        *last ^= 0xFF;
    }
    assert!(matches!(
        decode_frame_from_slice(&corrupted, MAX_REQUEST_FRAME_BYTES),
        Err(IpcError::ChecksumMismatch { .. })
    ));

    assert!(matches!(
        validate_capabilities(&["bearer:secret123".to_owned()]),
        Err(IpcError::InvalidCapability { .. })
    ));
    assert!(matches!(
        validate_capabilities(&["sk_live_12345".to_owned()]),
        Err(IpcError::InvalidCapability { .. })
    ));
    Ok(())
}

#[test]
fn oversized_frames_refused_before_allocation_for_request_and_response() -> TestResult {
    let huge_req_header = encode_frame_header(IPC_PROTOCOL_VERSION, FrameFlags::REQUEST, u32::MAX);
    let mut cursor = Cursor::new(huge_req_header);
    assert!(matches!(
        read_frame(&mut cursor, MAX_REQUEST_FRAME_BYTES),
        Err(IpcError::FrameTooLarge {
            limit: MAX_REQUEST_FRAME_BYTES,
            ..
        })
    ));

    let over_req_payload = (MAX_REQUEST_FRAME_BYTES - 16 + 1) as u32;
    let over_req_header =
        encode_frame_header(IPC_PROTOCOL_VERSION, FrameFlags::REQUEST, over_req_payload);
    let mut req_cursor = Cursor::new(over_req_header);
    assert!(matches!(
        read_frame(&mut req_cursor, MAX_REQUEST_FRAME_BYTES),
        Err(IpcError::FrameTooLarge {
            actual,
            limit: MAX_REQUEST_FRAME_BYTES
        }) if actual == MAX_REQUEST_FRAME_BYTES + 1
    ));

    let over_resp_payload = (MAX_RESPONSE_FRAME_BYTES - 16 + 1) as u32;
    let over_resp_header = encode_frame_header(
        IPC_PROTOCOL_VERSION,
        FrameFlags::RESPONSE,
        over_resp_payload,
    );
    let mut resp_cursor = Cursor::new(over_resp_header);
    assert!(matches!(
        read_frame(&mut resp_cursor, MAX_RESPONSE_FRAME_BYTES),
        Err(IpcError::FrameTooLarge {
            actual,
            limit: MAX_RESPONSE_FRAME_BYTES
        }) if actual == MAX_RESPONSE_FRAME_BYTES + 1
    ));
    Ok(())
}
