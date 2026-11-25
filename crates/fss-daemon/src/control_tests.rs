#![forbid(unsafe_code)]
//! Admission contracts for the actual daemon control handler, before supervisor effects.

use super::*;
use fss_core::PrincipalId;
use fss_ipc::{CancelReason, RequestCancelToken};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct NoForwardWrites;

impl ForwardBatchWriter for NoForwardWrites {
    fn forward_delta_batch(
        &self,
        _batch_bytes: &[u8],
    ) -> Result<(u64, ContentDigest, ContentDigest), DaemonError> {
        Err(DaemonError::InvalidConfig {
            detail: "control admission must not write an evidence batch".to_owned(),
        })
    }
}

fn handler() -> DaemonIpcHandlerAdapter {
    DaemonIpcHandlerAdapter {
        shared: ControlPlaneShared::new(
            "site-control",
            ContentDigest::sha256(b"deployment-root"),
            vec!["sensor:front".to_owned(), "sensor:rear".to_owned()],
            ControlStatusSnapshot {
                head_commit_sequence: 0,
                history_root: ContentDigest::sha256(b"history"),
                state_root: ContentDigest::sha256(b"state"),
                cameras: Vec::new(),
                ring: RingWatermarkStatus {
                    used_bytes: 0,
                    capacity_bytes: 1024,
                    watermark_percent: 0,
                },
                scrub: ActiveScrubStatus::Idle,
            },
            Arc::new(NoForwardWrites),
        ),
    }
}

fn context() -> Result<RequestContext, fss_core::ContractError> {
    Ok(RequestContext {
        connection_id: 1,
        request_id: 7,
        deployment_id: "site-control".to_owned(),
        contract_basis_digest: reference_contract_basis().basis_digest(),
        principal: PrincipalId::parse("principal:owner")?,
        granted_capabilities: vec!["CAP-AGENT-CAMERA-CONTROL-001".to_owned()],
        cancel: RequestCancelToken::new(),
    })
}

fn assert_refused(response: IpcResponse, expected_error: &str, expected_retryable: bool) {
    assert!(
        matches!(
            &response,
            IpcResponse::Refused { request_id: 7, error_id, retryable, .. }
                if error_id.as_str() == expected_error && *retryable == expected_retryable
        ),
        "expected {expected_error} (retryable={expected_retryable}), got {response:?}"
    );
}

#[test]
fn every_control_requires_its_exact_site_operation_and_target_approval() -> TestResult {
    let ctx = context()?;
    for (op, target) in [
        (BoundedControlOp::StartCamera, Some("sensor:front")),
        (BoundedControlOp::StopCamera, Some("sensor:front")),
        (BoundedControlOp::SnapshotCamera, Some("sensor:front")),
        (BoundedControlOp::ReloadManifest, None),
        (BoundedControlOp::ProbeDetect, Some("sensor:front")),
        (BoundedControlOp::ProbeDetect, None),
        (BoundedControlOp::TriggerScrub, None),
    ] {
        let handler = handler();
        for approval in [
            ContentDigest::sha256(b"arbitrary-unapproved-request"),
            control_op_approval_digest("site-other", op, target),
            control_op_approval_digest(
                "site-control",
                if op == BoundedControlOp::StopCamera {
                    BoundedControlOp::StartCamera
                } else {
                    BoundedControlOp::StopCamera
                },
                target,
            ),
            control_op_approval_digest("site-control", op, Some("sensor:rear")),
            handler.shared.expected_stop_approval(),
        ] {
            assert_refused(
                handler.submit_bounded_control(&ctx, op, target, approval),
                ERR_DAEMON_CONTROL_APPROVAL_001,
                false,
            );
            assert!(handler.shared.drain_control_commands().is_empty());
            assert!(!handler.shared.is_shutdown_requested());
        }

        let approval = control_op_approval_digest("site-control", op, target);
        let response = handler.submit_bounded_control(&ctx, op, target, approval);
        let IpcResponse::ControlAccepted {
            operation_id,
            state,
            ..
        } = response
        else {
            return Err(format!("valid approval refused: {response:?}").into());
        };
        assert_eq!(state, ControlOperationState::Queued);
        assert_eq!(
            handler.shared.drain_control_commands(),
            vec![PendingControlCommand {
                operation_id,
                op,
                target_camera_id: target.map(str::to_owned),
                approval_digest: approval,
            }]
        );
    }
    Ok(())
}

#[test]
fn control_handler_refuses_missing_unknown_and_ignored_targets() -> TestResult {
    let handler = handler();
    let ctx = context()?;
    for op in [
        BoundedControlOp::StartCamera,
        BoundedControlOp::StopCamera,
        BoundedControlOp::SnapshotCamera,
    ] {
        assert_refused(
            handler.submit_bounded_control(
                &ctx,
                op,
                None,
                control_op_approval_digest("site-control", op, None),
            ),
            ERR_IPC_WIRE_CORRUPT_001,
            false,
        );
    }
    for op in [
        BoundedControlOp::ReloadManifest,
        BoundedControlOp::TriggerScrub,
    ] {
        let target = Some("sensor:front");
        assert_refused(
            handler.submit_bounded_control(
                &ctx,
                op,
                target,
                control_op_approval_digest("site-control", op, target),
            ),
            ERR_IPC_WIRE_CORRUPT_001,
            false,
        );
    }
    let op = BoundedControlOp::StartCamera;
    let target = Some("sensor:unknown");
    assert_refused(
        handler.submit_bounded_control(
            &ctx,
            op,
            target,
            control_op_approval_digest("site-control", op, target),
        ),
        ERR_DAEMON_UNKNOWN_CAMERA_001,
        false,
    );
    assert!(handler.shared.drain_control_commands().is_empty());
    assert!(!handler.shared.is_shutdown_requested());
    Ok(())
}

#[test]
fn cancelled_controls_cannot_queue_work_or_shut_down_the_daemon() -> TestResult {
    let handler = handler();
    let ctx = context()?;
    ctx.cancel.cancel(CancelReason::ClientCancelRequest);
    for (op, target, approval) in [
        (
            BoundedControlOp::StopCamera,
            Some("sensor:front"),
            control_op_approval_digest(
                "site-control",
                BoundedControlOp::StopCamera,
                Some("sensor:front"),
            ),
        ),
        (
            BoundedControlOp::StopCamera,
            Some(DAEMON_STOP_TARGET),
            handler.shared.expected_stop_approval(),
        ),
    ] {
        assert!(matches!(
            handler.submit_bounded_control(&ctx, op, target, approval),
            IpcResponse::Cancelled { request_id: 7 }
        ));
    }
    assert!(handler.shared.drain_control_commands().is_empty());
    assert!(!handler.shared.is_shutdown_requested());
    Ok(())
}

#[test]
fn full_control_queue_refuses_without_eviction_then_recovers_after_drain() -> TestResult {
    let handler = handler();
    let ctx = context()?;
    let op = BoundedControlOp::SnapshotCamera;
    let target = Some("sensor:front");
    let approval = control_op_approval_digest("site-control", op, target);
    let mut accepted_ids = Vec::new();
    for _ in 0..1024 {
        let response = handler.submit_bounded_control(&ctx, op, target, approval);
        let IpcResponse::ControlAccepted { operation_id, .. } = response else {
            return Err(format!("queue refused below the declared capacity: {response:?}").into());
        };
        accepted_ids.push(operation_id);
    }
    assert_refused(
        handler.submit_bounded_control(&ctx, op, target, approval),
        "ERR-BUDGET-EXHAUSTED-001",
        true,
    );
    let drained = handler.shared.drain_control_commands();
    assert_eq!(drained.len(), accepted_ids.len());
    assert_eq!(
        drained
            .into_iter()
            .map(|cmd| cmd.operation_id)
            .collect::<Vec<_>>(),
        accepted_ids,
        "capacity pressure must not evict an already acknowledged command"
    );
    assert!(matches!(
        handler.submit_bounded_control(&ctx, op, target, approval),
        IpcResponse::ControlAccepted {
            state: ControlOperationState::Queued,
            ..
        }
    ));
    assert_eq!(handler.shared.drain_control_commands().len(), 1);
    Ok(())
}

#[test]
fn poisoned_control_queue_refuses_work_but_allows_shutdown() -> TestResult {
    let handler = handler();
    let shared = Arc::clone(&handler.shared);
    let poison = std::thread::spawn(move || {
        let _guard = shared.control_queue.lock();
        panic!("test the poisoned queue refusal");
    });
    assert!(poison.join().is_err());
    assert!(handler.shared.control_queue.is_poisoned());
    let op = BoundedControlOp::StopCamera;
    let target = Some("sensor:front");
    assert_refused(
        handler.submit_bounded_control(
            &context()?,
            op,
            target,
            control_op_approval_digest("site-control", op, target),
        ),
        crate::error::ERR_DAEMON_SHUTDOWN_001,
        false,
    );
    assert!(matches!(
        handler.submit_bounded_control(
            &context()?,
            BoundedControlOp::StopCamera,
            Some(DAEMON_STOP_TARGET),
            handler.shared.expected_stop_approval(),
        ),
        IpcResponse::ControlAccepted {
            state: ControlOperationState::Accepted,
            ..
        }
    ));
    assert!(handler.shared.is_shutdown_requested());
    Ok(())
}

#[test]
fn shutdown_is_separately_approved_and_bypasses_queue_capacity() -> TestResult {
    let handler = handler();
    let ctx = context()?;
    let op = BoundedControlOp::StopCamera;
    assert_refused(
        handler.submit_bounded_control(
            &ctx,
            op,
            Some(DAEMON_STOP_TARGET),
            control_op_approval_digest("site-control", op, Some(DAEMON_STOP_TARGET)),
        ),
        ERR_DAEMON_CONTROL_APPROVAL_001,
        false,
    );
    assert!(!handler.shared.is_shutdown_requested());

    let target = Some("sensor:front");
    for _ in 0..1024 {
        assert!(matches!(
            handler.submit_bounded_control(
                &ctx,
                BoundedControlOp::SnapshotCamera,
                target,
                control_op_approval_digest(
                    "site-control",
                    BoundedControlOp::SnapshotCamera,
                    target
                ),
            ),
            IpcResponse::ControlAccepted { .. }
        ));
    }
    assert!(matches!(
        handler.submit_bounded_control(
            &ctx,
            op,
            Some(DAEMON_STOP_TARGET),
            handler.shared.expected_stop_approval(),
        ),
        IpcResponse::ControlAccepted {
            state: ControlOperationState::Accepted,
            ..
        }
    ));
    assert!(handler.shared.is_shutdown_requested());
    assert_refused(
        handler.submit_bounded_control(
            &ctx,
            op,
            target,
            control_op_approval_digest("site-control", op, target),
        ),
        ERR_IPC_SERVER_SHUTDOWN_001,
        true,
    );
    assert_eq!(handler.shared.drain_control_commands().len(), 1024);
    Ok(())
}
