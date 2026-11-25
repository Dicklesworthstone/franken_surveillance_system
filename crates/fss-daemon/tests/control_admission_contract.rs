#![forbid(unsafe_code)]
//! Exact approval admission through the real owner-authenticated local IPC transport.

use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fss_core::{ContentDigest, PrincipalId, reference_contract_basis};
use fss_daemon::{
    ControlPlaneServer, ControlPlaneShared, ControlStatusSnapshot, DAEMON_STOP_TARGET, DaemonError,
    ERR_DAEMON_CONTROL_APPROVAL_001, ForwardBatchWriter, control_op_approval_digest,
};
use fss_ipc::{
    ActiveScrubStatus, BoundedControlOp, ControlOperationState, IpcClient, IpcClientConfig,
    IpcResponse, RingWatermarkStatus, deployment_root_digest,
};

type TestResult = Result<(), Box<dyn Error>>;
const SITE: &str = "site-control-admission";
const CAMERA_A: &str = "sensor:front";
const CAMERA_B: &str = "sensor:rear";

struct TempDeployment(PathBuf);

impl TempDeployment {
    fn new() -> Result<Self, Box<dyn Error>> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "fss-admit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self(path.canonicalize()?))
    }
}

impl Drop for TempDeployment {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct NoForwardedWrites;

impl ForwardBatchWriter for NoForwardedWrites {
    fn forward_delta_batch(
        &self,
        _batch_bytes: &[u8],
    ) -> Result<(u64, ContentDigest, ContentDigest), DaemonError> {
        Err(DaemonError::InvalidConfig {
            detail: "bounded-control test has no batch writer".to_owned(),
        })
    }
}

fn start_server(
    root: &TempDeployment,
) -> Result<(ControlPlaneServer, Arc<ControlPlaneShared>, IpcClient), Box<dyn Error>> {
    let shared = ControlPlaneShared::new(
        SITE,
        deployment_root_digest(&root.0),
        vec![CAMERA_A.to_owned(), CAMERA_B.to_owned()],
        ControlStatusSnapshot {
            head_commit_sequence: 0,
            history_root: ContentDigest::sha256(b"history"),
            state_root: ContentDigest::sha256(b"state"),
            cameras: Vec::new(),
            ring: RingWatermarkStatus {
                used_bytes: 0,
                capacity_bytes: 4096,
                watermark_percent: 0,
            },
            scrub: ActiveScrubStatus::Idle,
        },
        Arc::new(NoForwardedWrites),
    );
    let server = ControlPlaneServer::start(
        root.0.clone(),
        SITE.to_owned(),
        "control-admission-test".to_owned(),
        ContentDigest::sha256(b"manifest"),
        0,
        Arc::clone(&shared),
    )?;
    let mut config = IpcClientConfig::from_contract_basis(
        root.0.clone(),
        SITE,
        &reference_contract_basis(),
        PrincipalId::parse("principal:owner")?,
        vec!["CAP-AGENT-CAMERA-CONTROL-001".to_owned()],
    );
    config.io_timeout = Duration::from_secs(3);
    let client = IpcClient::connect(config)?;
    Ok((server, shared, client))
}

fn assert_approval_refused(response: IpcResponse, request_id: u64) {
    assert!(
        matches!(response, IpcResponse::Refused {
            request_id: actual,
            ref error_id,
            retryable: false,
            ..
        } if actual == request_id && error_id.as_str() == ERR_DAEMON_CONTROL_APPROVAL_001),
        "request {request_id} must refuse the mismatched approval: {response:?}"
    );
}

#[test]
fn every_control_binds_approval_to_deployment_operation_and_target_over_uds() -> TestResult {
    let root = TempDeployment::new()?;
    let (server, shared, mut client) = start_server(&root)?;
    let operations = [
        (BoundedControlOp::StartCamera, Some(CAMERA_A)),
        (BoundedControlOp::StopCamera, Some(CAMERA_A)),
        (BoundedControlOp::SnapshotCamera, Some(CAMERA_A)),
        (BoundedControlOp::ReloadManifest, None),
        (BoundedControlOp::ProbeDetect, Some(CAMERA_A)),
        (BoundedControlOp::ProbeDetect, None),
        (BoundedControlOp::TriggerScrub, None),
    ];
    for (op, target) in operations {
        let other_op = if op == BoundedControlOp::StartCamera {
            BoundedControlOp::StopCamera
        } else {
            BoundedControlOp::StartCamera
        };
        let other_target = target.map_or(Some(CAMERA_A), |_| Some(CAMERA_B));
        let wrong_approvals = [
            ContentDigest::sha256(b"unapproved"),
            control_op_approval_digest("site-other", op, target),
            control_op_approval_digest(SITE, other_op, target),
            control_op_approval_digest(SITE, op, other_target),
            shared.expected_stop_approval(),
        ];
        for approval in wrong_approvals {
            let request_id = client.next_request_id();
            let response = client.submit_bounded_control(
                request_id,
                op,
                target.map(str::to_owned),
                approval,
            )?;
            assert_approval_refused(response, request_id);
            assert!(shared.drain_control_commands().is_empty());
            assert!(!shared.is_shutdown_requested());
        }

        let approval = control_op_approval_digest(SITE, op, target);
        let request_id = client.next_request_id();
        let response =
            client.submit_bounded_control(request_id, op, target.map(str::to_owned), approval)?;
        let IpcResponse::ControlAccepted {
            request_id: accepted_id,
            operation_id,
            state: ControlOperationState::Queued,
        } = response
        else {
            return Err(format!("valid {op:?} request was not queued: {response:?}").into());
        };
        assert_eq!(accepted_id, request_id);
        let commands = shared.drain_control_commands();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].operation_id, operation_id);
        assert_eq!(commands[0].op, op);
        assert_eq!(commands[0].target_camera_id.as_deref(), target);
        assert_eq!(commands[0].approval_digest, approval);
    }
    drop(client);
    server.shutdown()?;
    Ok(())
}

#[test]
fn camera_stop_approval_cannot_stop_the_daemon_over_uds() -> TestResult {
    let root = TempDeployment::new()?;
    let (server, shared, mut client) = start_server(&root)?;
    for approval in [
        control_op_approval_digest(SITE, BoundedControlOp::StopCamera, Some(CAMERA_A)),
        control_op_approval_digest(SITE, BoundedControlOp::StopCamera, Some(DAEMON_STOP_TARGET)),
    ] {
        let request_id = client.next_request_id();
        let response = client.submit_bounded_control(
            request_id,
            BoundedControlOp::StopCamera,
            Some(DAEMON_STOP_TARGET.to_owned()),
            approval,
        )?;
        assert_approval_refused(response, request_id);
        assert!(!shared.is_shutdown_requested());
    }
    let request_id = client.next_request_id();
    let response = client.submit_bounded_control(
        request_id,
        BoundedControlOp::StopCamera,
        Some(DAEMON_STOP_TARGET.to_owned()),
        shared.expected_stop_approval(),
    )?;
    assert!(matches!(
        response,
        IpcResponse::ControlAccepted {
            request_id: actual,
            state: ControlOperationState::Accepted,
            ..
        } if actual == request_id
    ));
    assert!(shared.is_shutdown_requested());
    assert!(shared.drain_control_commands().is_empty());
    drop(client);
    server.shutdown()?;
    Ok(())
}
