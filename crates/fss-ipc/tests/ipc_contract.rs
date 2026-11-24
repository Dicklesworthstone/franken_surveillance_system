#![forbid(unsafe_code)]
//! Live UDS security, handshake mismatch, oversized-header, and stale-socket recovery tests.

use std::error::Error;
use std::fs::{self, Permissions};
use std::io::Write;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fss_core::{
    CanonicalDecode, CanonicalEncode, ContentDigest, ContractBasis, OperationId, PrincipalId,
    reference_contract_basis,
};
use fss_ipc::{
    ActiveScrubStatus, BoundedControlOp, CameraLiveStatus, ControlOperationState, DaemonIpcHandler,
    DeltaStreamSink, DeploymentChannel, DeploymentClient, ERR_IPC_FRAME_TOO_LARGE_001,
    ERR_IPC_HANDSHAKE_MISMATCH_001, FrameFlags, HandshakeRequest, IPC_PROTOCOL_VERSION, IpcClient,
    IpcClientConfig, IpcError, IpcResponse, IpcServer, IpcServerConfig, LiveDaemonStatus,
    MAX_REQUEST_FRAME_BYTES, MAX_RESPONSE_FRAME_BYTES, RequestContext, RingWatermarkStatus,
    StreamEndReason, default_run_dir, default_socket_path, deployment_root_digest,
    encode_frame_header, read_frame, write_frame,
};

type TestResult = Result<(), Box<dyn Error>>;
static TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

struct TempDeployment {
    root: PathBuf,
}

impl TempDeployment {
    fn new(tag: &str) -> Result<Self, Box<dyn Error>> {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("fss-ipc-s-{}-{tag}-{seq}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for TempDeployment {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct SimpleHandler {
    head_seq: AtomicU64,
}

impl SimpleHandler {
    fn new() -> Self {
        Self {
            head_seq: AtomicU64::new(10),
        }
    }
}

impl DaemonIpcHandler for SimpleHandler {
    fn head_commit_sequence(&self) -> u64 {
        self.head_seq.load(Ordering::Acquire)
    }

    fn submit_delta_batch(
        &self,
        ctx: &RequestContext,
        idempotency_key: ContentDigest,
        batch_bytes: &[u8],
        _approval_digest: Option<ContentDigest>,
    ) -> IpcResponse {
        let seq = self.head_seq.fetch_add(1, Ordering::AcqRel) + 1;
        IpcResponse::DeltaBatchCommitted {
            request_id: ctx.request_id,
            commit_sequence: seq,
            history_root: ContentDigest::sha256(batch_bytes),
            state_root: idempotency_key,
        }
    }

    fn query_live_status(
        &self,
        ctx: &RequestContext,
        include_cameras: bool,
        include_ring: bool,
    ) -> IpcResponse {
        let cameras = if include_cameras {
            vec![CameraLiveStatus {
                camera_id: "cam-front-01".to_owned(),
                running: true,
                fps_milli: 29_970,
                reconnect_count: 1,
                queue_depth: 3,
                frames_ingested: 12_345,
            }]
        } else {
            Vec::new()
        };
        let ring = include_ring.then_some(RingWatermarkStatus {
            used_bytes: 512 * 1024 * 1024,
            capacity_bytes: 1024 * 1024 * 1024,
            watermark_percent: 50,
        });
        IpcResponse::LiveStatus(LiveDaemonStatus {
            request_id: ctx.request_id,
            daemon_uptime_ms: 42_000,
            head_commit_sequence: self.head_seq.load(Ordering::Acquire),
            history_root: ContentDigest::sha256(b"history"),
            state_root: ContentDigest::sha256(b"state"),
            active_connections: 1,
            cameras,
            ring,
            scrub: ActiveScrubStatus::Idle,
        })
    }

    fn subscribe_deltas(
        &self,
        _ctx: &RequestContext,
        _since_commit_seq: u64,
        _max_batch: u32,
        _sink: &mut DeltaStreamSink<'_>,
    ) -> StreamEndReason {
        StreamEndReason::Completed
    }

    fn submit_bounded_control(
        &self,
        ctx: &RequestContext,
        op: BoundedControlOp,
        _target_camera_id: Option<&str>,
        _approval_digest: ContentDigest,
    ) -> IpcResponse {
        match OperationId::parse(format!("op:{}:{}", op.as_str(), ctx.request_id)) {
            Ok(operation_id) => IpcResponse::ControlAccepted {
                request_id: ctx.request_id,
                operation_id,
                state: ControlOperationState::Accepted,
            },
            Err(_) => IpcResponse::Cancelled {
                request_id: ctx.request_id,
            },
        }
    }
}

fn test_basis() -> ContractBasis {
    reference_contract_basis()
}

fn test_principal() -> Result<PrincipalId, Box<dyn Error>> {
    Ok(PrincipalId::parse("principal:local-operator")?)
}

#[test]
fn live_server_rejects_oversized_request_frame_header() -> TestResult {
    let tmp = TempDeployment::new("oversize")?;
    let basis = test_basis();
    let server = IpcServer::bind(
        IpcServerConfig::new(tmp.path(), "site:oversize", basis.basis_digest(), "d1"),
        Arc::new(SimpleHandler::new()),
    )?;

    let mut raw = UnixStream::connect(server.socket_path())?;
    raw.set_read_timeout(Some(Duration::from_secs(2)))?;
    raw.set_write_timeout(Some(Duration::from_secs(2)))?;
    let hs = HandshakeRequest {
        protocol_version: IPC_PROTOCOL_VERSION,
        deployment_id: "site:oversize".to_owned(),
        deployment_root_digest: deployment_root_digest(tmp.path()),
        contract_basis_digest: basis.basis_digest(),
        principal: test_principal()?,
        capabilities: vec!["cap.observe.status".to_owned()],
    };
    let _ = write_frame(
        &mut raw,
        FrameFlags::HANDSHAKE,
        &hs.try_canonical_bytes()?,
        MAX_REQUEST_FRAME_BYTES,
    )?;
    let _hs_reply = read_frame(&mut raw, MAX_RESPONSE_FRAME_BYTES)?;

    let over_req_header = encode_frame_header(
        IPC_PROTOCOL_VERSION,
        FrameFlags::REQUEST,
        (MAX_REQUEST_FRAME_BYTES - 16 + 1) as u32,
    );
    raw.write_all(&over_req_header)?;
    raw.flush()?;
    let reply_frame = read_frame(&mut raw, MAX_RESPONSE_FRAME_BYTES)?;
    match IpcResponse::from_canonical_bytes(&reply_frame.payload)? {
        IpcResponse::Refused { error_id, .. } => {
            assert_eq!(error_id.as_str(), ERR_IPC_FRAME_TOO_LARGE_001);
        }
        other => return Err(format!("expected FrameTooLarge refusal, got {other:?}").into()),
    }

    server.shutdown()?;
    Ok(())
}

#[test]
fn handshake_rejects_deployment_and_contract_basis_mismatch() -> TestResult {
    let tmp = TempDeployment::new("hs-mismatch")?;
    let basis = test_basis();
    let server = IpcServer::bind(
        IpcServerConfig::new(tmp.path(), "site:expected", basis.basis_digest(), "d1"),
        Arc::new(SimpleHandler::new()),
    )?;

    let bad_dep = IpcClient::connect(IpcClientConfig::from_contract_basis(
        tmp.path(),
        "site:wrong",
        &basis,
        test_principal()?,
        vec!["cap.observe.status".to_owned()],
    ));
    match bad_dep {
        Err(IpcError::HandshakeRejected { error_id, .. }) => {
            assert_eq!(error_id.as_str(), ERR_IPC_HANDSHAKE_MISMATCH_001);
        }
        Ok(_) => return Err("wrong deployment_id unexpectedly succeeded".into()),
        Err(other) => return Err(format!("unexpected error: {other}").into()),
    }

    let mut wrong_basis = basis.clone();
    wrong_basis.producer_release_id = "fss:release:v999".to_owned();
    let direct_res = DeploymentClient::connect_or_direct(
        tmp.path(),
        "site:expected",
        &wrong_basis,
        test_principal()?,
    );
    match direct_res {
        Err(IpcError::HandshakeRejected { error_id, .. }) => {
            assert_eq!(error_id.as_str(), ERR_IPC_HANDSHAKE_MISMATCH_001);
        }
        Ok(DeploymentChannel::OfflineDirect { .. }) => {
            return Err("contract basis mismatch must never silently fall back offline".into());
        }
        Ok(DeploymentChannel::LiveDaemon(_)) => {
            return Err("contract basis mismatch unexpectedly connected".into());
        }
        Err(other) => return Err(format!("unexpected error: {other}").into()),
    }

    server.shutdown()?;
    Ok(())
}

#[test]
fn security_enforces_0700_dir_0600_socket_and_refuses_symlinks_and_world_writable() -> TestResult {
    let tmp = TempDeployment::new("sec-ok")?;
    let basis = test_basis();
    let server = IpcServer::bind(
        IpcServerConfig::new(tmp.path(), "site:sec", basis.basis_digest(), "d1"),
        Arc::new(SimpleHandler::new()),
    )?;
    let run_mode = fs::symlink_metadata(default_run_dir(tmp.path()))?
        .permissions()
        .mode()
        & 0o777;
    let sock_mode = fs::symlink_metadata(default_socket_path(tmp.path()))?
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(run_mode, 0o700);
    assert_eq!(sock_mode, 0o600);

    fs::set_permissions(
        default_socket_path(tmp.path()),
        Permissions::from_mode(0o660),
    )?;
    assert!(matches!(
        IpcClient::connect(IpcClientConfig::from_contract_basis(
            tmp.path(),
            "site:sec",
            &basis,
            test_principal()?,
            Vec::new(),
        )),
        Err(IpcError::InsecurePermissions { mode: 0o660, .. })
    ));
    fs::set_permissions(
        default_socket_path(tmp.path()),
        Permissions::from_mode(0o600),
    )?;
    server.shutdown()?;

    let tmp_perm = TempDeployment::new("sec-perm")?;
    let bad_run = default_run_dir(tmp_perm.path());
    fs::create_dir(&bad_run)?;
    fs::set_permissions(&bad_run, Permissions::from_mode(0o755))?;
    assert!(matches!(
        IpcServer::bind(
            IpcServerConfig::new(tmp_perm.path(), "site:perm", basis.basis_digest(), "d1"),
            Arc::new(SimpleHandler::new()),
        ),
        Err(IpcError::InsecurePermissions { mode: 0o755, .. })
    ));

    let tmp_sym_run = TempDeployment::new("sec-symrun")?;
    let real_target = tmp_sym_run.path().join("real_run");
    fs::create_dir(&real_target)?;
    fs::set_permissions(&real_target, Permissions::from_mode(0o700))?;
    symlink(&real_target, default_run_dir(tmp_sym_run.path()))?;
    assert!(matches!(
        IpcServer::bind(
            IpcServerConfig::new(tmp_sym_run.path(), "site:sym", basis.basis_digest(), "d1"),
            Arc::new(SimpleHandler::new()),
        ),
        Err(IpcError::InsecurePath { .. })
    ));

    let tmp_sym_sock = TempDeployment::new("sec-symsock")?;
    let run_dir = default_run_dir(tmp_sym_sock.path());
    fs::create_dir(&run_dir)?;
    fs::set_permissions(&run_dir, Permissions::from_mode(0o700))?;
    let sentinel = tmp_sym_sock.path().join("sentinel.txt");
    fs::write(&sentinel, b"do-not-delete")?;
    let sock_link = default_socket_path(tmp_sym_sock.path());
    symlink(&sentinel, &sock_link)?;
    assert!(matches!(
        IpcServer::bind(
            IpcServerConfig::new(tmp_sym_sock.path(), "site:ss", basis.basis_digest(), "d1"),
            Arc::new(SimpleHandler::new()),
        ),
        Err(IpcError::InsecurePath { .. })
    ));
    assert!(fs::symlink_metadata(&sock_link)?.file_type().is_symlink());
    assert_eq!(fs::read(&sentinel)?, b"do-not-delete");
    Ok(())
}

#[test]
fn stale_socket_recovery_and_live_duplicate_bind_refusal() -> TestResult {
    let tmp = TempDeployment::new("stale")?;
    let basis = test_basis();
    let run_dir = default_run_dir(tmp.path());
    fs::create_dir(&run_dir)?;
    fs::set_permissions(&run_dir, Permissions::from_mode(0o700))?;
    let sock_path = default_socket_path(tmp.path());

    {
        let raw_listener = UnixListener::bind(&sock_path)?;
        fs::set_permissions(&sock_path, Permissions::from_mode(0o600))?;
        drop(raw_listener);
    }
    assert!(fs::symlink_metadata(&sock_path).is_ok());

    let channel =
        DeploymentClient::connect_or_direct(tmp.path(), "site:stale", &basis, test_principal()?)?;
    assert!(!channel.is_live());

    let server = IpcServer::bind(
        IpcServerConfig::new(tmp.path(), "site:stale", basis.basis_digest(), "d1"),
        Arc::new(SimpleHandler::new()),
    )?;

    assert!(matches!(
        IpcServer::bind(
            IpcServerConfig::new(tmp.path(), "site:stale", basis.basis_digest(), "d2"),
            Arc::new(SimpleHandler::new()),
        ),
        Err(IpcError::DaemonAlreadyRunning { .. })
    ));

    let mut client = IpcClient::connect(IpcClientConfig::from_contract_basis(
        tmp.path(),
        "site:stale",
        &basis,
        test_principal()?,
        vec!["cap.observe.status".to_owned()],
    ))?;
    let status = client.query_live_status(1, true, true)?;
    assert!(matches!(status, IpcResponse::LiveStatus(_)));
    server.shutdown()?;
    Ok(())
}
