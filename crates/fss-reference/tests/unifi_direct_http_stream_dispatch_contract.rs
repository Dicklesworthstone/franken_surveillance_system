#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Synthetic journaled local serializer dispatch and reconciliation contracts.
use asupersync::{
    http::h1::Response, io::AsyncWrite, net::TcpListener, runtime::RuntimeBuilder, time::timeout,
};
use fss_core::{
    BudgetVector, ContentDigest, IdempotencyKey, OperationId, RegionId, RegionKind,
    RootAuthoritySpec, RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_object::{
    HostSpoolIo, SpoolLimits, StagingSpool,
    effect_journal::{EffectJournalLimits, FileEffectJournal, FileTrustedRootPinRetainer},
};
use fss_reference::unifi_direct::{
    AudioCodec, StreamStart, VideoChannel, VideoCodec,
    camera_api::{HandoffError, HandoffWrite, Phase, SerializerAuthority, Session, WriteOutcome},
    camera_http,
    handoff::Framing,
    http_stream::{
        Operation as SerializerOperation, Plan, Preconditions, ReadbackChange, ReadbackObservation,
        checkpoint,
    },
    metered::{MeteredClock, MeteredIo},
};
use fss_runtime::{
    authority::AuthorityCx,
    effect::{CommitApproval, CommittedEffect, EffectCoordinator, PrepareSpec, Reconciliation},
    effect_journal::{EffectJournalStore, EffectPinRetainer, PinRetainedEffectJournal},
    execution::{TaskCompletion, TaskSpec, run_owned_async},
    lease::LeaseRegistry,
};
use std::os::unix::fs::DirBuilderExt;
use std::{
    cell::{Cell, RefCell},
    error::Error,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4},
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

type Test = Result<(), Box<dyn Error>>;
fn metadata_journal(
    dir: &std::path::Path,
    label: &str,
) -> Result<PinRetainedEffectJournal, Box<dyn Error>> {
    let limits = EffectJournalLimits::default();
    let file = FileEffectJournal::create(
        dir.join(format!("{label}-journal")),
        limits,
        Arc::new(HostSpoolIo),
    )?;
    let root = FileTrustedRootPinRetainer::create(
        dir.join(format!("{label}-root")),
        limits,
        Arc::new(HostSpoolIo),
        ContentDigest::sha256(label.as_bytes()),
    )?;
    Ok(PinRetainedEffectJournal::new(
        Box::new(file),
        Box::new(root),
    )?)
}
fn serializer_snapshot(
    peer: Ipv4Addr,
    generation: u64,
    payload: &[u8],
) -> Result<fss_reference::unifi_direct::camera_api::VideoSerializers, Box<dyn Error>> {
    let mut session = Session::new(peer, generation)?;
    let r = session.prepare_login(br#"{"username":"fixture","password":"synthetic"}"#)?;
    session.finish_write(r, WriteOutcome::Written)?;
    session.accept_login(
        Response::new(200, "OK", Vec::new()).with_header("Set-Cookie", "authId=synthetic"),
    )?;
    let r = session.prepare_status()?;
    session.finish_write(r, WriteOutcome::Written)?;
    session.accept_status(Response::new(200, "OK", b"{}".to_vec()))?;
    let r = session.prepare_serializer_settings()?;
    session.finish_write(r, WriteOutcome::Written)?;
    Ok(session
        .accept_settings_with_serializers(Response::new(200, "OK", payload.to_vec()))?
        .1)
}
struct Guard(bool);
struct CheckpointPolicy(bool);
impl checkpoint::Authority for CheckpointPolicy {
    fn permits(&self, _: &asupersync::Cx, _: &checkpoint::Scope, _: checkpoint::Action) -> bool {
        self.0
    }
}
struct DenyCheckpoint(checkpoint::Action);
impl checkpoint::Authority for DenyCheckpoint {
    fn permits(
        &self,
        _: &asupersync::Cx,
        _: &checkpoint::Scope,
        action: checkpoint::Action,
    ) -> bool {
        action != self.0
    }
}
impl SerializerAuthority for Guard {
    fn permits(&self, _: &Plan, _: Preconditions, _: &CommittedEffect) -> bool {
        self.0
    }
}
struct OwnerPolicy(Cell<bool>);
impl camera_http::Authority for OwnerPolicy {
    fn permits(&self, _: Ipv4Addr, generation: u64, operation: camera_http::Operation) -> bool {
        generation == 1 && (operation != camera_http::Operation::SerializerSettings || self.0.get())
    }
}
fn fixture_server(address: std::net::SocketAddr, match_request: bool) -> std::io::Result<()> {
    let mut socket = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    socket.set_read_timeout(Some(Duration::from_secs(8)))?;
    let mut routes = vec![
        "POST /api/1.1/login ",
        "GET /api/1.1/status ",
        "GET /api/1.1/settings ",
        "PUT /api/1.1/settings ",
        "GET /api/1.1/settings ",
    ];
    if match_request {
        routes.extend(["PUT /api/1.1/settings ", "GET /api/1.1/settings "]);
    }
    for (index, route) in routes.iter().enumerate() {
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            socket.read_exact(&mut byte)?;
            request.push(byte[0]);
            if request.len() > 8192 {
                return Err(std::io::Error::other("fixture header limit"));
            }
        }
        let header = std::str::from_utf8(&request).map_err(std::io::Error::other)?;
        if !header.starts_with(*route) {
            return Err(std::io::Error::other("fixture route"));
        }
        let length = header
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .map_or(Ok(0), str::parse::<usize>)
            .map_err(std::io::Error::other)?;
        if length > 4096 {
            return Err(std::io::Error::other("fixture body limit"));
        }
        let mut body = vec![0u8; length];
        socket.read_exact(&mut body)?;
        if index == 3 {
            let text = std::str::from_utf8(&body).map_err(std::io::Error::other)?;
            if !text.contains("\"video1\":{\"avSerializer\":")
                || text.contains("\"video2\"")
                || text.contains("\"controller\"")
            {
                return Err(std::io::Error::other("fixture serializer mismatch"));
            }
        }
        if index == 5 && body != br#"{"av":{"video":{"video1":{"avSerializer":null}}}}"# {
            return Err(std::io::Error::other("fixture restore mismatch"));
        }
        let reply: &[u8] = if index == 4 && match_request {
            br#"{"av":{"video":{"video1":{"avSerializer":{"type":"extendedFlv","parameters":{"streamName":"0123456789abcdef","withOpus":false},"destinations":["tcp://192.168.42.11:17777?retryInterval=1&connectTimeout=5"]}},"video2":{"avSerializer":{"destinations":["tcp://fixture:1"]}}}}}"#
        } else if index == 2 || index == 4 || index == 6 {
            br#"{"av":{"video":{"video1":{"avSerializer":null},"video2":{"avSerializer":{"destinations":["tcp://fixture:1"]}}}}}"#
        } else {
            b"{}"
        };
        let cookie = if index == 0 {
            "Set-Cookie: authId=synthetic\r\n"
        } else {
            ""
        };
        let head = format!(
            "HTTP/1.1 200 OK\r\n{cookie}Content-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            reply.len()
        );
        socket.write_all(head.as_bytes())?;
        socket.write_all(reply)?;
    }
    Ok(())
}
struct Sink {
    bytes: Rc<RefCell<Vec<u8>>>,
    polled: Rc<Cell<bool>>,
    partial: bool,
}
impl AsyncWrite for Sink {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.polled.set(true);
        if self.partial && !self.bytes.borrow().is_empty() {
            return Poll::Pending;
        }
        let n = if self.partial {
            bytes.len().min(1)
        } else {
            bytes.len()
        };
        self.bytes.borrow_mut().extend_from_slice(&bytes[..n]);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn one_track_dispatch_requires_full_readback() -> Test {
    exercise(false, false, false, false)
}
#[test]
fn partial_write_fences_and_leaves_effect_open() -> Test {
    exercise(true, false, false, false)
}
#[test]
fn unsuccessful_response_fences_and_leaves_effect_open() -> Test {
    exercise(false, true, false, false)
}
#[test]
fn owned_http_checks_policy_and_requires_private_readback() -> Test {
    exercise(false, false, true, false)
}
#[test]
fn owned_http_observes_requested_fields_without_settling() -> Test {
    exercise(false, false, true, true)
}

fn exercise(partial: bool, bad_response: bool, owned: bool, match_request: bool) -> Test {
    let dir = std::env::temp_dir().join(format!(
        "fss-http-serializer-{}-{}-{}-{}-{}",
        std::process::id(),
        partial,
        bad_response,
        owned,
        match_request
    ));
    std::fs::create_dir(&dir)?;
    let journal = FileEffectJournal::create(
        dir.join("journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut effects = EffectCoordinator::with_journal(Box::new(journal))?;
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 1_000_000;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:serializer-test".into(),
            operation_id: OperationId::parse("operation:serializer-owner")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::AdapterAuth.as_str().into(),
                RuntimeGrant::ObserveStatus.as_str().into(),
                RuntimeGrant::CameraSettingPrepare.as_str().into(),
                RuntimeGrant::CameraSettingCommit.as_str().into(),
            ],
            deadline: Some(TimestampNs(600_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"fixture"),
            generation: 1,
        },
        RegionId::new("region:serializer-test")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let peer = Ipv4Addr::new(192, 168, 42, 10);
    let mut session = Session::new(peer, 1)?;
    let r = session.prepare_login(br#"{"username":"fixture","password":"synthetic"}"#)?;
    session.finish_write(r, WriteOutcome::Written)?;
    session.accept_login(
        Response::new(200, "OK", Vec::new()).with_header("Set-Cookie", "authId=synthetic"),
    )?;
    let r = session.prepare_status()?;
    session.finish_write(r, WriteOutcome::Written)?;
    session.accept_status(Response::new(200, "OK", b"{}".to_vec()))?;
    let r = session.prepare_serializer_settings()?;
    session.finish_write(r, WriteOutcome::Written)?;
    let (_, baseline) = session.accept_settings_with_serializers(Response::new(200, "OK", br#"{"av":{"video":{"video1":{"avSerializer":null},"video2":{"avSerializer":{"destinations":["tcp://fixture:1"]}}}}}"#.to_vec()))?;
    let mut other_session = Session::new(peer, 1)?;
    let r = other_session.prepare_login(br#"{"username":"fixture","password":"synthetic"}"#)?;
    other_session.finish_write(r, WriteOutcome::Written)?;
    other_session.accept_login(
        Response::new(200, "OK", Vec::new()).with_header("Set-Cookie", "authId=synthetic"),
    )?;
    let r = other_session.prepare_status()?;
    other_session.finish_write(r, WriteOutcome::Written)?;
    other_session.accept_status(Response::new(200, "OK", b"{}".to_vec()))?;
    let r = other_session.prepare_serializer_settings()?;
    other_session.finish_write(r, WriteOutcome::Written)?;
    let (_, changed) = other_session.accept_settings_with_serializers(Response::new(200, "OK", br#"{"av":{"video":{"video1":{"avSerializer":null},"video2":{"avSerializer":{"destinations":["tcp://fixture:2"]}}}}}"#.to_vec()))?;
    let camera = ContentDigest::sha256(b"fixture camera");
    let resource = format!("camera:{}", camera.to_text());
    let mut leases = LeaseRegistry::new();
    let fence = leases
        .acquire(&resource, authority.region().as_str(), None, TimestampNs(2))?
        .fence;
    let listener = SocketAddrV4::new(Ipv4Addr::new(192, 168, 42, 11), 17777);
    let conditions = Preconditions {
        camera,
        peer_admission: ContentDigest::sha256(b"peer"),
        session_generation: 1,
        lease_fence: fence,
        serializers: baseline.binding(|_, _| true)?,
        listener,
    };
    let start = StreamStart::new(
        VideoChannel::Video1,
        listener,
        VideoCodec::H264,
        AudioCodec::Aac,
        "0123456789abcdef",
    )?;
    let plan = Plan::new(peer, &start, conditions, &baseline, Framing::ContentLength)?;
    let op = OperationId::parse("operation:serializer-dispatch")?;
    let prepared = effects.prepare(
        &authority,
        &mut tree,
        &mut leases,
        PrepareSpec {
            operation: &op,
            idempotency_key: IdempotencyKey::parse(op.as_str())?,
            request_digest: plan.request_digest(),
            precondition_digest: plan.precondition_digest(),
            resource: &resource,
            fence,
            prepare_grant: RuntimeGrant::CameraSettingPrepare,
            commit_grant: RuntimeGrant::CameraSettingCommit,
            terminal_predicate: "independent readback or reconciliation",
        },
        TimestampNs(3),
    )?;
    let forward_preparation = prepared.digest();
    let approval = CommitApproval {
        prepared_digest: forward_preparation,
        current_precondition_digest: plan.precondition_digest(),
    };
    let permit = effects.commit(
        &authority,
        &tree,
        &mut leases,
        prepared,
        TimestampNs(4),
        approval,
    )?;
    // A synthetic expected readback supplies the exact intended reverse effect
    // before this fixture runs. The owner must still independently revalidate
    // the actual response before dispatching the separate restoration permit.
    let restore_op = OperationId::parse("operation:serializer-restore")?;
    let restore_parts = if owned && match_request {
        let r = other_session.prepare_serializer_settings()?;
        other_session.finish_write(r, WriteOutcome::Written)?;
        let (_, anticipated) = other_session.accept_settings_with_serializers(Response::new(200, "OK", br#"{"av":{"video":{"video1":{"avSerializer":{"type":"extendedFlv","parameters":{"streamName":"0123456789abcdef","withOpus":false},"destinations":["tcp://192.168.42.11:17777?retryInterval=1&connectTimeout=5"]}},"video2":{"avSerializer":{"destinations":["tcp://fixture:1"]}}}}}"#.to_vec()))?;
        let restore_conditions = Preconditions {
            serializers: anticipated.binding(|_, _| true)?,
            ..conditions
        };
        let restore_plan = plan.prepare_restore(
            &baseline,
            &anticipated,
            restore_conditions,
            Framing::ContentLength,
            |_, _| true,
        )?;
        let prepared = effects.prepare(
            &authority,
            &mut tree,
            &mut leases,
            PrepareSpec {
                operation: &restore_op,
                idempotency_key: IdempotencyKey::parse(restore_op.as_str())?,
                request_digest: restore_plan.request_digest(),
                precondition_digest: restore_plan.precondition_digest(),
                resource: &resource,
                fence,
                prepare_grant: RuntimeGrant::CameraSettingPrepare,
                commit_grant: RuntimeGrant::CameraSettingCommit,
                terminal_predicate: "independent restore observation or reconciliation",
            },
            TimestampNs(5),
        )?;
        let approval = CommitApproval {
            prepared_digest: prepared.digest(),
            current_precondition_digest: restore_plan.precondition_digest(),
        };
        let permit = effects.commit(
            &authority,
            &tree,
            &mut leases,
            prepared,
            TimestampNs(6),
            approval,
        )?;
        Some((restore_plan, restore_conditions, permit))
    } else {
        None
    };
    let runtime = RuntimeBuilder::current_thread().build()?;
    let checkpoint_scope =
        checkpoint::Scope::from_plan(&plan, ContentDigest::sha256(b"fixture certificate"))?;
    let key = checkpoint::Key::new([7; 32])?;
    let sealed = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        Ok::<_, Box<dyn Error>>(checkpoint::Sealed::capture(
            &cx,
            &CheckpointPolicy(true),
            checkpoint_scope,
            &key,
            &plan,
            &baseline,
        )?)
    })?;
    let mut checkpoint_spool = StagingSpool::open(
        dir.join("checkpoint-spool"),
        SpoolLimits::new(4, 1_000_000, 100_000, 8),
    )?;
    let key_dir = dir.join("keys");
    std::fs::DirBuilder::new().mode(0o700).create(&key_dir)?;
    let lease = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        Ok::<_, Box<dyn Error>>(checkpoint::keyfile::KeyLease::create(
            &cx,
            &CheckpointPolicy(true),
            checkpoint_scope,
            &key_dir.join("key"),
        )?)
    })?;
    let wrong_lease = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        Ok::<_, Box<dyn Error>>(checkpoint::keyfile::KeyLease::create(
            &cx,
            &CheckpointPolicy(true),
            checkpoint_scope,
            &key_dir.join("wrong-key"),
        )?)
    })?;
    let stored = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        assert!(
            checkpoint::Stored::capture_with_keyfile(
                &cx,
                &DenyCheckpoint(checkpoint::Action::Stage),
                checkpoint_scope,
                &lease,
                &plan,
                &baseline,
                &mut checkpoint_spool
            )
            .is_err()
        );
        Ok::<_, Box<dyn Error>>(checkpoint::Stored::capture_with_keyfile(
            &cx,
            &CheckpointPolicy(true),
            checkpoint_scope,
            &lease,
            &plan,
            &baseline,
            &mut checkpoint_spool,
        )?)
    })?;
    let other_conditions = Preconditions {
        peer_admission: ContentDigest::sha256(b"other peer admission"),
        ..conditions
    };
    let other_plan = Plan::new(
        peer,
        &start,
        other_conditions,
        &baseline,
        Framing::ContentLength,
    )?;
    let other_scope =
        checkpoint::Scope::from_plan(&other_plan, ContentDigest::sha256(b"fixture certificate"))?;
    let other_lease = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        Ok::<_, Box<dyn Error>>(checkpoint::keyfile::KeyLease::create(
            &cx,
            &CheckpointPolicy(true),
            other_scope,
            &key_dir.join("other-key"),
        )?)
    })?;
    let other_stored = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        Ok::<_, Box<dyn Error>>(checkpoint::Stored::capture_with_keyfile(
            &cx,
            &CheckpointPolicy(true),
            other_scope,
            &other_lease,
            &other_plan,
            &baseline,
            &mut checkpoint_spool,
        )?)
    })?;
    drop(checkpoint_spool);
    let mut reopened_spool = StagingSpool::open(
        dir.join("checkpoint-spool"),
        SpoolLimits::new(4, 1_000_000, 100_000, 8),
    )?;
    let stored_bytes = reopened_spool.read_bounded(stored.digest(), 100_000)?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        lease.with_key(&cx, &CheckpointPolicy(true), |key| {
            checkpoint::Sealed::from_bytes(&stored_bytes)?.open(
                &cx,
                &CheckpointPolicy(true),
                stored.scope(),
                key,
            )
        })??;
        Ok::<(), Box<dyn Error>>(())
    })?;
    let mut anchor_journal = metadata_journal(&dir, "checkpoint-anchor")?;
    let mut other_journal = metadata_journal(&dir, "other-anchor")?;
    let anchored = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        assert!(
            stored
                .anchor_with_keyfile(
                    &cx,
                    &DenyCheckpoint(checkpoint::Action::Anchor),
                    &lease,
                    &mut reopened_spool,
                    &mut anchor_journal
                )
                .is_err()
        );
        assert!(anchor_journal.head().is_none());
        assert!(
            stored
                .anchor_with_keyfile(
                    &cx,
                    &CheckpointPolicy(true),
                    &wrong_lease,
                    &mut reopened_spool,
                    &mut anchor_journal
                )
                .is_err()
        );
        assert!(anchor_journal.head().is_none());
        Ok::<_, Box<dyn Error>>(stored.anchor_with_keyfile(
            &cx,
            &CheckpointPolicy(true),
            &lease,
            &mut reopened_spool,
            &mut anchor_journal,
        )?)
    })?;
    let other_anchored = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        Ok::<_, Box<dyn Error>>(other_stored.anchor_with_keyfile(
            &cx,
            &CheckpointPolicy(true),
            &other_lease,
            &mut reopened_spool,
            &mut other_journal,
        )?)
    })?;
    assert_eq!(anchored.digest(), stored.digest());
    let anchor_pin = anchored.pin();
    drop(anchor_journal);
    let limits = EffectJournalLimits::default();
    let mut root = FileTrustedRootPinRetainer::open_trusting_storage(
        dir.join("checkpoint-anchor-root"),
        limits,
        Arc::new(HostSpoolIo),
        ContentDigest::sha256(b"checkpoint-anchor"),
    )?;
    assert_eq!(root.retained_pin()?, Some(anchor_pin));
    let file = FileEffectJournal::open(
        dir.join("checkpoint-anchor-journal"),
        limits,
        Arc::new(HostSpoolIo),
        anchor_pin,
    )?;
    let mut reopened_anchor =
        PinRetainedEffectJournal::for_reconciliation(Box::new(file), Box::new(root))?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let recovered = checkpoint::recover_record(
            &cx,
            &CheckpointPolicy(true),
            &mut reopened_anchor,
            anchor_pin,
        )?;
        assert_eq!(recovered.scope(), checkpoint_scope);
        assert_eq!(recovered.digest(), stored.digest());
        assert!(
            checkpoint::recover_record(
                &cx,
                &DenyCheckpoint(checkpoint::Action::Anchor),
                &mut reopened_anchor,
                anchor_pin
            )
            .is_err()
        );
        let wrong = fss_runtime::effect_journal::EffectJournalPin {
            sequence: anchor_pin.sequence,
            root: ContentDigest::sha256(b"wrong metadata pin"),
        };
        assert!(
            checkpoint::recover_record(&cx, &CheckpointPolicy(true), &mut reopened_anchor, wrong)
                .is_err()
        );
        Ok::<(), Box<dyn Error>>(())
    })?;
    let stored = anchored;
    let other_stored = other_anchored;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:serializer-test")?,
                started_at: TimestampNs(7),
            },
            &cx,
            async |task, cx| {
                let output: Test = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(8))?;
                    if owned {
                        let listener = TcpListener::bind("127.0.0.1:0").await?;
                        let address = listener.local_addr()?;
                        let fixture =
                            std::thread::spawn(move || fixture_server(address, match_request));
                        let (socket, _) =
                            timeout(cx.now(), Duration::from_secs(5), listener.accept()).await??;
                        let io = MeteredIo::with_clock(socket, clock, &resource, 4096)?;
                        let policy = OwnerPolicy(Cell::new(false));
                        let mut owner = camera_http::Owner::new(
                            io, task, cx, clock, &policy, peer, 1, &resource,
                        )?;
                        owner
                            .login(
                                br#"{"username":"fixture","password":"synthetic"}"#,
                                Duration::from_secs(5),
                            )
                            .await?;
                        owner.status(Duration::from_secs(5)).await?;
                        let (_, observed) =
                            owner.settings_serializers(Duration::from_secs(5)).await?;
                        let missing = owner
                            .dispatch_serializer(
                                &plan,
                                conditions,
                                &observed,
                                None,
                                permit,
                                &Guard(true),
                                Duration::from_secs(5),
                            )
                            .await
                            .expect_err("missing checkpoint must not write");
                        assert_eq!(missing.reason, HandoffError::CheckpointRequired);
                        let denied = owner
                            .dispatch_serializer(
                                &plan,
                                conditions,
                                &observed,
                                Some(&stored),
                                missing.permit,
                                &Guard(true),
                                Duration::from_secs(5),
                            )
                            .await
                            .expect_err("owner must deny write");
                        assert_eq!(denied.reason, HandoffError::Denied);
                        policy.0.set(true);
                        let permit = match owner
                            .dispatch_serializer(
                                &plan,
                                conditions,
                                &observed,
                                Some(&stored),
                                denied.permit,
                                &Guard(true),
                                Duration::from_secs(5),
                            )
                            .await
                            .map_err(|_| "owner dispatch refused")?
                        {
                            HandoffWrite::Written { permit } => permit,
                            _ => return Err("owner write indeterminate".into()),
                        };
                        owner
                            .read_serializer_response_observed(&permit, Duration::from_secs(5))
                            .await?;
                        assert_eq!(owner.phase(), Phase::ReconcileSerializers);
                        assert!(owner.settings(Duration::from_secs(5)).await.is_err());
                        let (_, readback) =
                            owner.settings_serializers(Duration::from_secs(5)).await?;
                        let comparison = plan
                            .observe_readback(&observed, &readback, |p, g| p == peer && g == 1)?;
                        assert_eq!(
                            comparison,
                            if match_request {
                                ReadbackObservation {
                                    change: ReadbackChange::TargetTrackOnly,
                                    requested_fields_match: true,
                                }
                            } else {
                                ReadbackObservation {
                                    change: ReadbackChange::Unchanged,
                                    requested_fields_match: false,
                                }
                            }
                        );
                        assert_eq!(owner.phase(), Phase::Snapshot);
                        if let Some((prepared_restore, restore_conditions, permit)) = restore_parts
                        {
                            let restore = plan.prepare_restore(
                                &observed,
                                &readback,
                                restore_conditions,
                                Framing::ContentLength,
                                |p, g| p == peer && g == 1,
                            )?;
                            assert_eq!(restore.operation(), SerializerOperation::Restore);
                            assert_eq!(restore.request_digest(), prepared_restore.request_digest());
                            let permit = match owner
                                .dispatch_serializer(
                                    &restore,
                                    restore_conditions,
                                    &readback,
                                    None,
                                    permit,
                                    &Guard(true),
                                    Duration::from_secs(5),
                                )
                                .await
                                .map_err(|_| "restore dispatch refused")?
                            {
                                HandoffWrite::Written { permit } => permit,
                                _ => return Err("restore write indeterminate".into()),
                            };
                            owner
                                .read_serializer_response_observed(&permit, Duration::from_secs(5))
                                .await?;
                            let (_, restored) =
                                owner.settings_serializers(Duration::from_secs(5)).await?;
                            assert_eq!(
                                observed.binding(|_, _| true)?,
                                restored.binding(|_, _| true)?
                            );
                            assert!(
                                restore
                                    .observe_readback(&readback, &restored, |p, g| p == peer
                                        && g == 1)?
                                    .requested_fields_match
                            );
                        }
                        drop(owner);
                        fixture.join().map_err(|_| "fixture panic")??;
                        return Ok(());
                    }
                    let bytes = Rc::new(RefCell::new(Vec::new()));
                    let polled = Rc::new(Cell::new(false));
                    let mut io = MeteredIo::with_clock(
                        Sink {
                            bytes: bytes.clone(),
                            polled: polled.clone(),
                            partial,
                        },
                        clock,
                        "fixture:camera",
                        4096,
                    )?;
                    let missing = session
                        .dispatch_serializer(
                            cx,
                            &mut io,
                            &plan,
                            conditions,
                            &baseline,
                            None,
                            permit,
                            &Guard(true),
                            Duration::from_secs(1),
                        )
                        .await
                        .expect_err("missing checkpoint must not write");
                    assert_eq!(missing.reason, HandoffError::CheckpointRequired);
                    assert!(!polled.get());
                    let wrong = session
                        .dispatch_serializer(
                            cx,
                            &mut io,
                            &plan,
                            conditions,
                            &baseline,
                            Some(&other_stored),
                            missing.permit,
                            &Guard(true),
                            Duration::from_secs(1),
                        )
                        .await
                        .expect_err("mismatched checkpoint must not write");
                    assert_eq!(wrong.reason, HandoffError::CheckpointRequired);
                    assert!(!polled.get());
                    let refusal = session
                        .dispatch_serializer(
                            cx,
                            &mut io,
                            &plan,
                            conditions,
                            &baseline,
                            Some(&stored),
                            wrong.permit,
                            &Guard(false),
                            Duration::from_secs(1),
                        )
                        .await
                        .expect_err("denied must not write");
                    assert_eq!(refusal.reason, HandoffError::Denied);
                    assert!(!polled.get());
                    let stale = Preconditions {
                        lease_fence: fence + 1,
                        ..conditions
                    };
                    let refusal = session
                        .dispatch_serializer(
                            cx,
                            &mut io,
                            &plan,
                            stale,
                            &baseline,
                            Some(&stored),
                            refusal.permit,
                            &Guard(true),
                            Duration::from_secs(1),
                        )
                        .await
                        .expect_err("stale fence must not write");
                    assert_eq!(refusal.reason, HandoffError::Stale);
                    assert!(!polled.get());
                    let refusal = session
                        .dispatch_serializer(
                            cx,
                            &mut io,
                            &plan,
                            conditions,
                            &changed,
                            Some(&stored),
                            refusal.permit,
                            &Guard(true),
                            Duration::from_secs(1),
                        )
                        .await
                        .expect_err("changed other track must not write");
                    assert_eq!(refusal.reason, HandoffError::Stale);
                    assert!(!polled.get());
                    let result = session
                        .dispatch_serializer(
                            cx,
                            &mut io,
                            &plan,
                            conditions,
                            &baseline,
                            Some(&stored),
                            refusal.permit,
                            &Guard(true),
                            Duration::from_millis(if partial { 50 } else { 1000 }),
                        )
                        .await
                        .map_err(|_| "dispatch refused")?;
                    if partial {
                        let mut permit = match result {
                            HandoffWrite::Indeterminate { permit } => permit,
                            _ => return Err("partial write was reported complete".into()),
                        };
                        assert!(!permit.try_claim_dispatch());
                        assert_eq!(bytes.borrow().len(), 1);
                        assert_eq!(session.phase(), Phase::Fenced);
                    } else {
                        let mut permit = match result {
                            HandoffWrite::Written { permit } => permit,
                            _ => return Err("unexpected partial write".into()),
                        };
                        assert!(!permit.try_claim_dispatch());
                        let wire = bytes.borrow();
                        let text = std::str::from_utf8(&wire)?;
                        assert!(text.starts_with("PUT /api/1.1/settings HTTP/1.1\r\n"));
                        assert!(text.contains("\"video1\":{\"avSerializer\":"));
                        assert!(!text.contains("\"controller\""));
                        assert!(!text.contains("\"video2\""));
                        drop(wire);
                        if bad_response {
                            assert!(
                                session
                                    .accept_serializer_response_observed(Response::new(
                                        503,
                                        "Unavailable",
                                        Vec::new()
                                    ))
                                    .is_err()
                            );
                            assert_eq!(session.phase(), Phase::Fenced);
                            return Ok(());
                        }
                        session.accept_serializer_response_observed(Response::new(
                            200,
                            "OK",
                            b"{}".to_vec(),
                        ))?;
                        assert_eq!(session.phase(), Phase::ReconcileSerializers);
                        assert!(session.prepare_settings().is_err());
                        assert!(session.prepare_status().is_err());
                        let r = session.prepare_serializer_settings()?;
                        session.finish_write(r, WriteOutcome::NotWritten)?;
                        assert_eq!(session.phase(), Phase::ReconcileSerializers);
                        let r = session.prepare_serializer_settings()?;
                        session.finish_write(r, WriteOutcome::Written)?;
                        session.accept_settings_with_serializers(Response::new(
                            200,
                            "OK",
                            b"{}".to_vec(),
                        ))?;
                        assert_eq!(session.phase(), Phase::Snapshot);
                    }
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(59_000_000_000),
                }
            },
        )
        .await?;
        run.receipt?;
        run.output
    })?;
    assert_eq!(
        effects
            .journal()
            .operation(&op)
            .ok_or("missing journal")?
            .state,
        fss_core::EffectState::Committed
    );
    if owned && match_request {
        assert_eq!(
            effects
                .journal()
                .operation(&restore_op)
                .ok_or("missing restore journal")?
                .state,
            fss_core::EffectState::Committed
        );
    }
    let verified = !owned && !partial && !bad_response;
    if verified {
        let handle = effects.prepared(&op).ok_or("missing preparation")?;
        let proof = ContentDigest::sha256(b"independent synthetic observation");
        effects.reconcile(
            &mut tree,
            &authority,
            &handle,
            Reconciliation::Indeterminate("fixture ambiguous write"),
            TimestampNs(60_000_000_000),
        )?;
        effects.reconcile(
            &mut tree,
            &authority,
            &handle,
            Reconciliation::Observed(proof),
            TimestampNs(61_000_000_000),
        )?;
        effects.reconcile(
            &mut tree,
            &authority,
            &handle,
            Reconciliation::Verified(proof),
            TimestampNs(62_000_000_000),
        )?;
    }
    let head = effects.durable_pin().ok_or("missing journal pin")?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        assert!(
            checkpoint_scope
                .match_recovered_journal(
                    &cx,
                    &CheckpointPolicy(true),
                    &effects,
                    &op,
                    head,
                    forward_preparation
                )
                .is_err()
        );
        Ok::<(), Box<dyn Error>>(())
    })?;
    drop(effects);
    let journal = FileEffectJournal::open(
        dir.join("journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        head,
    )?;
    let recovered = EffectCoordinator::recover(Box::new(journal), head)?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        assert_eq!(
            checkpoint_scope.match_recovered_journal(
                &cx,
                &CheckpointPolicy(true),
                &recovered,
                &op,
                head,
                forward_preparation
            )?,
            if verified { fss_core::EffectState::Verified } else { fss_core::EffectState::Committed }
        );
        assert!(
            checkpoint_scope
                .match_recovered_journal(
                    &cx,
                    &CheckpointPolicy(false),
                    &recovered,
                    &op,
                    head,
                    forward_preparation
                )
                .is_err()
        );
        assert!(
            checkpoint_scope
                .match_recovered_journal(
                    &cx,
                    &CheckpointPolicy(true),
                    &recovered,
                    &op,
                    head,
                    ContentDigest::sha256(b"wrong preparation")
                )
                .is_err()
        );
        let wrong_head = fss_runtime::effect_journal::EffectJournalPin {
            sequence: head.sequence,
            root: ContentDigest::sha256(b"wrong head"),
        };
        assert!(
            checkpoint_scope
                .match_recovered_journal(
                    &cx,
                    &CheckpointPolicy(true),
                    &recovered,
                    &op,
                    wrong_head,
                    forward_preparation
                )
                .is_err()
        );
        let changed_conditions = Preconditions {
            peer_admission: ContentDigest::sha256(b"other admission"),
            ..conditions
        };
        let changed_plan = Plan::new(
            peer,
            &start,
            changed_conditions,
            &baseline,
            Framing::ContentLength,
        )?;
        let changed_scope = checkpoint::Scope::from_plan(
            &changed_plan,
            ContentDigest::sha256(b"fixture certificate"),
        )?;
        assert!(
            changed_scope
                .match_recovered_journal(
                    &cx,
                    &CheckpointPolicy(true),
                    &recovered,
                    &op,
                    head,
                    forward_preparation
                )
                .is_err()
        );
        if owned && match_request {
            assert!(
                checkpoint_scope
                    .match_recovered_journal(
                        &cx,
                        &CheckpointPolicy(true),
                        &recovered,
                        &restore_op,
                        head,
                        forward_preparation
                    )
                    .is_err()
            );
        }
        let retained = checkpoint::Sealed::from_bytes(sealed.bytes())?.open(&cx, &CheckpointPolicy(true), checkpoint_scope, &key)?;
        let peer2 = Ipv4Addr::new(192, 168, 42, 12);
        let after = serializer_snapshot(peer2, 2, br#"{"av":{"video":{"video1":{"avSerializer":{"type":"extendedFlv","parameters":{"streamName":"0123456789abcdef","withOpus":false},"destinations":["tcp://192.168.42.11:17777?retryInterval=1&connectTimeout=5"]}},"video2":{"avSerializer":{"destinations":["tcp://fixture:1"]}}}}}"#)?;
        let current = Preconditions { session_generation: 2, serializers: after.binding(|_, _| true)?, ..conditions };
        let context = checkpoint::RestoreContext { camera, certificate: ContentDigest::sha256(b"fixture certificate"), peer: peer2, forward: &start, original_peer: peer, original_generation: 1, original_framing: Framing::ContentLength, current, framing: Framing::ContentLength, original_owner: &recovered, original_operation: &op, journal_head: head, preparation: forward_preparation };
        let admitted = |p, g| p == peer2 && g == 2;
        if verified {
            let result = retained.prepare_verified_restore(&cx, &CheckpointPolicy(true), context, &after, admitted)?;
            assert_eq!(result.operation(), SerializerOperation::Restore);
            let before2 = serializer_snapshot(peer2, 2, br#"{"av":{"video":{"video1":{"avSerializer":null},"video2":{"avSerializer":{"destinations":["tcp://fixture:1"]}}}}}"#)?;
            let before_conditions = Preconditions { serializers: before2.binding(|_, _| true)?, ..current };
            let independent = Plan::new(peer2, &start, before_conditions, &before2, Framing::ContentLength)?.prepare_restore(&before2, &after, current, Framing::ContentLength, admitted)?;
            assert_eq!(result.request_digest(), independent.request_digest());
            assert_eq!(result.precondition_digest(), independent.precondition_digest());
            let changed = serializer_snapshot(peer2, 2, br#"{"av":{"video":{"video1":{"avSerializer":{}},"video2":{"avSerializer":{}}}}}"#)?;
            assert!(retained.prepare_verified_restore(&cx, &CheckpointPolicy(true), context, &changed, admitted).is_err());
            assert!(retained.prepare_verified_restore(&cx, &CheckpointPolicy(true), context, &after, |_, _| false).is_err());
            let wrong = checkpoint::RestoreContext { certificate: ContentDigest::sha256(b"wrong"), ..context };
            assert!(retained.prepare_verified_restore(&cx, &CheckpointPolicy(true), wrong, &after, admitted).is_err());
            let other_codec = StreamStart::new(VideoChannel::Video1, listener, VideoCodec::H265, AudioCodec::Aac, "0123456789abcdef")?;
            let wrong = checkpoint::RestoreContext { forward: &other_codec, ..context };
            assert!(retained.prepare_verified_restore(&cx, &CheckpointPolicy(true), wrong, &after, admitted).is_err());
            let wrong = checkpoint::RestoreContext { original_generation: 2, ..context };
            assert!(retained.prepare_verified_restore(&cx, &CheckpointPolicy(true), wrong, &after, admitted).is_err());
        } else {
            assert!(retained.prepare_verified_restore(&cx, &CheckpointPolicy(true), context, &after, admitted).is_err());
        }
        Ok::<(), Box<dyn Error>>(())
    })?;
    Ok(())
}
