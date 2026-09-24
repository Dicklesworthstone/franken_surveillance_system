#![forbid(unsafe_code)]
//! Native loopback and durable-journal contracts. Synthetic event evidence tests
//! gating only; it is not a real-camera or notification-service qualification.
use super::*;
use crate::{
    DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, PrepareAlertParams,
    ReferenceModelObservation, VirtualCameraSpec, evaluate_unknown_presence, execute_mock_model,
    publish_reference_event, run_reference_capture,
};
use fss_core::{
    CapsuleId, CaptureInterval, ContractError, EventId, IdempotencyKey, ObligationId,
    ObligationState, OperationId, ProbabilityInterval, SensorId,
};
use fss_ledger::{DurableLedgerLimits, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};
use std::cell::Cell;
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const DEADLINE: u64 = 1_000_000_000;

struct Directory(PathBuf);
impl Directory {
    fn new(name: &str) -> Test<Self> {
        for i in 0..100 {
            let path =
                std::env::temp_dir().join(format!("fss-webhook-{name}-{}-{i}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("webhook test directory exhausted".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Fixture {
    objects: InMemoryObjectStore,
    ledger: DurableReferenceLedger,
    journal: DurableEffectJournal,
    plan: ReferenceAlertPlan,
    // Rust drops fields in declaration order; remove the directory after handles.
    dir: Directory,
}
fn fixture(name: &str, endpoint: &WebhookEndpoint) -> Test<Fixture> {
    let dir = Directory::new(name)?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut ledger = DurableReferenceLedger::open(
        dir.0.join("events"),
        "site:webhook",
        IncompleteTailPolicy::Reject,
    )?;
    let mut observations = Vec::new();
    for (seed, domain) in [(11_u64, "power:a"), (22, "power:b")] {
        let camera = VirtualCameraSpec {
            capture_id: CapsuleId::parse(format!("capture:webhook:{seed}"))?,
            sensor_id: SensorId::parse(format!("sensor:webhook:{seed}"))?,
            seed,
            packet_count: 3,
            packet_bytes: 32,
            start_ns: i128::from(seed) * 10_000,
            period_ns: 1_000_000,
            uncertainty_ns: 100,
        };
        let capture = run_reference_capture(
            &camera,
            &DeliveryPlan::identity(camera.packet_count)?,
            &mut objects,
            &mut ledger,
        )?;
        let model = MockModelSpec::new(
            format!("mock:webhook:{seed}"),
            MockModelScript::Fixed {
                label: MockSemanticLabel::PersonLike,
                probability: ProbabilityInterval::new(0.95, 1.0)?,
            },
        )?;
        let result = execute_mock_model(&model, &capture, &mut objects)?;
        let first = capture.source_packets.first().ok_or("missing capture")?;
        let last = capture.source_packets.last().ok_or("missing capture")?;
        observations.push(ReferenceModelObservation::new(
            result,
            domain,
            CaptureInterval::new(first.capture.earliest, last.capture.latest)?,
        )?);
    }
    let decision = evaluate_unknown_presence(EventId::parse("event:webhook:test")?, observations)?;
    let receipt = publish_reference_event(&decision, &mut objects, &mut ledger)?;
    let mut journal =
        DurableEffectJournal::open(dir.0.join("effects"), IncompleteTailPolicy::Reject)?;
    let plan = journal.prepare_alert(PrepareAlertParams {
        decision: &decision,
        event_receipt: &receipt,
        authority: &ledger,
        operation_id: OperationId::parse("operation:webhook:1")?,
        idempotency_key: IdempotencyKey::parse("idempotency:webhook:1")?,
        obligation_id: ObligationId::parse("obligation:webhook:1")?,
        channel: endpoint.channel().to_owned(),
        now: TimestampNs(100),
    })?;
    Ok(Fixture {
        dir,
        objects,
        ledger,
        journal,
        plan,
    })
}
fn limits(bytes: usize) -> WebhookLimits {
    WebhookLimits {
        io_calls: 4096,
        io_bytes: bytes,
        response_bytes: 16384,
        connect_timeout_ns: 100_000_000,
    }
}
fn endpoint(peer: SocketAddr) -> Test<WebhookEndpoint> {
    Ok(WebhookEndpoint::new(
        peer,
        "/notify",
        ContentDigest::sha256(b"explicit-test-only-plaintext-approval"),
    )?)
}
struct Owner {
    route: ContentDigest,
    path: PathBuf,
    denied: Cell<Option<WebhookBoundary>>,
    revoke_after_send: Cell<bool>,
    saw_send: Cell<bool>,
    checks: Cell<usize>,
}
impl Owner {
    fn new(endpoint: &WebhookEndpoint, path: &Path) -> Self {
        Self {
            route: endpoint.digest(),
            path: path.to_path_buf(),
            denied: Cell::new(None),
            revoke_after_send: Cell::new(false),
            saw_send: Cell::new(false),
            checks: Cell::new(0),
        }
    }
}
impl WebhookAuthority for Owner {
    fn checkpoint(
        &self,
        scope: WebhookScope<'_>,
        boundary: WebhookBoundary,
        now: u64,
        deadline: u64,
    ) -> Result<(), WebhookDenial> {
        self.checks.set(self.checks.get() + 1);
        if scope.endpoint.digest() != self.route
            || scope.effect_journal != self.path
            || scope.operation.intent.effect_class != "alert.dispatch"
        {
            return Err(WebhookDenial::Unauthorized);
        }
        if boundary != WebhookBoundary::Record && now >= deadline {
            return Err(WebhookDenial::Deadline);
        }
        if boundary == WebhookBoundary::Send {
            self.saw_send.set(true);
        }
        if self.denied.get() == Some(boundary)
            || boundary == WebhookBoundary::AfterIo
                && self.saw_send.get()
                && self.revoke_after_send.get()
        {
            return Err(WebhookDenial::Revoked);
        }
        Ok(())
    }
}
/// Same-thread nonblocking loopback peer. No detached test work or sleeps.
struct Relay {
    listener: TcpListener,
    stream: Option<TcpStream>,
    request: Vec<u8>,
    reply: Vec<u8>,
    sent: usize,
    accepted: usize,
    close_without_ack: bool,
}
impl Relay {
    fn new(reply: &[u8]) -> Test<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            stream: None,
            request: Vec::new(),
            reply: reply.to_vec(),
            sent: 0,
            accepted: 0,
            close_without_ack: false,
        })
    }
    fn peer(&self) -> Test<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }
    fn step(&mut self) -> Test {
        if self.stream.is_none() && self.accepted == 0 {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(true)?;
                    self.stream = Some(stream);
                    self.accepted += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e.into()),
            }
        }
        let Some(stream) = self.stream.as_mut() else {
            return Ok(());
        };
        let mut bytes = [0; 4096];
        match stream.read(&mut bytes) {
            Ok(n) => self.request.extend_from_slice(&bytes[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
        if self.request.len() > 4096 {
            return Err("unexpected oversized request".into());
        }
        if let Some(end) = self.request.windows(4).position(|b| b == b"\r\n\r\n") {
            let text = std::str::from_utf8(&self.request[..end])?;
            let size: usize = text
                .split("\r\n")
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .ok_or("missing length")?
                .parse()?;
            if self.request.len() == end + 4 + size {
                if self.close_without_ack {
                    self.stream = None;
                    return Ok(());
                }
                if self.sent != self.reply.len() {
                    match stream.write(&self.reply[self.sent..]) {
                        Ok(n) => self.sent += n,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(e) => return Err(e.into()),
                    }
                }
            }
        }
        Ok(())
    }
}
fn drive(
    attempt: &mut WebhookAttempt<'_>,
    relay: &mut Relay,
    objects: &InMemoryObjectStore,
    owner: &Owner,
) -> Test<WebhookOutcome> {
    for n in 0..5000 {
        relay.step()?;
        let result = attempt.poll(101 + n, owner, |d| {
            objects.read_verified(d).map(|b| b.to_vec())
        });
        if let WebhookProgress::ReadyToRecord(outcome) = result {
            return Ok(outcome);
        }
        // Test scheduler only: allow TCP ACK timers to progress while receiving.
        // The production owner never sleeps or runs an internal polling loop.
        if attempt.phase == Phase::Receive {
            std::thread::sleep(Duration::from_millis(1));
        } else {
            std::thread::yield_now();
        }
    }
    Err("bounded webhook fixture did not complete".into())
}

#[test]
fn endpoint_pins_route_and_refuses_secret_or_injected_targets() -> Test {
    let peer = "127.0.0.1:8900".parse()?;
    let first = endpoint(peer)?;
    for path in [
        "https://host/a",
        "//host",
        "/a?token=x",
        "/a#fragment",
        "/%0d",
        "/a\r\nX:y",
        "/../a",
        "/./a",
        "/a b",
    ] {
        assert!(WebhookEndpoint::new(peer, path, ContentDigest::sha256(b"approval")).is_err());
    }
    let second = WebhookEndpoint::new(peer, "/different", first.plaintext_approval())?;
    assert_ne!(first.channel(), second.channel());
    assert!(!format!("{first:?}").contains("127.0.0.1"));
    assert!(!format!("{first:?}").contains("notify"));
    Ok(())
}
#[test]
fn response_requires_complete_final_head_and_preserves_all_fragment_boundaries() -> Test {
    for bytes in [b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n".as_slice(),
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
        b"HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\nHTTP/1.0 202 Accepted\r\nX-Receipt: id\r\n\r\n"] {
        for end in 0..bytes.len() { assert_eq!(wire::response(&bytes[..end]), Ok(None), "prefix {end}"); }
        assert!(wire::response(bytes).map_err(|_| "fixture response refused")?.is_some());
    }
    assert_eq!(
        wire::response(b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\npartial"),
        Ok(Some(200))
    );
    Ok(())
}
#[test]
fn response_refuses_ambiguous_framing_and_header_injection() {
    for bytes in [
        b"HTTP/1.1 200 OK\nX: y\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n X: y\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX: y\rZ: x\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"HTTP/1.1 101 Upgrade\r\n\r\n",
        b"HTTP/1.1 204 OK\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\n",
        b"HTTP/1.1 200 O\0K\r\n\r\n",
    ] {
        assert!(wire::response(bytes).is_err(), "{bytes:?}");
    }
    let many = [
        b"HTTP/1.1 100 Continue\r\n\r\n".repeat(9),
        b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
    ]
    .concat();
    assert!(wire::response(&many).is_err());
}
#[test]
fn native_post_is_durably_committed_before_connect_and_never_verified_by_http() -> Test {
    for fragment in [1, 7, 4096] {
        let mut relay = Relay::new(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n")?;
        let endpoint = endpoint(relay.peer()?)?;
        let mut f = fixture(&format!("accepted-{fragment}"), &endpoint)?;
        let owner = Owner::new(&endpoint, f.journal.path());
        let path = f.journal.path().to_path_buf();
        let mut attempt = WebhookAttempt::begin(
            &f.plan,
            &endpoint,
            &f.ledger,
            &mut f.journal,
            limits(fragment),
            101,
            DEADLINE,
            &owner,
            |d| f.objects.read_verified(d).map(|b| b.to_vec()),
        )?;
        assert_eq!(attempt.evidence().sent_bytes(), 0);
        assert_eq!(relay.accepted, 0);
        let on_disk = DurableEffectJournal::inspect(&path, DurableLedgerLimits::default())?;
        assert_eq!(
            on_disk
                .journal
                .ok_or("missing journal")?
                .operation(&f.plan.intent.operation_id)
                .ok_or("missing committed operation")?
                .state,
            EffectState::Committed
        );
        assert_eq!(
            drive(&mut attempt, &mut relay, &f.objects, &owner)?,
            WebhookOutcome::ReceiverAccepted(202)
        );
        assert_eq!(relay.request, attempt.evidence().request());
        assert_eq!(attempt.evidence().sent_bytes(), relay.request.len());
        let request = std::str::from_utf8(&relay.request)?;
        assert!(request.starts_with("POST /notify HTTP/1.1\r\n"));
        assert!(request.contains("Idempotency-Key: "));
        assert!(request.contains("event_revision_sha256"));
        let digest = attempt.evidence().digest()?;
        assert_eq!(
            attempt.record(10000, &owner)?.state,
            EffectState::AdapterAccepted
        );
        assert_eq!(attempt.record(10001, &owner)?.result_digest, Some(digest));
        let calls = attempt.evidence().io_calls();
        assert_eq!(
            attempt.poll(10002, &owner, |d| f
                .objects
                .read_verified(d)
                .map(|b| b.to_vec())),
            WebhookProgress::ReadyToRecord(WebhookOutcome::ReceiverAccepted(202))
        );
        assert_eq!(attempt.evidence().io_calls(), calls);
        let evidence = attempt.retire();
        assert_eq!(
            f.journal
                .obligation(&f.plan.obligation_id)
                .ok_or("missing obligation")?
                .state,
            ObligationState::Pending
        );
        assert!(
            WebhookAttempt::begin(
                &f.plan,
                &endpoint,
                &f.ledger,
                &mut f.journal,
                limits(fragment),
                10003,
                DEADLINE,
                &owner,
                |d| f.objects.read_verified(d).map(|b| b.to_vec())
            )
            .is_err()
        );
        drop(f.journal);
        let reopened = DurableEffectJournal::open(path, IncompleteTailPolicy::Reject)?;
        assert_eq!(
            reopened
                .operation(&f.plan.intent.operation_id)
                .ok_or("lost outcome")?
                .result_digest,
            Some(evidence.digest()?)
        );
    }
    Ok(())
}
#[test]
fn lost_ack_remains_indeterminate_across_cold_restart_without_resend() -> Test {
    let mut relay = Relay::new(b"")?;
    relay.close_without_ack = true;
    let endpoint = endpoint(relay.peer()?)?;
    let mut f = fixture("lost-ack", &endpoint)?;
    let owner = Owner::new(&endpoint, f.journal.path());
    let path = f.journal.path().to_path_buf();
    let mut attempt = WebhookAttempt::begin(
        &f.plan,
        &endpoint,
        &f.ledger,
        &mut f.journal,
        limits(4096),
        101,
        DEADLINE,
        &owner,
        |d| f.objects.read_verified(d).map(|b| b.to_vec()),
    )?;
    assert_eq!(
        drive(&mut attempt, &mut relay, &f.objects, &owner)?,
        WebhookOutcome::Interrupted(WebhookInterruption::Disconnected)
    );
    assert!(!relay.request.is_empty());
    assert_eq!(
        attempt.record(10000, &owner)?.state,
        EffectState::Indeterminate
    );
    let evidence = attempt.retire();
    drop(f.journal);
    let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
    assert_eq!(
        journal
            .obligation(&f.plan.obligation_id)
            .ok_or("missing obligation")?
            .state,
        ObligationState::Indeterminate
    );
    assert!(
        WebhookAttempt::begin(
            &f.plan,
            &endpoint,
            &f.ledger,
            &mut journal,
            limits(4096),
            10001,
            DEADLINE,
            &owner,
            |d| f.objects.read_verified(d).map(|b| b.to_vec())
        )
        .is_err()
    );
    assert_eq!(
        record_webhook_evidence(&evidence, &endpoint, &mut journal, 10002, &owner)?.state,
        EffectState::Indeterminate
    );
    assert_eq!(relay.accepted, 1);
    Ok(())
}
#[test]
fn receiver_error_and_redirect_are_not_proof_of_no_effect_and_are_never_followed() -> Test {
    for (name, response, code) in [
        (
            "redirect",
            b"HTTP/1.1 302 Found\r\nLocation: http://example.invalid/secret\r\n\r\n".as_slice(),
            302,
        ),
        (
            "server-error",
            b"HTTP/1.1 500 Error\r\nContent-Length: 0\r\n\r\n",
            500,
        ),
    ] {
        let mut relay = Relay::new(response)?;
        let endpoint = endpoint(relay.peer()?)?;
        let mut f = fixture(name, &endpoint)?;
        let owner = Owner::new(&endpoint, f.journal.path());
        let mut attempt = WebhookAttempt::begin(
            &f.plan,
            &endpoint,
            &f.ledger,
            &mut f.journal,
            limits(4096),
            101,
            DEADLINE,
            &owner,
            |d| f.objects.read_verified(d).map(|b| b.to_vec()),
        )?;
        assert_eq!(
            drive(&mut attempt, &mut relay, &f.objects, &owner)?,
            WebhookOutcome::ReceiverStatus(code)
        );
        assert_eq!(
            attempt.record(10000, &owner)?.state,
            EffectState::Indeterminate
        );
        assert_eq!(relay.accepted, 1);
    }
    Ok(())
}
#[test]
fn refusal_before_commit_never_opens_socket_or_changes_prepared_operation() -> Test {
    let relay = Relay::new(b"")?;
    let endpoint = endpoint(relay.peer()?)?;
    let mut f = fixture("denied", &endpoint)?;
    let owner = Owner::new(&endpoint, f.journal.path());
    owner.denied.set(Some(WebhookBoundary::Commit));
    assert!(matches!(
        WebhookAttempt::begin(
            &f.plan,
            &endpoint,
            &f.ledger,
            &mut f.journal,
            limits(4096),
            101,
            DEADLINE,
            &owner,
            |d| f.objects.read_verified(d).map(|b| b.to_vec())
        ),
        Err(WebhookError::Denied(_))
    ));
    assert_eq!(
        f.journal
            .operation(&f.plan.intent.operation_id)
            .ok_or("missing operation")?
            .state,
        EffectState::Prepared
    );
    assert!(matches!(relay.listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}
#[test]
fn post_write_revocation_retains_sent_prefix_and_requires_local_cleanup_authority() -> Test {
    let mut relay = Relay::new(b"HTTP/1.1 200 OK\r\n\r\n")?;
    let endpoint = endpoint(relay.peer()?)?;
    let mut f = fixture("post-write", &endpoint)?;
    let owner = Owner::new(&endpoint, f.journal.path());
    owner.revoke_after_send.set(true);
    let mut attempt = WebhookAttempt::begin(
        &f.plan,
        &endpoint,
        &f.ledger,
        &mut f.journal,
        limits(7),
        101,
        DEADLINE,
        &owner,
        |d| f.objects.read_verified(d).map(|b| b.to_vec()),
    )?;
    assert_eq!(
        drive(&mut attempt, &mut relay, &f.objects, &owner)?,
        WebhookOutcome::Interrupted(WebhookInterruption::Denied(WebhookDenial::Revoked))
    );
    assert_eq!(attempt.evidence().sent_bytes(), 7);
    owner.denied.set(Some(WebhookBoundary::Record));
    assert!(matches!(
        attempt.record(10000, &owner),
        Err(WebhookError::Denied(_))
    ));
    let evidence = attempt.retire();
    assert_eq!(evidence.sent_bytes(), 7);
    assert_eq!(
        f.journal
            .operation(&f.plan.intent.operation_id)
            .ok_or("lost commit")?
            .state,
        EffectState::Committed
    );
    owner.denied.set(None);
    assert_eq!(
        record_webhook_evidence(&evidence, &endpoint, &mut f.journal, 10001, &owner)?.state,
        EffectState::Indeterminate
    );
    Ok(())
}
#[test]
fn changed_authority_head_blocks_first_write_after_committed_connect() -> Test {
    let mut relay = Relay::new(b"")?;
    let endpoint = endpoint(relay.peer()?)?;
    let mut f = fixture("stale", &endpoint)?;
    let owner = Owner::new(&endpoint, f.journal.path());
    let mut attempt = WebhookAttempt::begin(
        &f.plan,
        &endpoint,
        &f.ledger,
        &mut f.journal,
        limits(4096),
        101,
        DEADLINE,
        &owner,
        |d| f.objects.read_verified(d).map(|b| b.to_vec()),
    )?;
    assert_eq!(
        attempt.poll(102, &owner, |d| f
            .objects
            .read_verified(d)
            .map(|b| b.to_vec())),
        WebhookProgress::Pending
    );
    assert_eq!(
        attempt.poll(103, &owner, |d| f
            .objects
            .read_verified(d)
            .map(|b| b.to_vec())),
        WebhookProgress::Pending
    );
    fs::OpenOptions::new()
        .append(true)
        .open(f.dir.0.join("events"))?
        .write_all(b"uncommitted mutation")?;
    assert_eq!(
        attempt.poll(104, &owner, |d| f
            .objects
            .read_verified(d)
            .map(|b| b.to_vec())),
        WebhookProgress::ReadyToRecord(WebhookOutcome::Interrupted(
            WebhookInterruption::EventAuthorityRefused
        ))
    );
    relay.step()?;
    assert!(relay.request.is_empty());
    assert_eq!(attempt.evidence().sent_bytes(), 0);
    assert_eq!(
        attempt.record(105, &owner)?.state,
        EffectState::Indeterminate
    );
    Ok(())
}
#[test]
fn route_reinterpretation_and_forged_request_do_not_bypass_canonical_gate() -> Test {
    let relay = Relay::new(b"")?;
    let endpoint = endpoint(relay.peer()?)?;
    let mut f = fixture("forged", &endpoint)?;
    let other = WebhookEndpoint::new(endpoint.peer(), "/other", endpoint.plaintext_approval())?;
    let owner = Owner::new(&other, f.journal.path());
    assert!(matches!(
        WebhookAttempt::begin(
            &f.plan,
            &other,
            &f.ledger,
            &mut f.journal,
            limits(4096),
            101,
            DEADLINE,
            &owner,
            |d| f.objects.read_verified(d).map(|b| b.to_vec())
        ),
        Err(WebhookError::RouteMismatch)
    ));
    let mut forged = f.plan.clone();
    forged.channel = other.channel().to_owned();
    assert!(
        WebhookAttempt::begin(
            &forged,
            &other,
            &f.ledger,
            &mut f.journal,
            limits(4096),
            102,
            DEADLINE,
            &owner,
            |d| f.objects.read_verified(d).map(|b| b.to_vec())
        )
        .is_err()
    );
    assert_eq!(
        f.journal
            .operation(&f.plan.intent.operation_id)
            .ok_or("lost refusal")?
            .state,
        EffectState::Cancelled
    );
    assert!(matches!(relay.listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}
#[test]
fn zero_network_allowance_invalid_lease_and_deadline_do_not_claim_delivery() -> Test {
    let relay = Relay::new(b"")?;
    let endpoint = endpoint(relay.peer()?)?;
    let mut f = fixture("limits", &endpoint)?;
    let owner = Owner::new(&endpoint, f.journal.path());
    assert!(matches!(
        WebhookAttempt::begin(
            &f.plan,
            &endpoint,
            &f.ledger,
            &mut f.journal,
            WebhookLimits {
                io_calls: 0,
                ..limits(7)
            },
            101,
            DEADLINE,
            &owner,
            |d| f.objects.read_verified(d).map(|b| b.to_vec())
        ),
        Err(WebhookError::Configuration)
    ));
    let mut attempt = WebhookAttempt::begin(
        &f.plan,
        &endpoint,
        &f.ledger,
        &mut f.journal,
        limits(7),
        101,
        102,
        &owner,
        |d| f.objects.read_verified(d).map(|b| b.to_vec()),
    )?;
    assert_eq!(
        attempt.poll(102, &owner, |d| f
            .objects
            .read_verified(d)
            .map(|b| b.to_vec())),
        WebhookProgress::ReadyToRecord(WebhookOutcome::Interrupted(WebhookInterruption::Deadline))
    );
    assert_eq!(attempt.evidence().io_calls(), 0);
    assert_eq!(
        attempt.record(103, &owner)?.state,
        EffectState::Indeterminate
    );
    Ok(())
}
#[test]
fn journal_append_failure_preserves_observation_and_does_not_repeat_network() -> Test {
    let mut relay = Relay::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")?;
    let endpoint = endpoint(relay.peer()?)?;
    let mut f = fixture("append-fail", &endpoint)?;
    let owner = Owner::new(&endpoint, f.journal.path());
    let path = f.journal.path().to_path_buf();
    let mut attempt = WebhookAttempt::begin(
        &f.plan,
        &endpoint,
        &f.ledger,
        &mut f.journal,
        limits(4096),
        101,
        DEADLINE,
        &owner,
        |d| f.objects.read_verified(d).map(|b| b.to_vec()),
    )?;
    assert_eq!(
        drive(&mut attempt, &mut relay, &f.objects, &owner)?,
        WebhookOutcome::ReceiverAccepted(200)
    );
    let raw = attempt.evidence().encoded()?;
    let calls = attempt.evidence().io_calls();
    fs::OpenOptions::new()
        .append(true)
        .open(&path)?
        .write_all(b"foreign suffix")?;
    assert!(matches!(
        attempt.record(10000, &owner),
        Err(WebhookError::Journal(_))
    ));
    assert_eq!(attempt.evidence().encoded()?, raw);
    let _progress = attempt.poll(10001, &owner, |d| {
        f.objects.read_verified(d).map(|b| b.to_vec())
    });
    assert_eq!(attempt.evidence().io_calls(), calls);
    assert_eq!(relay.accepted, 1);
    let evidence = attempt.retire();
    assert_eq!(
        evidence.outcome(),
        Some(WebhookOutcome::ReceiverAccepted(200))
    );
    Ok(())
}
#[test]
fn dropped_committed_owner_cannot_be_restarted_as_a_new_dispatch() -> Test {
    let relay = Relay::new(b"")?;
    let endpoint = endpoint(relay.peer()?)?;
    let mut f = fixture("dropped", &endpoint)?;
    let owner = Owner::new(&endpoint, f.journal.path());
    let path = f.journal.path().to_path_buf();
    let attempt = WebhookAttempt::begin(
        &f.plan,
        &endpoint,
        &f.ledger,
        &mut f.journal,
        limits(4096),
        101,
        DEADLINE,
        &owner,
        |d| f.objects.read_verified(d).map(|b| b.to_vec()),
    )?;
    drop(attempt);
    drop(f.journal);
    let mut reopened = DurableEffectJournal::open(path, IncompleteTailPolicy::Reject)?;
    assert!(matches!(
        WebhookAttempt::begin(
            &f.plan,
            &endpoint,
            &f.ledger,
            &mut reopened,
            limits(4096),
            102,
            DEADLINE,
            &owner,
            |d| f.objects.read_verified(d).map(|b| b.to_vec())
        ),
        Err(WebhookError::Authority(ReferenceError::Contract(
            ContractError::ReconciliationRequired
        )))
    ));
    assert!(matches!(relay.listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}

#[test]
fn every_early_socket_allowance_cut_retains_prefix_without_exceeding_the_limit() -> Test {
    for ceiling in 1..=8 {
        let mut relay = Relay::new(b"")?;
        let endpoint = endpoint(relay.peer()?)?;
        let mut f = fixture(&format!("io-cut-{ceiling}"), &endpoint)?;
        let owner = Owner::new(&endpoint, f.journal.path());
        let mut attempt = WebhookAttempt::begin(
            &f.plan,
            &endpoint,
            &f.ledger,
            &mut f.journal,
            WebhookLimits {
                io_calls: ceiling,
                ..limits(7)
            },
            101,
            DEADLINE,
            &owner,
            |d| f.objects.read_verified(d).map(|b| b.to_vec()),
        )?;
        assert_eq!(
            drive(&mut attempt, &mut relay, &f.objects, &owner)?,
            WebhookOutcome::Interrupted(WebhookInterruption::Limit)
        );
        assert_eq!(attempt.evidence().io_calls(), ceiling);
        assert_eq!(
            attempt.evidence().sent_bytes(),
            ceiling.saturating_sub(2) as usize * 7
        );
        assert_eq!(
            attempt.record(10000, &owner)?.state,
            EffectState::Indeterminate
        );
    }
    Ok(())
}
#[test]
fn a_matching_intent_in_another_journal_history_cannot_absorb_wire_evidence() -> Test {
    let relay = Relay::new(b"")?;
    let endpoint = endpoint(relay.peer()?)?;
    let mut f = fixture("wrong-history", &endpoint)?;
    let owner = Owner::new(&endpoint, f.journal.path());
    let attempt = WebhookAttempt::begin(
        &f.plan,
        &endpoint,
        &f.ledger,
        &mut f.journal,
        limits(7),
        101,
        DEADLINE,
        &owner,
        |d| f.objects.read_verified(d).map(|b| b.to_vec()),
    )?;
    let evidence = attempt.retire();
    let mut other =
        DurableEffectJournal::open(f.dir.0.join("other-effects"), IncompleteTailPolicy::Reject)?;
    other.prepare(
        f.plan.intent.clone(),
        f.plan.obligation_id.clone(),
        crate::REFERENCE_ALERT_TERMINAL_PREDICATE,
        TimestampNs(90),
    )?;
    other.transition(
        &f.plan.intent.operation_id,
        EffectState::Committed,
        TimestampNs(91),
        None,
        None,
    )?;
    let other_owner = Owner::new(&endpoint, other.path());
    assert!(matches!(
        record_webhook_evidence(&evidence, &endpoint, &mut other, 102, &other_owner),
        Err(WebhookError::EffectMismatch)
    ));
    assert_eq!(
        other
            .operation(&f.plan.intent.operation_id)
            .ok_or("missing operation")?
            .state,
        EffectState::Committed
    );
    Ok(())
}
#[test]
fn malformed_network_response_and_response_limit_remain_unresolved() -> Test {
    for (name, reply, response_bytes, expected) in [
        (
            "malformed",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
            16384,
            WebhookInterruption::InvalidResponse,
        ),
        (
            "header-limit",
            [b"HTTP/1.1 200 OK\r\nLong: ".as_slice(), &[b'a'; 200]].concat(),
            64,
            WebhookInterruption::Limit,
        ),
    ] {
        let mut relay = Relay::new(&reply)?;
        let endpoint = endpoint(relay.peer()?)?;
        let mut f = fixture(name, &endpoint)?;
        let owner = Owner::new(&endpoint, f.journal.path());
        let mut attempt = WebhookAttempt::begin(
            &f.plan,
            &endpoint,
            &f.ledger,
            &mut f.journal,
            WebhookLimits {
                response_bytes,
                ..limits(4096)
            },
            101,
            DEADLINE,
            &owner,
            |d| f.objects.read_verified(d).map(|b| b.to_vec()),
        )?;
        assert_eq!(
            drive(&mut attempt, &mut relay, &f.objects, &owner)?,
            WebhookOutcome::Interrupted(expected)
        );
        assert!(attempt.evidence().response_prefix().len() <= response_bytes);
        assert_eq!(
            attempt.record(10000, &owner)?.state,
            EffectState::Indeterminate
        );
    }
    Ok(())
}
