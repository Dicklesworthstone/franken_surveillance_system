#![forbid(unsafe_code)]
//! Actual loopback observations survive publication, restart and later reconciliation.
//! The peer runs on this test's thread; retrieval has no network or effect authority.

use super::{Prepared, SITE, T_COMMIT, prepared_for_channel};
use crate::alert_reconcile::{
    AlertAttestation, AlertReconciliationOutcome, CAP_ALERT_RECONCILE,
    preview_alert_reconciliation, reconcile_alert_operation,
};
use crate::webhook::retained::{
    WEBHOOK_CUSTODY_BYTES, WEBHOOK_CUSTODY_STORAGE_OPERATIONS, check_webhook_retention,
    read_retained_webhook_evidence, retain_webhook_evidence,
};
use crate::webhook::{
    WebhookAttempt, WebhookAuthority, WebhookBoundary, WebhookDenial, WebhookEndpoint,
    WebhookEvidence, WebhookLimits, WebhookOutcome, WebhookProgress, WebhookScope,
    record_webhook_evidence,
};
use crate::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx};
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, EffectState, ObligationState, OperationId,
    RootAuthoritySpec, TimestampNs,
};
use fss_publication::{LOCAL_ROOTS_DIR, LedgerCutPoint, LocalPublicationError, ROOT_RECORD_SUFFIX};
use std::error::Error;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

type Test<T = ()> = Result<T, Box<dyn Error>>;
const OWNER: &str = "principal:webhook-custody-owner";
const INSPECT: &str = "CAP-AGENT-SITUATION-READ-001";
const COMMIT: &str = "CAP-ALERT-COMMIT-001";
const START: u64 = T_COMMIT as u64;
const DEADLINE: u64 = START + 10_000_000_000;
const ACCEPTED: &[u8] = b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n";

fn context(root: &Path, capabilities: &[&str]) -> Test<(ContextAuthority, ReplayCx)> {
    let mut caps = vec![ADP_REPLAY_ROW_ID.to_owned()];
    caps.extend(
        capabilities
            .iter()
            .map(|capability| (*capability).to_owned()),
    );
    caps.sort();
    caps.dedup();
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:webhook-custody-test".to_owned(),
        operation_id: OperationId::parse("operation:webhook-custody-test")?,
        principal: OWNER.to_owned(),
        capabilities: caps,
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(8 * 1024 * 1024)
            .storage_operations(8192)
            .build()?,
        privacy_scope: "privacy:local-authorized-files".to_owned(),
        retention_scope: "retention:existing-deployment-policy".to_owned(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, root.to_path_buf())?;
    Ok((authority, cx))
}

fn journal_bytes(dep: &ReferenceDeployment) -> Test<(Vec<u8>, Vec<u8>)> {
    Ok((
        fs::read(dep.effects().path())?,
        fs::read(dep.ledger().path())?,
    ))
}

struct Owner {
    route: ContentDigest,
    journal: PathBuf,
}

impl WebhookAuthority for Owner {
    fn checkpoint(
        &self,
        scope: WebhookScope<'_>,
        boundary: WebhookBoundary,
        now: u64,
        deadline: u64,
    ) -> Result<u64, WebhookDenial> {
        if scope.endpoint.digest() != self.route
            || scope.effect_journal != self.journal
            || scope.operation.intent.effect_class != "alert.dispatch"
        {
            return Err(WebhookDenial::Unauthorized);
        }
        if boundary != WebhookBoundary::Record && now >= deadline {
            return Err(WebhookDenial::Deadline);
        }
        Ok(now)
    }
}

/// One bounded, same-thread receiver. The request is actual socket input, independent of
/// the adapter's retained request. A second connection is always a test failure.
struct Relay {
    listener: TcpListener,
    stream: Option<TcpStream>,
    request: Vec<u8>,
    reply: Vec<u8>,
    sent: usize,
    accepted: usize,
    lose_ack: bool,
}

impl Relay {
    fn new(lose_ack: bool) -> Test<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            stream: None,
            request: Vec::new(),
            reply: ACCEPTED.to_vec(),
            sent: 0,
            accepted: 0,
            lose_ack,
        })
    }

    fn peer(&self) -> Test<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    fn step(&mut self) -> Test {
        match self.listener.accept() {
            Ok((stream, _)) => {
                self.accepted += 1;
                assert_eq!(self.accepted, 1, "evidence handling must never resend");
                stream.set_nonblocking(true)?;
                self.stream = Some(stream);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
        let Some(stream) = self.stream.as_mut() else {
            return Ok(());
        };
        let mut bytes = [0; 4096];
        match stream.read(&mut bytes) {
            Ok(n) => self.request.extend_from_slice(&bytes[..n]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
        if self.request.len() > 8192 {
            return Err("test relay request exceeded its bound".into());
        }
        if let Some(end) = self
            .request
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
        {
            let headers = std::str::from_utf8(&self.request[..end])?;
            let size: usize = headers
                .split("\r\n")
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .ok_or("test request omitted length")?
                .parse()?;
            if self.request.len() == end + 4 + size {
                if self.lose_ack {
                    self.stream = None;
                    return Ok(());
                }
                if self.sent < self.reply.len() {
                    match stream.write(&self.reply[self.sent..]) {
                        Ok(n) => self.sent += n,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        Err(error) => return Err(error.into()),
                    }
                }
            }
        }
        Ok(())
    }
}

struct Fixture {
    prepared: Prepared,
    endpoint: WebhookEndpoint,
    owner: Owner,
    relay: Relay,
    _directory: Directory,
}

struct Directory(PathBuf);

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl Fixture {
    fn new(label: &str, lose_ack: bool) -> Test<Self> {
        let relay = Relay::new(lose_ack)?;
        let endpoint = WebhookEndpoint::new(
            relay.peer()?,
            "/notify",
            ContentDigest::sha256(b"explicit-local-test-only-plaintext-route-approval"),
        )?;
        let prepared = prepared_for_channel(label, endpoint.channel())?;
        let owner = Owner {
            route: endpoint.digest(),
            journal: prepared.dep.effects().path().to_path_buf(),
        };
        let directory = Directory(prepared.root.clone());
        Ok(Self {
            prepared,
            endpoint,
            owner,
            relay,
            _directory: directory,
        })
    }

    fn observe(&mut self) -> Test<WebhookEvidence> {
        let (journal, ledger, publisher) = self.prepared.dep.effect_dispatch_parts();
        let mut attempt = WebhookAttempt::begin(
            &self.prepared.plan,
            &self.endpoint,
            ledger,
            journal,
            WebhookLimits {
                io_calls: 4096,
                io_bytes: 4096,
                response_bytes: 16_384,
                connect_timeout_ns: 100_000_000,
            },
            START,
            DEADLINE,
            &self.owner,
            |digest| {
                publisher
                    .spool()
                    .read(digest)
                    .map_err(LocalPublicationError::Spool)
            },
        )?;
        for step in 1..=4096 {
            self.relay.step()?;
            if let WebhookProgress::ReadyToRecord(_) =
                attempt.poll(START + step, &self.owner, |digest| {
                    publisher
                        .spool()
                        .read(digest)
                        .map_err(LocalPublicationError::Spool)
                })
            {
                let evidence = attempt.retire();
                assert_eq!(self.relay.accepted, 1);
                assert_eq!(evidence.request(), self.relay.request);
                assert_eq!(evidence.sent_bytes(), self.relay.request.len());
                return Ok(evidence);
            }
            // Allow loopback TCP acknowledgment timers to run; production poll never sleeps.
            if attempt.evidence().sent_bytes() == attempt.evidence().request().len() {
                std::thread::sleep(Duration::from_millis(1));
            } else {
                std::thread::yield_now();
            }
        }
        Err("bounded loopback observation did not finish".into())
    }
}

#[test]
fn accepted_bytes_are_root_last_custody_and_cold_inspection_never_writes() -> Test {
    let mut fixture = Fixture::new("wire-cold-read", false)?;
    let evidence = fixture.observe()?;
    assert_eq!(
        evidence.outcome(),
        Some(WebhookOutcome::ReceiverAccepted(202))
    );
    let (auth, cx) = context(&fixture.prepared.root, &[INSPECT, COMMIT])?;
    fixture
        .prepared
        .dep
        .publisher_mut()
        .tighten_read_budget(WEBHOOK_CUSTODY_BYTES, WEBHOOK_CUSTODY_STORAGE_OPERATIONS)?;
    let original_journal = fs::read(fixture.prepared.dep.effects().path())?;
    let retained = retain_webhook_evidence(&mut fixture.prepared.dep, &evidence, &auth, &cx)?;
    assert!(!retained.journal_observation_recorded());
    assert_eq!(retained.digest(), evidence.digest()?);
    assert_eq!(retained.intent(), evidence.intent());
    assert_eq!(retained.commitment_root(), evidence.commitment_root());
    assert_eq!(retained.request(), fixture.relay.request);
    assert_eq!(retained.response_prefix(), ACCEPTED);
    assert_eq!(retained.sent_bytes(), fixture.relay.request.len());
    assert_eq!(
        fixture
            .prepared
            .dep
            .publisher()
            .spool()
            .read(retained.digest())?,
        evidence.encoded()?
    );
    assert!(fixture.prepared.dep.ledger().batches().iter().any(|batch| {
        batch.children.contains(&retained.digest())
            && batch.deltas.iter().any(|delta| {
                delta.family == fss_publication::ROOT_REACHABILITY_FAMILY
                    && delta.payload_digest == retained.root()
            })
    }));
    assert_eq!(
        original_journal,
        fs::read(fixture.prepared.dep.effects().path())?
    );
    let receipt = record_webhook_evidence(
        &evidence,
        &fixture.endpoint,
        fixture.prepared.dep.effects_mut(),
        START + 10_000,
        &fixture.owner,
    )?;
    assert_eq!(receipt.state, EffectState::AdapterAccepted);
    assert_eq!(receipt.result_digest, Some(retained.digest()));
    let id = fixture.prepared.plan.intent.operation_id.clone();
    let before = journal_bytes(&fixture.prepared.dep)?;
    drop(fixture.prepared.dep);
    cx.drain_and_finalize();
    let (auth, cx) = context(&fixture.prepared.root, &[INSPECT])?;
    let reopened = ReferenceDeployment::open(&fixture.prepared.root, SITE, &cx)?;
    let after_open = journal_bytes(&reopened)?;
    for _ in 0..3 {
        let loaded = read_retained_webhook_evidence(&reopened, &id, &auth, &cx)?
            .ok_or("cold inspection lost retained wire")?;
        assert_eq!(loaded.digest(), retained.digest());
        assert_eq!(loaded.root(), retained.root());
        assert_eq!(loaded.request(), evidence.request());
        assert_eq!(loaded.response_prefix(), evidence.response_prefix());
        assert_eq!(loaded.outcome(), WebhookOutcome::ReceiverAccepted(202));
        assert!(loaded.journal_observation_recorded());
    }
    assert_eq!(before, after_open);
    assert_eq!(after_open, journal_bytes(&reopened)?);
    assert_ne!(
        reopened
            .effects()
            .obligation(&fixture.prepared.plan.obligation_id)
            .ok_or("missing obligation")?
            .state,
        ObligationState::Verified,
        "an HTTP acknowledgment must not become proof of human delivery"
    );
    fixture.relay.step()?;
    assert_eq!(fixture.relay.accepted, 1);
    Ok(())
}

#[test]
fn published_wire_before_journal_observation_survives_restart_without_resend() -> Test {
    let mut fixture = Fixture::new("wire-published-crash", false)?;
    let evidence = fixture.observe()?;
    let (auth, cx) = context(&fixture.prepared.root, &[INSPECT, COMMIT])?;
    let retained = retain_webhook_evidence(&mut fixture.prepared.dep, &evidence, &auth, &cx)?;
    let id = fixture.prepared.plan.intent.operation_id.clone();
    assert_eq!(
        fixture
            .prepared
            .dep
            .effects()
            .operation(&id)
            .ok_or("missing commitment")?
            .state,
        EffectState::Committed
    );
    drop(fixture.prepared.dep);
    cx.drain_and_finalize();
    let (auth, cx) = context(&fixture.prepared.root, &[INSPECT, COMMIT])?;
    let mut reopened = ReferenceDeployment::open(&fixture.prepared.root, SITE, &cx)?;
    let operation = reopened.effects().operation(&id).ok_or("lost operation")?;
    assert_eq!(operation.state, EffectState::Indeterminate);
    assert_eq!(operation.result_digest, None);
    let before = journal_bytes(&reopened)?;
    let loaded = read_retained_webhook_evidence(&reopened, &id, &auth, &cx)?
        .ok_or("published observation disappeared across the crash cut")?;
    assert_eq!(loaded.digest(), retained.digest());
    assert_eq!(loaded.response_prefix(), ACCEPTED);
    assert!(!loaded.journal_observation_recorded());
    let retry = retain_webhook_evidence(&mut reopened, &evidence, &auth, &cx)?;
    assert_eq!(retry.digest(), retained.digest());
    assert_eq!(retry.root(), retained.root());
    assert_eq!(before, journal_bytes(&reopened)?);
    fixture.relay.step()?;
    assert_eq!(fixture.relay.accepted, 1);
    assert_eq!(
        reopened
            .effects()
            .operation(&id)
            .ok_or("missing operation")?
            .state,
        EffectState::Indeterminate
    );
    Ok(())
}

#[test]
fn staging_wire_alone_is_not_published_evidence_after_a_crash() -> Test {
    let mut fixture = Fixture::new("wire-staged-crash", true)?;
    let evidence = fixture.observe()?;
    assert!(matches!(
        evidence.outcome(),
        Some(WebhookOutcome::Interrupted(_))
    ));
    assert_eq!(evidence.response_prefix(), b"");
    let staged = fixture.prepared.dep.stage_payload(&evidence.encoded()?)?;
    assert_eq!(staged, evidence.digest()?);
    let id = fixture.prepared.plan.intent.operation_id.clone();
    let (auth, cx) = context(&fixture.prepared.root, &[INSPECT])?;
    assert!(read_retained_webhook_evidence(&fixture.prepared.dep, &id, &auth, &cx)?.is_none());
    drop(fixture.prepared.dep);
    cx.drain_and_finalize();
    let (auth, cx) = context(&fixture.prepared.root, &[INSPECT])?;
    let reopened = ReferenceDeployment::open(&fixture.prepared.root, SITE, &cx)?;
    let before = journal_bytes(&reopened)?;
    assert_eq!(
        reopened
            .effects()
            .operation(&id)
            .ok_or("missing operation")?
            .state,
        EffectState::Indeterminate
    );
    assert!(read_retained_webhook_evidence(&reopened, &id, &auth, &cx)?.is_none());
    assert_eq!(before, journal_bytes(&reopened)?);
    fixture.relay.step()?;
    assert_eq!(fixture.relay.accepted, 1);
    Ok(())
}

#[test]
fn durable_root_before_ledger_append_is_recovered_once_without_retransmission() -> Test {
    let mut fixture = Fixture::new("wire-root-ledger-crash", false)?;
    let evidence = fixture.observe()?;
    let (auth, cx) = context(&fixture.prepared.root, &[INSPECT, COMMIT])?;
    let id = fixture.prepared.plan.intent.operation_id.clone();
    let before = journal_bytes(&fixture.prepared.dep)?;
    fixture
        .prepared
        .dep
        .inject_ledger_crash_at(LedgerCutPoint::AfterRootDurable);
    assert!(retain_webhook_evidence(&mut fixture.prepared.dep, &evidence, &auth, &cx).is_err());
    assert_eq!(before, journal_bytes(&fixture.prepared.dep)?);
    assert!(read_retained_webhook_evidence(&fixture.prepared.dep, &id, &auth, &cx).is_err());
    drop(fixture.prepared.dep);
    cx.drain_and_finalize();
    let (auth, cx) = context(&fixture.prepared.root, &[INSPECT, COMMIT])?;
    let mut reopened = ReferenceDeployment::open(&fixture.prepared.root, SITE, &cx)?;
    let recovered_journal = fs::read(reopened.effects().path())?;
    assert!(read_retained_webhook_evidence(&reopened, &id, &auth, &cx).is_err());
    let retained = retain_webhook_evidence(&mut reopened, &evidence, &auth, &cx)?;
    assert_eq!(retained.digest(), evidence.digest()?);
    assert_eq!(recovered_journal, fs::read(reopened.effects().path())?);
    let after = journal_bytes(&reopened)?;
    let duplicate = retain_webhook_evidence(&mut reopened, &evidence, &auth, &cx)?;
    assert_eq!(duplicate.root(), retained.root());
    assert_eq!(after, journal_bytes(&reopened)?);
    assert_eq!(
        reopened
            .effects()
            .operation(&id)
            .ok_or("missing operation")?
            .state,
        EffectState::Indeterminate
    );
    fixture.relay.step()?;
    assert_eq!(fixture.relay.accepted, 1);
    Ok(())
}

#[test]
fn tampered_wire_or_missing_root_is_refused_without_repairing_history() -> Test {
    for (label, damage_root) in [("wire-tamper", false), ("wire-root-missing", true)] {
        let mut fixture = Fixture::new(label, false)?;
        let evidence = fixture.observe()?;
        let (auth, cx) = context(&fixture.prepared.root, &[INSPECT, COMMIT])?;
        let retained = retain_webhook_evidence(&mut fixture.prepared.dep, &evidence, &auth, &cx)?;
        let id = fixture.prepared.plan.intent.operation_id.clone();
        let before = journal_bytes(&fixture.prepared.dep)?;
        if damage_root {
            let path = fixture
                .prepared
                .dep
                .publisher()
                .root_dir()
                .join(LOCAL_ROOTS_DIR)
                .join(format!("{}{ROOT_RECORD_SUFFIX}", retained.slot()));
            fs::remove_file(path)?;
        } else {
            let path = fixture
                .prepared
                .dep
                .publisher()
                .spool()
                .object_path(retained.digest());
            let mut bytes = fs::read(&path)?;
            let last = bytes.last_mut().ok_or("empty stored object")?;
            *last ^= 1;
            fs::write(path, bytes)?;
        }
        assert!(read_retained_webhook_evidence(&fixture.prepared.dep, &id, &auth, &cx).is_err());
        assert!(retain_webhook_evidence(&mut fixture.prepared.dep, &evidence, &auth, &cx).is_err());
        assert_eq!(before, journal_bytes(&fixture.prepared.dep)?);
        fixture.relay.step()?;
        assert_eq!(fixture.relay.accepted, 1);
    }
    Ok(())
}

#[test]
fn terminal_operator_reconciliation_preserves_separate_actual_wire_custody() -> Test {
    let mut fixture = Fixture::new("wire-after-reconciliation", false)?;
    let evidence = fixture.observe()?;
    let (auth, cx) = context(
        &fixture.prepared.root,
        &[INSPECT, COMMIT, CAP_ALERT_RECONCILE],
    )?;
    let retained = retain_webhook_evidence(&mut fixture.prepared.dep, &evidence, &auth, &cx)?;
    record_webhook_evidence(
        &evidence,
        &fixture.endpoint,
        fixture.prepared.dep.effects_mut(),
        START + 10_000,
        &fixture.owner,
    )?;
    let id = fixture.prepared.plan.intent.operation_id.clone();
    let attestation = AlertAttestation {
        outcome: AlertReconciliationOutcome::Delivered,
        evidence: ContentDigest::sha256(b"independent recipient confirmation, asserted by owner"),
        statement: "Recipient independently confirmed receipt".to_owned(),
    };
    let preview =
        preview_alert_reconciliation(&fixture.prepared.dep, &id, &attestation, &auth, &cx)?;
    let reconciled = reconcile_alert_operation(
        &mut fixture.prepared.dep,
        &id,
        &attestation,
        preview.approval_digest(),
        TimestampNs(i128::from(START + 20_000)),
        &auth,
        &cx,
    )?;
    assert_eq!(reconciled.operation.state, EffectState::Verified);
    assert_ne!(reconciled.operation.result_digest, Some(retained.digest()));
    let before = journal_bytes(&fixture.prepared.dep)?;
    let loaded = read_retained_webhook_evidence(&fixture.prepared.dep, &id, &auth, &cx)?
        .ok_or("new terminal proof hid the original wire")?;
    assert_eq!(loaded.digest(), evidence.digest()?);
    assert_eq!(loaded.request(), evidence.request());
    assert_eq!(loaded.response_prefix(), ACCEPTED);
    assert_eq!(loaded.outcome(), WebhookOutcome::ReceiverAccepted(202));
    assert!(loaded.journal_observation_recorded());
    let retry = retain_webhook_evidence(&mut fixture.prepared.dep, &evidence, &auth, &cx)?;
    assert_eq!(retry.digest(), retained.digest());
    assert_eq!(before, journal_bytes(&fixture.prepared.dep)?);
    fixture.relay.step()?;
    assert_eq!(fixture.relay.accepted, 1);
    Ok(())
}

#[test]
fn owner_assertion_without_wire_custody_cannot_be_reported_as_a_network_observation() -> Test {
    let mut fixture = Fixture::new("wire-not-operator-assertion", true)?;
    let evidence = fixture.observe()?;
    record_webhook_evidence(
        &evidence,
        &fixture.endpoint,
        fixture.prepared.dep.effects_mut(),
        START + 10_000,
        &fixture.owner,
    )?;
    let id = fixture.prepared.plan.intent.operation_id.clone();
    let (auth, cx) = context(
        &fixture.prepared.root,
        &[INSPECT, COMMIT, CAP_ALERT_RECONCILE],
    )?;
    let attestation = AlertAttestation {
        outcome: AlertReconciliationOutcome::Delivered,
        evidence: evidence.digest()?,
        statement: "Owner cites an observation digest without retaining its actual bytes"
            .to_owned(),
    };
    let preview =
        preview_alert_reconciliation(&fixture.prepared.dep, &id, &attestation, &auth, &cx)?;
    reconcile_alert_operation(
        &mut fixture.prepared.dep,
        &id,
        &attestation,
        preview.approval_digest(),
        TimestampNs(i128::from(START + 20_000)),
        &auth,
        &cx,
    )?;
    let before = journal_bytes(&fixture.prepared.dep)?;
    assert!(read_retained_webhook_evidence(&fixture.prepared.dep, &id, &auth, &cx)?.is_none());
    assert_eq!(before, journal_bytes(&fixture.prepared.dep)?);
    fixture.relay.step()?;
    assert_eq!(fixture.relay.accepted, 1);
    Ok(())
}

#[test]
fn custody_authority_refusal_and_prepublication_cancellation_leave_both_journals_unchanged() -> Test
{
    let mut fixture = Fixture::new("wire-custody-denied", false)?;
    let id = fixture.prepared.plan.intent.operation_id.clone();
    let (preflight_auth, preflight_cx) = context(&fixture.prepared.root, &[COMMIT])?;
    let prepared_history = journal_bytes(&fixture.prepared.dep)?;
    check_webhook_retention(&fixture.prepared.dep, &id, &preflight_auth, &preflight_cx)?;
    assert_eq!(prepared_history, journal_bytes(&fixture.prepared.dep)?);
    let evidence = fixture.observe()?;
    let before = journal_bytes(&fixture.prepared.dep)?;
    let (denied, denied_cx) = context(&fixture.prepared.root, &[])?;
    assert!(
        retain_webhook_evidence(&mut fixture.prepared.dep, &evidence, &denied, &denied_cx,)
            .is_err()
    );
    assert!(
        read_retained_webhook_evidence(&fixture.prepared.dep, &id, &denied, &denied_cx).is_err()
    );
    let (mut auth, cx) = context(&fixture.prepared.root, &[INSPECT, COMMIT])?;
    auth.anchor_universe = ContentDigest::sha256(b"another deployment's authority");
    assert!(retain_webhook_evidence(&mut fixture.prepared.dep, &evidence, &auth, &cx).is_err());
    let (auth, cancelled) = context(&fixture.prepared.root, &[INSPECT, COMMIT])?;
    cancelled.request_cancellation();
    assert!(
        retain_webhook_evidence(&mut fixture.prepared.dep, &evidence, &auth, &cancelled,).is_err()
    );
    assert_eq!(before, journal_bytes(&fixture.prepared.dep)?);
    fixture.relay.step()?;
    assert_eq!(fixture.relay.accepted, 1);
    Ok(())
}
