#![forbid(unsafe_code)]
//! Native, opt-in HTTP alert dispatch through the existing event and effect gates.
//!
//! This lane targets an explicitly approved plaintext relay, not a TLS downgrade.
//! A complete 2xx response head proves relay acceptance only, never human delivery.
//! Commitment is durable before any network I/O. There is no automatic resend,
//! redirect, credential acquisition, DNS lookup, worker, or terminal-proof shortcut.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;
use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, EffectIntent,
    EffectState, OperationReceipt, TimestampNs};
use fss_ledger::DurableReferenceLedger;
use crate::{DurableEffectError, DurableEffectJournal, ReferenceError};
use super::{ReferenceAlertPlan, check_alert_dispatch_authority, revalidate_alert_event_authority};

mod wire;

/// Frozen relay route. A nonzero approval handle is evidence to the live authority,
/// not authorization by itself. Debug intentionally omits the network address/path.
#[derive(Clone, Eq, PartialEq)]
pub struct WebhookEndpoint {
    peer: SocketAddr,
    target: String,
    approval: ContentDigest,
    digest: ContentDigest,
    channel: String,
}
impl WebhookEndpoint {
    /// Admit an exact, independently resolved peer and non-secret absolute path.
    /// Query strings, userinfo, escapes and redirects are not accepted. A receiver
    /// requiring TLS must use another admitted transport, never a plaintext fallback.
    pub fn new(peer: SocketAddr, target: &str, plaintext_approval: ContentDigest)
        -> Result<Self, WebhookError> {
        if peer.port() == 0 || peer.ip().is_unspecified() || peer.ip().is_multicast()
            || matches!(peer.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
            || !target.starts_with('/') || target.starts_with("//") || target.len() > 1024
            || !target.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._~-".contains(&b))
            || target.split('/').any(|part| part == "." || part == "..")
            || plaintext_approval.bytes() == [0; 32] {
            return Err(WebhookError::Configuration);
        }
        let mut e = CanonicalEncoder::new();
        e.text("fss.http-webhook-route.v1:explicit-plaintext:json-references");
        e.text(&peer.to_string()); e.text(target); e.digest(plaintext_approval);
        let digest = ContentDigest::sha256(&e.finish_checked().map_err(ReferenceError::from)?);
        let channel = format!("http-webhook:{}", wire::hex(digest));
        Ok(Self { peer, target: target.to_owned(), approval: plaintext_approval, digest, channel })
    }
    /// Exact relay address, never resolved or redirected in this module.
    pub fn peer(&self) -> SocketAddr { self.peer }
    /// Frozen non-secret HTTP target.
    pub fn target(&self) -> &str { &self.target }
    /// Independently issued plaintext-route approval handle.
    pub fn plaintext_approval(&self) -> ContentDigest { self.approval }
    /// Frozen route/security profile; successful resource budgets do not change it.
    pub fn digest(&self) -> ContentDigest { self.digest }
    /// Use this exact value as PrepareAlertParams.channel BEFORE preparing the intent.
    /// An existing plan for a different route/channel cannot be repurposed.
    pub fn channel(&self) -> &str { &self.channel }
}
impl std::fmt::Debug for WebhookEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookEndpoint").field("digest", &self.digest).finish_non_exhaustive()
    }
}

/// Distinct boundaries for live capabilities, deadline, cancellation and local cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebhookBoundary {
    /// Authority-ledger reads and durable effect commitment; no network I/O yet.
    Commit,
    /// One bounded TCP connection attempt.
    Connect,
    /// Configure the already connected socket as nonblocking.
    Configure,
    /// Revalidate canonical event authority and send one bounded request prefix.
    Send,
    /// Read a bounded response prefix.
    Receive,
    /// Post-socket operation check; exact returned bytes were retained first.
    AfterIo,
    /// Append the observed outcome locally; may require separately granted cleanup authority.
    Record,
}
/// Live owner refusal without provider/address/secret information.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebhookDenial {
    /// No capability for this exact operation, disclosure or route.
    Unauthorized,
    /// A previously granted capability was revoked.
    Revoked,
    /// Owner cancellation; outstanding committed effects remain recoverable.
    Cancelled,
    /// Independently measured deadline expired.
    Deadline,
    /// Independent resource budget exhausted.
    Budget,
}
/// Exact operation and local effect-journal scope supplied to every authority check.
#[derive(Clone, Copy)]
pub struct WebhookScope<'a> {
    /// Frozen peer, plaintext limitation, path and approval handle.
    pub endpoint: &'a WebhookEndpoint,
    /// Actual durable receipt, including original principal/capability/lease,
    /// effect state, idempotency and preconditions. Check all of them.
    pub operation: &'a OperationReceipt,
    /// Existing local journal path; the owner must authorize this persistence scope.
    pub effect_journal: &'a Path,
}
/// Implement with the owning Cx or equivalent explicit live authority. The check
/// MUST independently verify actual elapsed time, principal, disclosure/route,
/// journal scope, generation and cancellation, including AFTER a socket operation. The
/// supplied time is caller admission time, not an inferred post-I/O clock reading.
/// There is no permissive production implementation. Record is a cleanup boundary:
/// a revoked network lease never grants local journal authority automatically.
pub trait WebhookAuthority {
    /// Fail closed without exposing secret policy/provider strings.
    fn checkpoint(&self, scope: WebhookScope<'_>, boundary: WebhookBoundary,
        now_ns: u64, network_deadline_ns: u64) -> Result<(), WebhookDenial>;
}

/// Whole-attempt ceilings; no retries or budget refills occur internally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebhookLimits {
    /// Every connect/configure/read/write attempt, including WouldBlock/Interrupted.
    pub io_calls: u64,
    /// Maximum bytes offered to one read or write, 1..=4096.
    pub io_bytes: usize,
    /// Complete retained response-prefix bound, 64..=16384 bytes.
    pub response_bytes: usize,
    /// One blocking connect timeout, 1 ns..=5 seconds, further capped by the lease.
    pub connect_timeout_ns: u64,
}
impl WebhookLimits {
    fn validate(self) -> Result<(), WebhookError> {
        if !(1..=4096).contains(&self.io_calls) || !(1..=4096).contains(&self.io_bytes)
            || !(64..=16384).contains(&self.response_bytes)
            || !(1..=5_000_000_000).contains(&self.connect_timeout_ns) {
            return Err(WebhookError::Configuration);
        }
        Ok(())
    }
}

/// Failures before commitment, or explicit local-recording failures. A journal
/// append error can require reopen/reconciliation; it is never a resend instruction.
#[derive(Debug)]
pub enum WebhookError {
    /// Invalid route/limits/lease, or unsupported request representation.
    Configuration,
    /// Plan channel does not pin this exact endpoint.
    RouteMismatch,
    /// Live capability check refused before this operation.
    Denied(WebhookDenial),
    /// Caller admission time regressed.
    ClockReversed,
    /// No completed observation is available for local recording.
    NotFinished,
    /// Existing effect history is not exactly this attempt's intent/outcome.
    EffectMismatch,
    /// Bounded allocation was refused.
    Allocation,
    /// Existing alert authority, policy, corroboration or tamper gate refused.
    Authority(ReferenceError),
    /// Durable effect operation refused; retained wire evidence remains inspectable.
    Journal(DurableEffectError),
}
impl From<ReferenceError> for WebhookError { fn from(e: ReferenceError) -> Self { Self::Authority(e) } }
impl From<DurableEffectError> for WebhookError { fn from(e: DurableEffectError) -> Self { Self::Journal(e) } }
impl std::fmt::Display for WebhookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Configuration => "invalid webhook configuration", Self::RouteMismatch => "webhook route mismatch",
            Self::Denied(_) => "webhook authority refused", Self::ClockReversed => "webhook admission clock reversed",
            Self::NotFinished => "webhook observation unfinished", Self::EffectMismatch => "webhook effect history mismatch",
            Self::Allocation => "webhook allocation refused", Self::Authority(_) => "webhook event authority refused",
            Self::Journal(_) => "webhook local effect recording refused",
        })
    }
}
impl std::error::Error for WebhookError {}

/// Why no trustworthy acknowledgement was accepted. All are conservatively
/// indeterminate after commitment, even when no request byte was sent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebhookInterruption {
    /// Transport lease elapsed.
    Deadline,
    /// Caller admission time moved backwards; no new I/O was permitted.
    ClockReversed,
    /// A live capability was refused.
    Denied(WebhookDenial),
    /// Current event/policy/tamper authority could not be revalidated before a write.
    EventAuthorityRefused,
    /// Whole-attempt socket operation or response-prefix limit reached.
    Limit,
    /// Connect/configure/read/write failed, without exposing OS error text.
    Io,
    /// Socket closed before a complete final response head.
    Disconnected,
    /// Response was malformed or outside the strict supported framing subset.
    InvalidResponse,
    /// Owner explicitly retired unfinished work.
    Retired,
}
/// Acknowledgement is not independent terminal proof or human notification receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebhookOutcome {
    /// A complete HTTP 2xx head, not body completion or actual human delivery.
    ReceiverAccepted(u16),
    /// Non-2xx response; server-side effects are still unknown, not proven absent.
    ReceiverStatus(u16),
    /// No accepted final acknowledgement. Exact prefixes remain available.
    Interrupted(WebhookInterruption),
}
/// One bounded polling result. ReadyToRecord never means the outcome is durable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebhookProgress {
    /// No final acknowledgement yet; call poll under the same owner allowance.
    Pending,
    /// Network is closed; record only locally or transfer the evidence explicitly.
    ReadyToRecord(WebhookOutcome),
}

/// Complete actual request/response prefixes. Construction is private: callers
/// cannot turn arbitrary response bytes into a trusted network observation.
/// Persist encoded() through an authorized custody owner; a digest is not custody.
pub struct WebhookEvidence {
    intent: EffectIntent, route: ContentDigest, commitment_root: ContentDigest, request: Vec<u8>, response: Vec<u8>,
    sent: usize, calls: u64, committed_ns: u64, deadline_ns: u64, last_admission_ns: u64, outcome: Option<WebhookOutcome>,
}
impl WebhookEvidence {
    /// Existing immutable effect identity, never model-generated dispatch authority.
    pub fn intent(&self) -> &EffectIntent { &self.intent }
    /// Exact endpoint/security generation.
    pub fn route_digest(&self) -> ContentDigest { self.route }
    /// Exact durable journal prefix AFTER commit, binding the prepared authority.
    pub fn commitment_root(&self) -> ContentDigest { self.commitment_root }
    /// Complete frozen request. Only request()[..sent_bytes()] was accepted locally by TCP.
    pub fn request(&self) -> &[u8] { &self.request }
    /// Prefix accepted by local write calls; not proof of remote receipt.
    pub fn sent_bytes(&self) -> usize { self.sent }
    /// All bytes actually read, including informational heads and bounded same-read suffix.
    pub fn response_prefix(&self) -> &[u8] { &self.response }
    /// Syscalls attempted; failed/blocked calls remain charged.
    pub fn io_calls(&self) -> u64 { self.calls }
    /// Actual final network disposition, or None while this owner is working.
    pub fn outcome(&self) -> Option<WebhookOutcome> { self.outcome }
    /// Complete local observation encoding; not a new effect journal or delivery proof.
    pub fn encoded(&self) -> Result<Vec<u8>, WebhookError> {
        let outcome = self.outcome.ok_or(WebhookError::NotFinished)?;
        let mut e = CanonicalEncoder::new(); e.text("fss.http-webhook-observation.v1");
        self.intent.encode_canonical(&mut e); e.digest(self.route); e.digest(self.commitment_root);
        e.bytes(&self.request); e.u64(self.sent as u64); e.bytes(&self.response);
        e.u64(self.calls); e.u64(self.committed_ns); e.u64(self.deadline_ns); e.u64(self.last_admission_ns);
        wire::encode_outcome(&mut e, outcome);
        e.finish_checked().map_err(ReferenceError::from).map_err(WebhookError::from)
    }
    /// Source-bound observation fingerprint, not provider-authenticated terminal proof.
    pub fn digest(&self) -> Result<ContentDigest, WebhookError> { Ok(ContentDigest::sha256(&self.encoded()?)) }
}
impl std::fmt::Debug for WebhookEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookEvidence").field("sent_bytes", &self.sent)
            .field("received_bytes", &self.response.len()).field("outcome", &self.outcome).finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase { Connect, Configure, Send, Receive, Finished }

/// Exclusive, finite native dispatch. Dropping/retiring never rolls back the
/// durable Committed operation and never makes it eligible for automatic resend.
/// Poll does at most one socket socket operation; no hidden sleeps, retries or threads.
pub struct WebhookAttempt<'a> {
    plan: &'a ReferenceAlertPlan, endpoint: &'a WebhookEndpoint,
    ledger: &'a DurableReferenceLedger, journal: &'a mut DurableEffectJournal,
    limits: WebhookLimits, deadline_ns: u64, last_ns: u64,
    phase: Phase, stream: Option<TcpStream>, evidence: WebhookEvidence,
}
impl<'a> WebhookAttempt<'a> {
    /// Reuse ALL existing preparation-time/event-lineage/tamper gates, then commit
    /// durably before returning an owner capable of any network I/O. `read_payload`
    /// must verify the objects in the ledger, not manufacture payloads. This method
    /// may durably cancel an ineligible prepared plan through the existing helper.
    #[allow(clippy::too_many_arguments)]
    pub fn begin<E: Into<ReferenceError>>(
        plan: &'a ReferenceAlertPlan, endpoint: &'a WebhookEndpoint,
        ledger: &'a DurableReferenceLedger, journal: &'a mut DurableEffectJournal,
        limits: WebhookLimits, now_ns: u64, deadline_ns: u64,
        owner: &impl WebhookAuthority,
        read_payload: impl FnMut(ContentDigest) -> Result<Vec<u8>, E>,
    ) -> Result<Self, WebhookError> {
        limits.validate()?;
        if deadline_ns <= now_ns || deadline_ns - now_ns > 60_000_000_000 {
            return Err(WebhookError::Configuration);
        }
        if plan.channel != endpoint.channel { return Err(WebhookError::RouteMismatch); }
        let operation = journal.operation(&plan.intent.operation_id).ok_or(WebhookError::EffectMismatch)?;
        let scope = WebhookScope { endpoint, operation, effect_journal: journal.path() };
        owner.checkpoint(scope, WebhookBoundary::Commit, now_ns, deadline_ns).map_err(WebhookError::Denied)?;
        let request = wire::request(plan, endpoint)?;
        let mut response = Vec::new();
        response.try_reserve_exact(limits.response_bytes).map_err(|_| WebhookError::Allocation)?;
        let mut evidence = WebhookEvidence { intent: plan.intent.clone(), route: endpoint.digest,
            commitment_root: journal.last_root(), request, response, sent: 0, calls: 0, committed_ns: now_ns, deadline_ns, last_admission_ns: now_ns, outcome: None };
        revalidate_alert_event_authority(plan, ledger, read_payload,
            TimestampNs(i128::from(now_ns)), journal)?;
        let operation = journal.operation(&plan.intent.operation_id).ok_or(WebhookError::EffectMismatch)?;
        owner.checkpoint(WebhookScope { endpoint, operation, effect_journal: journal.path() },
            WebhookBoundary::Commit, now_ns, deadline_ns).map_err(WebhookError::Denied)?;
        journal.transition(&plan.intent.operation_id, EffectState::Committed,
            TimestampNs(i128::from(now_ns)), None, None)?;
        // The cached root binds exactly the journal history/authority that committed.
        // No allocation or fallible work follows commitment before returning ownership.
        evidence.commitment_root = journal.last_root();
        Ok(Self { plan, endpoint, ledger, journal, limits, deadline_ns, last_ns: now_ns,
            phase: Phase::Connect, stream: None, evidence })
    }
    /// Exact retained input/observation, also available after refusal.
    pub fn evidence(&self) -> &WebhookEvidence { &self.evidence }
    /// Durable receipt may be Committed while a local observation awaits recording.
    pub fn operation(&self) -> Option<&OperationReceipt> { self.journal.operation(&self.plan.intent.operation_id) }

    /// At most one connect/configuration/read/write attempt. Event eligibility is
    /// rechecked before connecting and EACH write, using the same canonical helper
    /// as ordinary dispatch. Failures close the socket and retain all actual bytes.
    /// Spent socket API calls are not refunded; final output never authorizes another send.
    pub fn poll<E: Into<ReferenceError>>(&mut self, now_ns: u64, owner: &impl WebhookAuthority,
        read_payload: impl FnMut(ContentDigest) -> Result<Vec<u8>, E>) -> WebhookProgress {
        if let Some(outcome) = self.evidence.outcome { return WebhookProgress::ReadyToRecord(outcome); }
        if now_ns < self.last_ns {
            return self.finish(WebhookOutcome::Interrupted(WebhookInterruption::ClockReversed));
        }
        self.last_ns = now_ns; self.evidence.last_admission_ns = now_ns;
        if now_ns >= self.deadline_ns {
            return self.finish(WebhookOutcome::Interrupted(WebhookInterruption::Deadline));
        }
        let boundary = match self.phase {
            Phase::Connect => WebhookBoundary::Connect, Phase::Configure => WebhookBoundary::Configure,
            Phase::Send => WebhookBoundary::Send, Phase::Receive => WebhookBoundary::Receive,
            Phase::Finished => return self.finish(WebhookOutcome::Interrupted(WebhookInterruption::Retired)),
        };
        if let Err(reason) = self.probe(owner, boundary, now_ns) {
            return self.finish(WebhookOutcome::Interrupted(WebhookInterruption::Denied(reason)));
        }
        if matches!(self.phase, Phase::Connect | Phase::Send) {
            let obligation = self.journal.obligation(&self.plan.obligation_id);
            let valid = self.journal.operation(&self.plan.intent.operation_id).is_some_and(|op|
                op.state == EffectState::Committed && op.intent == self.plan.intent);
            if !valid || check_alert_dispatch_authority(self.plan, self.ledger, read_payload,
                &self.evidence.intent, obligation).is_err() {
                return self.finish(WebhookOutcome::Interrupted(WebhookInterruption::EventAuthorityRefused));
            }
            // A source read can consume time or trigger revocation. Recheck immediately before send.
            if let Err(reason) = self.probe(owner, boundary, now_ns) {
                return self.finish(WebhookOutcome::Interrupted(WebhookInterruption::Denied(reason)));
            }
        }
        if self.evidence.calls == self.limits.io_calls {
            return self.finish(WebhookOutcome::Interrupted(WebhookInterruption::Limit));
        }
        if self.phase == Phase::Receive && self.evidence.response.len() == self.limits.response_bytes {
            return self.finish(WebhookOutcome::Interrupted(WebhookInterruption::Limit));
        }
        self.evidence.calls += 1;
        let result: Result<(), WebhookInterruption> = match self.phase {
            Phase::Connect => {
                let timeout = self.limits.connect_timeout_ns.min(self.deadline_ns - now_ns);
                match TcpStream::connect_timeout(&self.endpoint.peer, Duration::from_nanos(timeout)) {
                    Ok(stream) => { self.stream = Some(stream); self.phase = Phase::Configure; Ok(()) }
                    Err(_) => Err(WebhookInterruption::Io),
                }
            }
            Phase::Configure => match self.stream.as_ref().map(|s| s.set_nonblocking(true)) {
                Some(Ok(())) => { self.phase = Phase::Send; Ok(()) }
                _ => Err(WebhookInterruption::Io),
            },
            Phase::Send => {
                let end = (self.evidence.sent + self.limits.io_bytes).min(self.evidence.request.len());
                match self.stream.as_mut().map(|s| s.write(&self.evidence.request[self.evidence.sent..end])) {
                    Some(Ok(0)) => Err(WebhookInterruption::Disconnected),
                    Some(Ok(count)) => {
                        self.evidence.sent += count;
                        if self.evidence.sent == self.evidence.request.len() { self.phase = Phase::Receive; }
                        Ok(())
                    }
                    Some(Err(e)) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => Ok(()),
                    _ => Err(WebhookInterruption::Io),
                }
            }
            Phase::Receive => {
                let mut bytes = [0_u8; 4096];
                let count = self.limits.io_bytes.min(self.limits.response_bytes - self.evidence.response.len());
                match self.stream.as_mut().map(|s| s.read(&mut bytes[..count])) {
                    Some(Ok(0)) => Err(WebhookInterruption::Disconnected),
                    Some(Ok(count)) => { self.evidence.response.extend_from_slice(&bytes[..count]); Ok(()) }
                    Some(Err(e)) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => Ok(()),
                    _ => Err(WebhookInterruption::Io),
                }
            }
            Phase::Finished => Err(WebhookInterruption::Retired),
        };
        // Preserve returned bytes/counts BEFORE consulting possibly revoked authority.
        if let Err(reason) = self.probe(owner, WebhookBoundary::AfterIo, now_ns) {
            return self.finish(WebhookOutcome::Interrupted(WebhookInterruption::Denied(reason)));
        }
        if let Err(reason) = result { return self.finish(WebhookOutcome::Interrupted(reason)); }
        if self.phase == Phase::Receive {
            match wire::response(&self.evidence.response) {
                Ok(Some(status)) => return self.finish(if (200..300).contains(&status) {
                    WebhookOutcome::ReceiverAccepted(status)
                } else { WebhookOutcome::ReceiverStatus(status) }),
                Ok(None) => {},
                Err(()) => return self.finish(WebhookOutcome::Interrupted(WebhookInterruption::InvalidResponse)),
            }
        }
        WebhookProgress::Pending
    }

    fn probe(&self, owner: &impl WebhookAuthority, boundary: WebhookBoundary, now_ns: u64)
        -> Result<(), WebhookDenial> {
        let operation = self.journal.operation(&self.plan.intent.operation_id).ok_or(WebhookDenial::Unauthorized)?;
        owner.checkpoint(WebhookScope { endpoint: self.endpoint, operation,
            effect_journal: self.journal.path() }, boundary, now_ns, self.deadline_ns)
    }
    fn finish(&mut self, outcome: WebhookOutcome) -> WebhookProgress {
        self.stream = None; self.phase = Phase::Finished; self.evidence.outcome = Some(outcome);
        WebhookProgress::ReadyToRecord(outcome)
    }
    /// Append only the local observation: 2xx -> AdapterAccepted, everything else ->
    /// Indeterminate. Never Observed/Verified, and never close the delivery obligation.
    /// Storage failure preserves evidence and disables all further socket work. Repeating
    /// this method is local-only; an uncertain append may require journal reopen.
    pub fn record(&mut self, now_ns: u64, owner: &impl WebhookAuthority)
        -> Result<&OperationReceipt, WebhookError> {
        if now_ns < self.last_ns { return Err(WebhookError::ClockReversed); }
        if self.evidence.outcome.is_none() { return Err(WebhookError::NotFinished); }
        self.last_ns = now_ns;
        record_webhook_evidence(&self.evidence, self.endpoint, self.journal, now_ns, owner)
    }
    /// Stop without any further I/O and transfer all request/response evidence.
    /// The durable journal still owns the unresolved/accepted effect. Retirement
    /// does not cancel it, verify delivery, or authorize another attempt.
    #[must_use]
    pub fn retire(mut self) -> WebhookEvidence {
        if self.evidence.outcome.is_none() {
            self.finish(WebhookOutcome::Interrupted(WebhookInterruption::Retired));
        }
        self.evidence
    }
}

/// Record transferred genuine wire evidence under an explicit local-cleanup grant.
/// This also handles a retired owner after cancellation or a failed record append.
/// Reopening an uncertain journal is separate; no network I/O or resend occurs here.
/// Exact recorded repeats verify durable history before returning the old receipt.
pub fn record_webhook_evidence<'a>(evidence: &WebhookEvidence, endpoint: &WebhookEndpoint,
    journal: &'a mut DurableEffectJournal, now_ns: u64, owner: &impl WebhookAuthority)
    -> Result<&'a OperationReceipt, WebhookError> {
    let outcome = evidence.outcome.ok_or(WebhookError::NotFinished)?;
    if now_ns < evidence.last_admission_ns { return Err(WebhookError::ClockReversed); }
    if evidence.route != endpoint.digest { return Err(WebhookError::RouteMismatch); }
    let operation = journal.operation(&evidence.intent.operation_id).ok_or(WebhookError::EffectMismatch)?;
    owner.checkpoint(WebhookScope { endpoint, operation, effect_journal: journal.path() },
        WebhookBoundary::Record, now_ns, evidence.deadline_ns).map_err(WebhookError::Denied)?;
    // No receipt laundering into another history with merely equal operation strings.
    if !journal.committed_roots()?.contains(&evidence.commitment_root) { return Err(WebhookError::EffectMismatch); }
    let digest = evidence.digest()?;
    let next = if matches!(outcome, WebhookOutcome::ReceiverAccepted(_)) {
        EffectState::AdapterAccepted
    } else { EffectState::Indeterminate };
    let operation = journal.operation(&evidence.intent.operation_id).ok_or(WebhookError::EffectMismatch)?;
    if operation.intent != evidence.intent { return Err(WebhookError::EffectMismatch); }
    if operation.state == next && operation.result_digest == Some(digest) {
        return journal.operation(&evidence.intent.operation_id).ok_or(WebhookError::EffectMismatch);
    }
    if operation.state != EffectState::Committed { return Err(WebhookError::EffectMismatch); }
    let reason = (next == EffectState::Indeterminate).then(|| "webhook_delivery_unresolved".to_owned());
    journal.transition(&evidence.intent.operation_id, next, TimestampNs(i128::from(now_ns)),
        Some(digest), reason).map_err(WebhookError::from)
}

#[cfg(test)]
mod tests;
