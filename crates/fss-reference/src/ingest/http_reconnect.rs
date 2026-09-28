#![forbid(unsafe_code)]
//! Bounded native HTTP reacquisition across explicitly reserved source generations.
//!
//! A plan contains the exact routes and per-connection allowances approved by its owner. Their
//! checked sum is the whole-plan reservation; a failed connection consumes its slot, and unused
//! allowances are never recycled. One framing-work budget and one absolute deadline span every
//! connection. No generation, route, credential, clock, worker, sleep or grant is invented here.
//!
//! Each connection ends at a mandatory ownership barrier. `take_handoff` transfers all unfinished
//! source, and `acknowledge_handoff` accepts responsibility for that exact transfer before another
//! connection is possible. This is NOT proof of durable custody: retain the reads and handoff before
//! acknowledging them. A reconnect is always a discontinuity, never evidence of scene absence or
//! capture continuity. Only selected transport failures and explicit framing truncation are
//! retryable; authorization, privacy, malformed input, resource limits and cancellation fail closed.

use std::fmt;
use std::io::ErrorKind;

use fss_codec_mjpeg::DecodeBudget;
use fss_codec_mjpeg::http::{HttpError, HttpResponseStream};
use fss_codec_mjpeg::http_mjpeg::{HttpJpegFrame, HttpMjpegError};
use fss_codec_mjpeg::multipart::MultipartError;
use fss_codec_mjpeg::stream::StreamBasis;

use super::http_camera::{
    HttpCamera, HttpCameraAuthority, HttpCameraError, HttpCameraLimits, HttpCameraOperation,
    HttpCameraRetirement, HttpCameraRoute, HttpCameraStep, HttpCameraTotals, HttpWireRead,
    HttpWireReceipt,
};

/// Hard bound on reserved connections; every slot is consumed at most once.
pub const MAX_RECONNECT_CONNECTIONS: usize = 32;

/// An independently selected route/generation and its non-replenishing allowance. Not a grant.
#[derive(Clone, Debug)]
pub struct HttpReconnectSlot {
    /// Same source and endpoint as every other slot, with a strictly newer stream generation.
    pub route: HttpCameraRoute,
    /// Reserved for this connection only. Unused capacity is not transferred to another slot.
    pub limits: HttpCameraLimits,
}

/// Explicit owner policy; there is deliberately no permissive default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpReconnectPolicy {
    /// Positive delay before the first retry; retries back off exponentially without sleeping here.
    pub initial_backoff_ns: u64,
    /// Positive cap, at most sixty seconds, on each retry delay.
    pub maximum_backoff_ns: u64,
    /// Whether an actually completed HTTP/MIME response may start a fresh source generation.
    pub reconnect_after_complete: bool,
    /// Single native framing-work allowance across the entire plan, including failed attempts.
    pub framing_work: u64,
}

/// Checked sum of independently reserved slots, not measured resource consumption.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HttpReconnectReservation {
    /// Maximum number of submitted connections, including refused submissions.
    pub connections: u32,
    /// Maximum original response bytes over all slots.
    pub wire_bytes: u64,
    /// Maximum dechunked bytes over all slots.
    pub entity_bytes: u64,
    /// Maximum admitted nonzero HTTP chunks over all slots.
    pub chunks: u64,
    /// Maximum read/write syscall attempts over all slots.
    pub io_calls: u64,
    /// Maximum complete MIME parts, not decoded pictures or retained evidence.
    pub frames: u64,
    /// Sum of connect timeout ceilings, additionally limited by the one absolute deadline.
    pub connect_timeout_ns: u64,
    /// Single parser-work budget; never recreated when a connection ends.
    pub framing_work: u64,
}

/// Actual local work, independent of the reservation and of remote receipt/capture claims.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HttpReconnectTotals {
    /// Consumed plan slots, including a connect refused before TCP.
    pub slots_started: u32,
    /// TCP attempts actually made by the native connector.
    pub connect_attempts: u32,
    /// Locally accepted request bytes, not a remote acknowledgement.
    pub sent_bytes: u64,
    /// All original successful reads, including post-read revocation.
    pub received_bytes: u64,
    /// Read syscall attempts, including WouldBlock and Interrupted.
    pub read_calls: u64,
    /// Write syscall attempts, including WouldBlock and Interrupted.
    pub write_calls: u64,
    /// Complete mapped MIME parts, including an untransferred part in a handoff.
    pub frames: u64,
    /// Connections that really completed both HTTP and MIME framing.
    pub completed_connections: u32,
    /// Consumed shared native parser work, including failed parsing.
    pub framing_work: u64,
}

/// Why an exact connection slot ended. No variant certifies physical sensor continuity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpReconnectOutcome {
    /// Both native parsers completed; the original completion receipt stays in the handoff.
    Complete,
    /// Connection setup failed; no HTTP request was sent by this connector.
    ConnectFailed {
        /// Original payload-free failure, not a retry recommendation.
        reason: HttpCameraError,
        /// Whether TCP was attempted rather than refused before I/O.
        attempted: bool,
    },
    /// A connected source failed; accepted raw input remains in the handoff.
    SourceFailed(HttpCameraError),
}

/// Explicit reason no additional connection will be submitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpReconnectStop {
    /// Successful completion with continuous reacquisition disabled.
    Complete,
    /// Failure is outside the narrow transport/truncation retry policy.
    NotRetryable,
    /// No independently reserved source generation remains.
    ConnectionsExhausted,
    /// No shared native parser-work allowance remains.
    FramingWorkExhausted,
    /// Backoff cannot finish strictly before the absolute deadline, or its clock sum overflows.
    Deadline,
}

/// Immutable source-boundary acknowledgement key. It is not a custody/publication certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpReconnectReceipt {
    /// One-based consumed slot ordinal, never reused within this owner.
    pub connection: u32,
    /// Exact ended source generation, even when no response bytes arrived.
    pub source: StreamBasis,
    /// Original terminal observation, preserved rather than flattened into success.
    pub outcome: HttpReconnectOutcome,
    /// Original connection-local I/O accounting; offsets restart only in a new generation.
    pub totals: HttpCameraTotals,
    /// Owner admission time of the terminal observation, NEVER camera capture time.
    pub admitted_ns: u64,
    /// Exact next preselected source generation, or None when terminal.
    pub next_source: Option<StreamBasis>,
    /// Earliest external-owner admission time for that next connection.
    pub retry_at_ns: Option<u64>,
    /// Why the plan stops; exactly one of this or next_source is present.
    pub stop: Option<HttpReconnectStop>,
}

/// Original source ownership transfer; take it and retain it before acknowledging its receipt.
#[derive(Debug)]
#[must_use]
pub struct HttpReconnectHandoff {
    receipt: HttpReconnectReceipt,
    /// Every unexposed raw read, parser remainder, pending frame and actual completion receipt.
    /// None only when the native connector never constructed an HTTP camera owner.
    pub source: Option<HttpCameraRetirement>,
}
impl HttpReconnectHandoff {
    /// Exact key to acknowledge only after accepting responsibility for all transferred source.
    pub fn receipt(&self) -> HttpReconnectReceipt {
        self.receipt
    }
}

/// One bounded owner operation; waiting never spins or sleeps inside this library.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpReconnectStep {
    /// One TCP connection succeeded, but no GET or first-frame claim is made.
    Connected(StreamBasis),
    /// Existing source progress, with the same raw-read/frame backpressure contract.
    Source(HttpCameraStep),
    /// External owner must wait, checking readiness, cancellation and deadline independently.
    Waiting {
        /// Earliest reconnect time, in the caller's nanosecond clock.
        not_before_ns: u64,
    },
    /// Transfer and acknowledge this exact handoff before any later network attempt.
    HandoffReady(HttpReconnectReceipt),
    /// All mandatory handoffs were accepted and no further connection is planned.
    Stopped,
}

/// Payload-free supervisor refusals. Source refusals retain their original typed identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpReconnectError {
    /// Invalid/overflowing plan, endpoint drift, repeated generation or invalid limits.
    Configuration,
    /// Admission clock regressed; this caller error does not advance the owner.
    ClockReversed,
    /// No live source owns the requested wire/frame operation.
    NotActive,
    /// A handoff was not transferred, or its exact source-bound key does not match.
    ReceiptMismatch,
    /// Source or current authority refused; no implicit grant or retry is created.
    Source(HttpCameraError),
}
impl fmt::Display for HttpReconnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HTTP reacquisition refused: {self:?}")
    }
}
impl std::error::Error for HttpReconnectError {}

/// Native bounded reacquisition with an ownership barrier between every source generation.
/// Drop closes the current socket only. Use `retire` to transfer unfinished source instead.
pub struct HttpReconnect {
    slots: Vec<HttpReconnectSlot>,
    policy: HttpReconnectPolicy,
    reservation: HttpReconnectReservation,
    deadline_ns: u64,
    clock: u64,
    index: usize,
    not_before_ns: u64,
    camera: Option<HttpCamera>,
    framing: DecodeBudget<'static>,
    totals: HttpReconnectTotals,
    handoff: Option<HttpReconnectHandoff>,
    awaiting: Option<HttpReconnectReceipt>,
    stopped: bool,
    failure: Option<HttpReconnectError>,
}
impl fmt::Debug for HttpReconnect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpReconnect")
            .field("reservation", &self.reservation)
            .field("totals", &self.totals())
            .field("awaiting", &self.awaiting)
            .field("stopped", &self.stopped)
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}
impl HttpReconnect {
    /// Validate the entire frozen plan without network or filesystem I/O.
    /// Every slot names the same exact endpoint/source and a strictly increasing generation.
    /// A live `HttpCameraAuthority` must still authorize every actual network/parse operation.
    pub fn new(
        slots: Vec<HttpReconnectSlot>,
        policy: HttpReconnectPolicy,
        now_ns: u64,
        deadline_ns: u64,
    ) -> Result<Self, HttpReconnectError> {
        if slots.is_empty()
            || slots.len() > MAX_RECONNECT_CONNECTIONS
            || now_ns >= deadline_ns
            || policy.initial_backoff_ns == 0
            || policy.initial_backoff_ns > policy.maximum_backoff_ns
            || policy.maximum_backoff_ns > 60_000_000_000
            || policy.framing_work == 0
        {
            return Err(HttpReconnectError::Configuration);
        }
        let mut reservation = HttpReconnectReservation {
            connections: slots.len() as u32,
            framing_work: policy.framing_work,
            ..HttpReconnectReservation::default()
        };
        let first = &slots[0].route;
        let mut previous_generation = None;
        for slot in &slots {
            let route = &slot.route;
            if route.peer() != first.peer()
                || route.authority() != first.authority()
                || route.target() != first.target()
                || route.security() != first.security()
                || route.basis().source != first.basis().source
                || previous_generation.is_some_and(|g| route.basis().generation <= g)
            {
                return Err(HttpReconnectError::Configuration);
            }
            validate_slot(slot)?;
            previous_generation = Some(route.basis().generation);
            let l = slot.limits;
            add_reserved(&mut reservation.wire_bytes, l.http.wire_bytes)?;
            add_reserved(&mut reservation.entity_bytes, l.http.entity_bytes)?;
            add_reserved(&mut reservation.chunks, l.http.chunks)?;
            add_reserved(&mut reservation.io_calls, l.io_calls)?;
            add_reserved(&mut reservation.frames, l.frames)?;
            add_reserved(&mut reservation.connect_timeout_ns, l.connect_timeout_ns)?;
        }
        Ok(Self {
            slots,
            policy,
            reservation,
            deadline_ns,
            clock: now_ns,
            index: 0,
            not_before_ns: now_ns,
            camera: None,
            framing: DecodeBudget::new(policy.framing_work),
            totals: HttpReconnectTotals::default(),
            handoff: None,
            awaiting: None,
            stopped: false,
            failure: None,
        })
    }

    /// Immutable whole-plan ceilings, including every slot rather than just the current one.
    pub fn reservation(&self) -> HttpReconnectReservation {
        self.reservation
    }
    /// Actual aggregate work including the live connection; no counters reset at a reconnect.
    pub fn totals(&self) -> HttpReconnectTotals {
        let mut totals = self.totals;
        if let Some(camera) = &self.camera {
            add_totals(&mut totals, camera.totals());
        }
        totals.framing_work = self.framing.used();
        totals
    }
    /// Read-only live source, including pending raw input after a late authority denial.
    pub fn camera(&self) -> Option<&HttpCamera> {
        self.camera.as_ref()
    }
    /// Original unacknowledged/incompletely parsed input, never concatenated across generations.
    pub fn pending_wire(&self) -> Option<&HttpWireRead> {
        self.camera.as_ref().and_then(HttpCamera::pending_wire)
    }
    /// Exact boundary that must be acknowledged; remains available after its source is transferred.
    pub fn pending_handoff(&self) -> Option<HttpReconnectReceipt> {
        self.awaiting
    }
    /// Transfer all ended-source ownership without I/O. This alone does not release the barrier.
    pub fn take_handoff(&mut self) -> Option<HttpReconnectHandoff> {
        self.handoff.take()
    }
    /// Accept responsibility for the exact already-transferred handoff. No storage proof is implied.
    /// The next `step` independently checks live authority and the absolute deadline before I/O.
    pub fn acknowledge_handoff(
        &mut self,
        receipt: HttpReconnectReceipt,
    ) -> Result<(), HttpReconnectError> {
        if self.handoff.is_some() || self.awaiting != Some(receipt) {
            return Err(HttpReconnectError::ReceiptMismatch);
        }
        self.awaiting = None;
        if let Some(not_before_ns) = receipt.retry_at_ns {
            self.index += 1;
            self.not_before_ns = not_before_ns;
        } else {
            self.stopped = true;
        }
        Ok(())
    }
    /// Original wire-acknowledgement contract; retain the exact read before accepting responsibility.
    pub fn acknowledge_wire(
        &mut self,
        receipt: HttpWireReceipt,
        now_ns: u64,
        authority: &dyn HttpCameraAuthority,
    ) -> Result<(), HttpReconnectError> {
        self.check_clock(now_ns)?;
        self.camera
            .as_mut()
            .ok_or(HttpReconnectError::NotActive)?
            .acknowledge_wire(receipt, now_ns, authority)
            .map_err(HttpReconnectError::Source)
    }
    /// Transfer one complete source-mapped frame. A new connection always has a distinct basis.
    pub fn take_frame(
        &mut self,
        ordinal: u64,
        encoded_sha256: [u8; 32],
        now_ns: u64,
        authority: &dyn HttpCameraAuthority,
    ) -> Result<HttpJpegFrame, HttpReconnectError> {
        self.check_clock(now_ns)?;
        self.camera
            .as_mut()
            .ok_or(HttpReconnectError::NotActive)?
            .take_frame(ordinal, encoded_sha256, now_ns, authority)
            .map_err(HttpReconnectError::Source)
    }
    /// At most one connect attempt OR one existing camera step. No internal retry/sleep loop.
    pub fn step(
        &mut self,
        now_ns: u64,
        authority: &dyn HttpCameraAuthority,
    ) -> Result<HttpReconnectStep, HttpReconnectError> {
        self.check_clock(now_ns)?;
        if let Some(receipt) = self.awaiting {
            return Ok(HttpReconnectStep::HandoffReady(receipt));
        }
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.stopped {
            return Ok(HttpReconnectStep::Stopped);
        }
        // The native owner performs its own checks before AND after every syscall and parse.
        // Backoff/connect preparation also rechecks live authority, including while idle.
        let route = &self.slots[self.index].route;
        let admitted = if now_ns >= self.deadline_ns {
            Err(HttpCameraError::Deadline)
        } else {
            authority
                .checkpoint(route, HttpCameraOperation::Poll, now_ns, self.deadline_ns)
                .map_err(HttpCameraError::Denied)
        };
        if let Err(error) = admitted {
            if self.camera.is_some() {
                return Ok(self.end_source(HttpReconnectOutcome::SourceFailed(error), now_ns));
            }
            let error = HttpReconnectError::Source(error);
            self.failure = Some(error);
            return Err(error);
        }
        if let Some(camera) = &mut self.camera {
            return match camera.step(now_ns, authority, &mut self.framing) {
                Ok(HttpCameraStep::Complete) => {
                    Ok(self.end_source(HttpReconnectOutcome::Complete, now_ns))
                }
                Ok(step) => Ok(HttpReconnectStep::Source(step)),
                Err(HttpCameraError::ClockReversed) => Err(HttpReconnectError::ClockReversed),
                Err(error) => {
                    Ok(self.end_source(HttpReconnectOutcome::SourceFailed(error), now_ns))
                }
            };
        }
        if now_ns < self.not_before_ns {
            return Ok(HttpReconnectStep::Waiting {
                not_before_ns: self.not_before_ns,
            });
        }
        let slot = &self.slots[self.index];
        self.totals.slots_started += 1;
        match HttpCamera::connect(
            slot.route.clone(),
            slot.limits,
            now_ns,
            self.deadline_ns,
            authority,
        ) {
            Ok(camera) => {
                self.totals.connect_attempts += 1;
                let basis = camera.route().basis();
                self.camera = Some(camera);
                Ok(HttpReconnectStep::Connected(basis))
            }
            Err(failure) => {
                self.totals.connect_attempts += u32::from(failure.attempted);
                Ok(self.end_source(
                    HttpReconnectOutcome::ConnectFailed {
                        reason: failure.reason,
                        attempted: failure.attempted,
                    },
                    now_ns,
                ))
            }
        }
    }
    fn check_clock(&mut self, now_ns: u64) -> Result<(), HttpReconnectError> {
        if now_ns < self.clock {
            return Err(HttpReconnectError::ClockReversed);
        }
        self.clock = now_ns;
        Ok(())
    }
    fn end_source(&mut self, outcome: HttpReconnectOutcome, now_ns: u64) -> HttpReconnectStep {
        let source = self.camera.take().map(HttpCamera::retire);
        let totals = source
            .as_ref()
            .map_or(HttpCameraTotals::default(), |s| s.totals);
        add_totals(&mut self.totals, totals);
        if outcome == HttpReconnectOutcome::Complete {
            self.totals.completed_connections += 1;
        }
        let retry = match outcome {
            HttpReconnectOutcome::Complete => self.policy.reconnect_after_complete,
            HttpReconnectOutcome::ConnectFailed { reason, .. }
            | HttpReconnectOutcome::SourceFailed(reason) => retryable(reason),
        };
        let mut retry_at_ns = None;
        let stop = if !retry {
            Some(if outcome == HttpReconnectOutcome::Complete {
                HttpReconnectStop::Complete
            } else {
                HttpReconnectStop::NotRetryable
            })
        } else if self.index + 1 == self.slots.len() {
            Some(HttpReconnectStop::ConnectionsExhausted)
        } else if self.framing.used() >= self.policy.framing_work {
            Some(HttpReconnectStop::FramingWorkExhausted)
        } else {
            match now_ns.checked_add(backoff(self.policy, self.index)) {
                Some(at) if at < self.deadline_ns => {
                    retry_at_ns = Some(at);
                    None
                }
                _ => Some(HttpReconnectStop::Deadline),
            }
        };
        let next_source = retry_at_ns.map(|_| self.slots[self.index + 1].route.basis());
        let receipt = HttpReconnectReceipt {
            connection: self.index as u32 + 1,
            source: self.slots[self.index].route.basis(),
            outcome,
            totals,
            admitted_ns: now_ns,
            next_source,
            retry_at_ns,
            stop,
        };
        self.handoff = Some(HttpReconnectHandoff { receipt, source });
        self.awaiting = Some(receipt);
        HttpReconnectStep::HandoffReady(receipt)
    }
    /// Close the live socket and transfer all still-owned source without I/O, allocation or retry.
    pub fn retire(mut self) -> HttpReconnectRetirement {
        let totals = self.totals();
        HttpReconnectRetirement {
            totals,
            reservation: self.reservation,
            active: self.camera.take().map(HttpCamera::retire),
            handoff: self.handoff.take(),
            awaiting: self.awaiting,
            failure: self.failure,
        }
    }
}

/// Explicit final handoff; earlier accepted handoffs remain owned by their original recipients.
#[derive(Debug)]
#[must_use]
pub struct HttpReconnectRetirement {
    /// Actual aggregate work up to retirement.
    pub totals: HttpReconnectTotals,
    /// Original aggregate ceilings, not a claim that all reservations were consumed.
    pub reservation: HttpReconnectReservation,
    /// Current connection's complete unfinished-source ownership, when one was active.
    pub active: Option<HttpCameraRetirement>,
    /// Ended source not yet transferred through take_handoff.
    pub handoff: Option<HttpReconnectHandoff>,
    /// Unacknowledged boundary; may name an already-transferred handoff.
    pub awaiting: Option<HttpReconnectReceipt>,
    /// Supervisor refusal, distinct from any original source failure in its handoff.
    pub failure: Option<HttpReconnectError>,
}

fn add_reserved(total: &mut u64, amount: u64) -> Result<(), HttpReconnectError> {
    *total = total
        .checked_add(amount)
        .ok_or(HttpReconnectError::Configuration)?;
    Ok(())
}
fn validate_slot(slot: &HttpReconnectSlot) -> Result<(), HttpReconnectError> {
    let l = slot.limits;
    // Same pre-I/O bounds as HttpCamera; HttpResponseStream owns HTTP-limit validation.
    if !(1..=65536).contains(&l.read_bytes)
        || l.io_calls == 0
        || !(1..=1_000_000).contains(&l.frames)
        || !(1..=65536).contains(&l.source_runs)
        || !(1..=60_000_000_000).contains(&l.connect_timeout_ns)
        || !(4..=16 * 1024 * 1024).contains(&l.multipart.frame_bytes)
        || !(4..=16384).contains(&l.multipart.header_bytes)
        || l.multipart.wrapper_bytes > 65536
    {
        return Err(HttpReconnectError::Configuration);
    }
    HttpResponseStream::new(slot.route.basis(), l.http)
        .map(|_| ())
        .map_err(|_| HttpReconnectError::Configuration)
}
fn add_totals(total: &mut HttpReconnectTotals, source: HttpCameraTotals) {
    // Each owner is counted exactly once. Checked reservations bound all input-derived counters;
    // request bytes are bounded by HttpCameraRoute and the hard thirty-two-slot plan ceiling.
    total.sent_bytes += source.sent_bytes;
    total.received_bytes += source.received_bytes;
    total.read_calls += source.read_calls;
    total.write_calls += source.write_calls;
    total.frames += source.frames;
}
fn backoff(policy: HttpReconnectPolicy, ordinal: usize) -> u64 {
    policy
        .initial_backoff_ns
        .saturating_mul(1_u64 << ordinal.min(MAX_RECONNECT_CONNECTIONS - 1))
        .min(policy.maximum_backoff_ns)
}
fn retryable(error: HttpCameraError) -> bool {
    match error {
        HttpCameraError::Io { operation, kind } => {
            matches!(
                operation,
                HttpCameraOperation::Connect
                    | HttpCameraOperation::Read
                    | HttpCameraOperation::Write
            ) && matches!(
                kind,
                ErrorKind::ConnectionRefused
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::BrokenPipe
                    | ErrorKind::TimedOut
                    | ErrorKind::UnexpectedEof
                    | ErrorKind::NotConnected
            )
        }
        HttpCameraError::WriteZero | HttpCameraError::Http(HttpError::Truncated) => true,
        HttpCameraError::Multipart(HttpMjpegError::Multipart(MultipartError::Truncated)) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests;
