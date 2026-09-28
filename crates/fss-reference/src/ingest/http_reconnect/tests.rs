#![forbid(unsafe_code)]

use super::*;
use super::super::http_camera::{HttpCameraDenial, HttpCameraSecurity};
use std::cell::Cell;
use std::net::SocketAddr;

fn policy() -> HttpReconnectPolicy {
    HttpReconnectPolicy {
        initial_backoff_ns: 10,
        maximum_backoff_ns: 80,
        reconnect_after_complete: false,
        framing_work: 1_000_000,
    }
}
fn slot(generation: u64) -> HttpReconnectSlot {
    HttpReconnectSlot {
        route: HttpCameraRoute::new(
            StreamBasis { source: [7; 32], generation },
            SocketAddr::from(([127, 0, 0, 1], 12345)),
            "camera.invalid",
            "/video",
            HttpCameraSecurity::OwnerApprovedPlaintext,
        )
        .expect("valid test route"),
        limits: HttpCameraLimits::default(),
    }
}
fn owner() -> HttpReconnect {
    HttpReconnect::new(vec![slot(3), slot(8), slot(21)], policy(), 0, 1_000)
        .expect("valid frozen plan")
}
fn failed_connect(owner: &mut HttpReconnect, now: u64) -> HttpReconnectReceipt {
    owner.totals.slots_started += 1;
    owner.totals.connect_attempts += 1;
    let HttpReconnectStep::HandoffReady(receipt) = owner.end_source(
        HttpReconnectOutcome::ConnectFailed {
            reason: HttpCameraError::Io {
                operation: HttpCameraOperation::Connect,
                kind: ErrorKind::ConnectionRefused,
            },
            attempted: true,
        },
        now,
    ) else {
        panic!("a failed slot must produce an exact handoff");
    };
    receipt
}
struct Deny {
    calls: Cell<usize>,
}
impl HttpCameraAuthority for Deny {
    fn checkpoint(
        &self,
        _: &HttpCameraRoute,
        _: HttpCameraOperation,
        _: u64,
        _: u64,
    ) -> Result<(), HttpCameraDenial> {
        self.calls.set(self.calls.get() + 1);
        Err(HttpCameraDenial::Revoked)
    }
}

#[test]
fn whole_plan_reservations_are_checked_sums_not_one_connection_limits() {
    let single = slot(1).limits;
    let run = owner();
    let r = run.reservation();
    assert_eq!(r.connections, 3);
    assert_eq!(r.wire_bytes, 3 * single.http.wire_bytes);
    assert_eq!(r.entity_bytes, 3 * single.http.entity_bytes);
    assert_eq!(r.chunks, 3 * single.http.chunks);
    assert_eq!(r.io_calls, 3 * single.io_calls);
    assert_eq!(r.frames, 3 * single.frames);
    assert_eq!(r.connect_timeout_ns, 3 * single.connect_timeout_ns);
    assert_eq!(r.framing_work, policy().framing_work);
    assert_eq!(run.totals(), HttpReconnectTotals::default());
}

#[test]
fn generation_resets_duplicates_and_endpoint_changes_fail_before_io() {
    for generations in [[3, 3], [8, 3]] {
        assert!(matches!(
            HttpReconnect::new(generations.into_iter().map(slot).collect(), policy(), 0, 100),
            Err(HttpReconnectError::Configuration)
        ));
    }
    let mut changed = slot(8);
    changed.route = HttpCameraRoute::new(
        changed.route.basis(), changed.route.peer(), "other.invalid", "/video",
        HttpCameraSecurity::OwnerApprovedPlaintext,
    ).expect("valid but independently different route");
    assert!(matches!(
        HttpReconnect::new(vec![slot(3), changed], policy(), 0, 100),
        Err(HttpReconnectError::Configuration)
    ));
}

#[test]
fn invalid_later_slot_is_not_deferred_until_after_a_connection() {
    let mut later = slot(8);
    later.limits.read_bytes = 0;
    assert!(matches!(
        HttpReconnect::new(vec![slot(3), later], policy(), 0, 100),
        Err(HttpReconnectError::Configuration)
    ));
}

#[test]
fn empty_oversized_overflowing_and_invalid_backoff_plans_are_refused() {
    let too_many = (1..=MAX_RECONNECT_CONNECTIONS as u64 + 1).map(slot).collect();
    for slots in [Vec::new(), too_many] {
        assert!(HttpReconnect::new(slots, policy(), 0, 100).is_err());
    }
    let mut huge = slot(1);
    huge.limits.io_calls = u64::MAX;
    assert!(HttpReconnect::new(vec![huge, slot(2)], policy(), 0, 100).is_err());
    let bad = HttpReconnectPolicy { initial_backoff_ns: 81, ..policy() };
    assert!(HttpReconnect::new(vec![slot(1)], bad, 0, 100).is_err());
    assert!(HttpReconnect::new(vec![slot(1)], policy(), 100, 100).is_err());
}

#[test]
fn exact_handoff_must_be_transferred_then_acknowledged_before_retry() {
    let mut run = owner();
    let receipt = failed_connect(&mut run, 1);
    assert_eq!(receipt.source.generation, 3);
    assert_eq!(receipt.next_source.expect("reserved next source").generation, 8);
    assert_eq!(receipt.retry_at_ns, Some(11));
    assert_eq!(run.acknowledge_handoff(receipt), Err(HttpReconnectError::ReceiptMismatch));
    let deny = Deny { calls: Cell::new(0) };
    for now in [2, 11, 99] {
        assert_eq!(run.step(now, &deny), Ok(HttpReconnectStep::HandoffReady(receipt)));
    }
    assert_eq!(deny.calls.get(), 0, "a pending handoff must perform no I/O/admission");
    let handoff = run.take_handoff().expect("owned handoff");
    assert_eq!(handoff.receipt(), receipt);
    assert!(handoff.source.is_none());
    assert!(run.take_handoff().is_none(), "source ownership transfers only once");
    let mut stale = receipt;
    stale.source.generation += 1;
    assert_eq!(run.acknowledge_handoff(stale), Err(HttpReconnectError::ReceiptMismatch));
    run.acknowledge_handoff(receipt).expect("accept exact transferred source");
    assert_eq!(run.index, 1);
    assert_eq!(run.acknowledge_handoff(receipt), Err(HttpReconnectError::ReceiptMismatch));
    assert!(matches!(run.step(100, &deny), Err(HttpReconnectError::Source(
        HttpCameraError::Denied(HttpCameraDenial::Revoked)
    ))));
    assert_eq!(run.totals().connect_attempts, 1, "revocation must block the next TCP attempt");
}

#[test]
fn all_reserved_slots_are_consumed_once_and_never_recycled() {
    let mut run = owner();
    for (index, now) in [1, 20, 60].into_iter().enumerate() {
        let receipt = failed_connect(&mut run, now);
        assert_eq!(receipt.connection, index as u32 + 1);
        assert_eq!(receipt.stop, (index == 2).then_some(HttpReconnectStop::ConnectionsExhausted));
        let handoff = run.take_handoff().expect("handoff");
        run.acknowledge_handoff(handoff.receipt()).expect("accept");
    }
    let deny = Deny { calls: Cell::new(0) };
    assert_eq!(run.step(100, &deny), Ok(HttpReconnectStep::Stopped));
    assert_eq!(deny.calls.get(), 0);
    assert_eq!(run.totals().slots_started, 3);
    assert_eq!(run.totals().connect_attempts, 3);
}

#[test]
fn retry_policy_excludes_permissions_protocol_errors_and_resource_failures() {
    for error in [
        HttpCameraError::Configuration,
        HttpCameraError::Deadline,
        HttpCameraError::Denied(HttpCameraDenial::Cancelled),
        HttpCameraError::Denied(HttpCameraDenial::Unauthorized),
        HttpCameraError::Denied(HttpCameraDenial::Revoked),
        HttpCameraError::Denied(HttpCameraDenial::Budget),
        HttpCameraError::NetworkLimit,
        HttpCameraError::FrameLimit,
        HttpCameraError::Allocation,
        HttpCameraError::PeerMismatch,
        HttpCameraError::Http(HttpError::Malformed),
        HttpCameraError::Http(HttpError::Status(401)),
        HttpCameraError::Http(HttpError::Status(503)),
        HttpCameraError::Multipart(HttpMjpegError::Multipart(MultipartError::Malformed)),
        HttpCameraError::Io { operation: HttpCameraOperation::Configure, kind: ErrorKind::TimedOut },
        HttpCameraError::Io { operation: HttpCameraOperation::Read, kind: ErrorKind::PermissionDenied },
    ] {
        assert!(!retryable(error), "must fail closed: {error:?}");
        let mut run = owner();
        run.end_source(HttpReconnectOutcome::SourceFailed(error), 1);
        let receipt = run.pending_handoff().expect("typed boundary");
        assert_eq!(receipt.outcome, HttpReconnectOutcome::SourceFailed(error));
        assert_eq!(receipt.stop, Some(HttpReconnectStop::NotRetryable));
        assert_eq!(receipt.next_source, None);
    }
    assert!(retryable(HttpCameraError::Http(HttpError::Truncated)));
    assert!(retryable(HttpCameraError::Multipart(
        HttpMjpegError::Multipart(MultipartError::Truncated)
    )));
}

#[test]
fn completion_is_terminal_unless_explicitly_enabled_and_never_changes_its_outcome() {
    let mut run = owner();
    run.end_source(HttpReconnectOutcome::Complete, 1);
    let receipt = run.pending_handoff().expect("completion boundary");
    assert_eq!(receipt.stop, Some(HttpReconnectStop::Complete));
    let mut run = HttpReconnect::new(
        vec![slot(1), slot(2)],
        HttpReconnectPolicy { reconnect_after_complete: true, ..policy() },
        0, 100,
    ).expect("explicit continuous reacquisition");
    run.end_source(HttpReconnectOutcome::Complete, 1);
    let receipt = run.pending_handoff().expect("completion boundary");
    assert_eq!(receipt.outcome, HttpReconnectOutcome::Complete);
    assert_eq!(receipt.stop, None);
    assert_eq!(receipt.next_source.expect("new generation").generation, 2);
}

#[test]
fn backoff_is_capped_and_deadline_or_clock_overflow_cannot_authorize_a_retry() {
    assert_eq!((0..7).map(|n| backoff(policy(), n)).collect::<Vec<_>>(),
               vec![10, 20, 40, 80, 80, 80, 80]);
    let mut run = HttpReconnect::new(vec![slot(1), slot(2)], policy(), 0, 11).expect("plan");
    assert_eq!(failed_connect(&mut run, 1).stop, Some(HttpReconnectStop::Deadline));
    let mut run = HttpReconnect::new(
        vec![slot(1), slot(2)], policy(), u64::MAX - 5, u64::MAX,
    ).expect("valid near clock ceiling");
    assert_eq!(failed_connect(&mut run, u64::MAX - 4).stop, Some(HttpReconnectStop::Deadline));
}

#[test]
fn admission_clock_cannot_regress_and_retirement_preserves_unaccepted_handoff() {
    let mut run = owner();
    run.check_clock(5).expect("advance");
    let deny = Deny { calls: Cell::new(0) };
    assert_eq!(run.step(4, &deny), Err(HttpReconnectError::ClockReversed));
    assert_eq!(deny.calls.get(), 0);
    let receipt = failed_connect(&mut run, 6);
    let retired = run.retire();
    assert_eq!(retired.awaiting, Some(receipt));
    assert_eq!(retired.handoff.expect("untransferred handoff").receipt(), receipt);
    assert!(retired.active.is_none());
    assert_eq!(retired.totals.slots_started, 1);
}

#[test]
fn denied_initial_admission_is_terminal_without_consuming_a_connection_slot() {
    let mut run = owner();
    let deny = Deny { calls: Cell::new(0) };
    let refused = run.step(0, &deny);
    assert!(matches!(refused, Err(HttpReconnectError::Source(HttpCameraError::Denied(_)))));
    assert_eq!(run.step(1, &deny), refused);
    assert_eq!(deny.calls.get(), 1, "terminal denial must never be automatically retried");
    assert_eq!(run.totals().slots_started, 0);
}
