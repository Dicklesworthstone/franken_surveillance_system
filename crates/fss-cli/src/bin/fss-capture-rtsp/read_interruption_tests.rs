#![forbid(unsafe_code)]
//! Admission tests: a typed acquisition fault is not proof of archive settlement.

use super::*;

fn settled_prefix() -> Statistics {
    Statistics {
        connection_attempted: true,
        collected_pictures: 2,
        durable_pictures: 2,
        durable_windows: 1,
        indexed_windows: 1,
        snapshot_digest: Some(ContentDigest::sha256(b"finished interrupted prefix")),
        ..Statistics::default()
    }
}

#[test]
fn interruption_retry_observes_only_the_five_native_abrupt_read_kinds() {
    for operation in [
        TcpOperation::Read,
        TcpOperation::Write,
        TcpOperation::Connect,
    ] {
        for kind in [
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::NotConnected,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::Interrupted,
            io::ErrorKind::TimedOut,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::InvalidData,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::Other,
        ] {
            let expected = operation == TcpOperation::Read
                && matches!(
                    kind,
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::NotConnected
                );
            assert_eq!(
                abrupt_read_failure(&TcpError::Io { operation, kind }),
                expected
            );
        }
    }
    for error in [
        TcpError::Deadline,
        TcpError::ReadDeadline,
        TcpError::Denied(TcpDenial::Unauthorized),
        TcpError::Denied(TcpDenial::Revoked),
        TcpError::Denied(TcpDenial::Cancelled),
        TcpError::Denied(TcpDenial::Budget),
        TcpError::Denied(TcpDenial::Deadline),
        TcpError::WorkBudget,
        TcpError::RequestBudget,
        TcpError::PeerMismatch,
        TcpError::Interrupted,
        TcpError::WriteZero,
    ] {
        assert!(!abrupt_read_failure(&error));
    }
}

#[test]
fn interruption_retry_preserves_the_original_source_error_and_native_report_cause() {
    let stats = settled_prefix();
    let outcome = AttemptOutcome::new(Err(Failure::ReadInterrupted), &stats);
    assert_eq!(outcome.result, Err(Failure::Protocol.code()));
    assert_eq!(Failure::ReadInterrupted.cause(), Failure::Protocol.cause());
    assert_eq!(outcome.retry, Some(RetryReason::ReadInterrupted));
    assert_eq!(outcome.durable_pictures, 2);
    assert!(!outcome.recovery_required);
    assert!(!stats.input_ended);
}

#[test]
fn interruption_retry_cannot_hide_unsettled_pictures_indexes_or_custody() {
    for condition in 0..13 {
        let mut stats = settled_prefix();
        match condition {
            0 => stats.snapshot_digest = None,
            1 => stats.collected_pictures += 1,
            2 => stats.durable_pictures += 1,
            3 => stats.indexed_windows = 0,
            4 => stats.pending_window = Some((ContentDigest::sha256(b"pending"), 1)),
            5 => stats.unrecorded_work_receipt = Some("unrecorded receipt".into()),
            6 => stats.unpublished_prepared_pictures = 1,
            7 => stats.unpublished_prepared_bytes = 1,
            8 => stats.pending_source_only_nals = 1,
            9 => stats.pending_request = true,
            10 => stats.unsealed_pictures = 1,
            11 => stats.untimed_picture_bytes = 1,
            _ => {
                stats.durable_windows = 0;
                stats.indexed_windows = 0;
            }
        }
        let outcome = AttemptOutcome::new(Err(Failure::ReadInterrupted), &stats);
        assert!(outcome.retry.is_none(), "condition {condition}");
        assert_eq!(outcome.result, Err(Failure::Protocol.code()));
        if condition < 9 {
            assert!(outcome.recovery_required, "condition {condition}");
        }
    }
}

#[test]
fn interruption_retry_refuses_empty_unconnected_or_source_ended_attempts() {
    for condition in 0..4 {
        let mut stats = settled_prefix();
        match condition {
            0 => {
                stats.collected_pictures = 0;
                stats.durable_pictures = 0;
                stats.durable_windows = 0;
                stats.indexed_windows = 0;
            }
            1 => stats.connection_attempted = false,
            2 => stats.input_ended = true,
            _ => stats = Statistics::default(),
        }
        assert!(
            AttemptOutcome::new(Err(Failure::ReadInterrupted), &stats)
                .retry
                .is_none()
        );
    }
}

#[test]
fn interruption_retry_does_not_promote_a_drained_protocol_or_security_failure() {
    for error in [
        Failure::Protocol,
        Failure::Authentication,
        Failure::AuthenticationRefused,
        Failure::Credentials,
        Failure::Entropy,
        Failure::Authority,
        Failure::Deadline,
        Failure::Timing,
        Failure::Storage,
        Failure::Output,
        Failure::WorkBudget,
        Failure::State,
        Failure::Configuration,
        Failure::Connect,
        Failure::EmptyCapture,
    ] {
        let outcome = AttemptOutcome::new(Err(error), &settled_prefix());
        assert!(outcome.retry.is_none(), "{error:?}");
        assert_eq!(outcome.result, Err(error.code()));
    }
}

#[test]
fn interruption_retry_keeps_nonpicture_transport_remainders_explicit() {
    let mut stats = settled_prefix();
    // These original omissions are not collected pictures or permission to reconstruct
    // bytes. They must remain in the terminal report after the immutable prefix settles.
    stats.unpublished_receiver_state = true;
    stats.receiver_tail = true;
    stats.unsealed_rtp_bytes = 13;
    let outcome = AttemptOutcome::new(Err(Failure::ReadInterrupted), &stats);
    assert_eq!(outcome.retry, Some(RetryReason::ReadInterrupted));
    assert!(stats.unpublished_receiver_state);
    assert!(stats.receiver_tail);
    assert_eq!(stats.unsealed_rtp_bytes, 13);
    assert_eq!(outcome.result, Err(Failure::Protocol.code()));
}
