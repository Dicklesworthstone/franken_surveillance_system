#![forbid(unsafe_code)]
//! Typed retry admission after the single-attempt owner has closed and reported its state.

use super::{Failure, Statistics};

/// These are observations, not permission to reconnect. A separately approved finite plan
/// must still grant the next attempt, its new generation, destinations and resource budgets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetryReason {
    ConnectionUnavailable,
    SourceEnded,
    ProgressStalled,
}
impl RetryReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionUnavailable => "connection_unavailable",
            Self::SourceEnded => "source_ended",
            Self::ProgressStalled => "recording_progress_stalled",
        }
    }
}

#[derive(Debug)]
pub(crate) struct AttemptOutcome {
    pub(crate) result: Result<(), &'static str>,
    pub(crate) retry: Option<RetryReason>,
    pub(crate) recovery_required: bool,
    pub(crate) durable_pictures: u64,
}
impl AttemptOutcome {
    pub(super) fn new(result: Result<(), Failure>, stats: &Statistics) -> Self {
        // An observed normal archive finish proves the native drain completed. Otherwise
        // only an attempt that never started archive work may be abandoned automatically.
        // Confirmed work pins are recovery inputs, NOT permission to start a new capture.
        let work_never_started = stats.pins.last_confirmed().is_none()
            && stats.durable_windows == 0
            && stats.unpublished_prepared_bytes == 0;
        let recovery_required = stats.pins.candidate().is_some()
            || stats.unrecorded_work_receipt.is_some()
            || stats.pending_window.is_some()
            || stats.unpublished_prepared_pictures != 0
            || stats.unpublished_prepared_bytes != 0
            || stats.pending_source_only_nals != 0
            || stats.indexed_windows != stats.durable_windows
            || (stats.snapshot_digest.is_none() && !work_never_started);
        let retry = if recovery_required {
            None
        } else {
            match result {
                Err(Failure::ConnectionUnavailable) if stats.connection_attempted => {
                    Some(RetryReason::ConnectionUnavailable)
                }
                Err(Failure::Shortfall) if stats.input_ended => Some(RetryReason::SourceEnded),
                Err(Failure::ProgressStalled)
                    if stats.snapshot_digest.is_some()
                        && stats.durable_pictures == stats.collected_pictures =>
                {
                    Some(RetryReason::ProgressStalled)
                }
                // Authentication, cancellation, authority, codec/protocol/timing, resource,
                // output and storage failures never become transient merely because a socket
                // closed. In particular an auth challenge at EOF is not a reconnect signal.
                _ => None,
            }
        };
        Self {
            result: result.map_err(Failure::code),
            retry,
            recovery_required,
            durable_pictures: stats.durable_pictures,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_core::ContentDigest;

    fn ended() -> Statistics {
        Statistics {
            input_ended: true,
            snapshot_digest: Some(ContentDigest::sha256(b"finished native archive")),
            durable_windows: 1,
            indexed_windows: 1,
            durable_pictures: 4,
            ..Statistics::default()
        }
    }

    #[test]
    fn only_an_observed_source_end_or_typed_connect_io_is_retryable() {
        assert_eq!(
            AttemptOutcome::new(Err(Failure::Shortfall), &ended()).retry,
            Some(RetryReason::SourceEnded)
        );
        let stats = Statistics {
            connection_attempted: true,
            ..Statistics::default()
        };
        assert_eq!(
            AttemptOutcome::new(Err(Failure::ConnectionUnavailable), &stats).retry,
            Some(RetryReason::ConnectionUnavailable)
        );
        assert!(
            AttemptOutcome::new(Err(Failure::Connect), &stats)
                .retry
                .is_none()
        );
        assert!(
            AttemptOutcome::new(Err(Failure::ConnectionUnavailable), &Statistics::default())
                .retry
                .is_none()
        );
        assert!(
            AttemptOutcome::new(Err(Failure::Shortfall), &stats)
                .retry
                .is_none()
        );
        assert!(AttemptOutcome::new(Ok(()), &ended()).retry.is_none());
    }

    #[test]
    fn fatal_failures_cannot_be_reclassified_by_eof_or_finished_storage() {
        for failure in [
            Failure::Configuration,
            Failure::Approval,
            Failure::Root,
            Failure::Storage,
            Failure::Connect,
            Failure::Authentication,
            Failure::AuthenticationRefused,
            Failure::Credentials,
            Failure::Entropy,
            Failure::Protocol,
            Failure::Timing,
            Failure::Deadline,
            Failure::Authority,
            Failure::WorkBudget,
            Failure::State,
            Failure::Output,
        ] {
            let outcome = AttemptOutcome::new(Err(failure), &ended());
            assert!(outcome.retry.is_none(), "{failure:?}");
            assert!(outcome.result.is_err());
        }
    }

    #[test]
    fn every_visible_unsettled_storage_condition_blocks_reconnection() {
        for condition in 0..6 {
            let mut stats = ended();
            match condition {
                0 => stats.pending_window = Some((ContentDigest::sha256(b"pending"), 1)),
                1 => stats.unrecorded_work_receipt = Some("receipt".into()),
                2 => stats.unpublished_prepared_pictures = 1,
                3 => stats.unpublished_prepared_bytes = 1,
                4 => stats.indexed_windows = 0,
                _ => stats.pending_source_only_nals = 1,
            }
            let outcome = AttemptOutcome::new(Err(Failure::Shortfall), &stats);
            assert!(outcome.recovery_required, "condition {condition}");
            assert!(outcome.retry.is_none());
        }
        let mut stats = ended();
        stats.snapshot_digest = None;
        assert!(AttemptOutcome::new(Err(Failure::Shortfall), &stats).recovery_required);
    }

    #[test]
    fn progress_retry_requires_normal_drain_without_inventing_source_eof() {
        let mut stats = ended();
        stats.input_ended = false;
        stats.collected_pictures = stats.durable_pictures;
        let outcome = AttemptOutcome::new(Err(Failure::ProgressStalled), &stats);
        assert_eq!(outcome.retry, Some(RetryReason::ProgressStalled));
        assert!(!outcome.recovery_required);
        assert!(!stats.input_ended);
        stats.snapshot_digest = None;
        assert!(AttemptOutcome::new(Err(Failure::ProgressStalled), &stats).retry.is_none());
        stats = ended();
        assert!(AttemptOutcome::new(Err(Failure::ProgressStalled), &stats).retry.is_none());
        assert!(AttemptOutcome::new(Err(Failure::ProgressStalled), &Statistics::default()).retry.is_none());
    }

    #[test]
    fn progress_expiry_does_not_relax_any_archive_recovery_barrier() {
        for condition in 0..7 {
            let mut stats = ended();
            stats.input_ended = false;
            stats.collected_pictures = stats.durable_pictures;
            match condition {
                0 => stats.pending_window = Some((ContentDigest::sha256(b"pending"), 1)),
                1 => stats.unrecorded_work_receipt = Some("receipt".into()),
                2 => stats.unpublished_prepared_pictures = 1,
                3 => stats.unpublished_prepared_bytes = 1,
                4 => stats.indexed_windows = 0,
                5 => stats.pending_source_only_nals = 1,
                _ => stats.snapshot_digest = None,
            }
            let outcome = AttemptOutcome::new(Err(Failure::ProgressStalled), &stats);
            assert!(outcome.recovery_required, "condition {condition}");
            assert!(outcome.retry.is_none());
        }
    }
}
