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
    /// The native owner observed a fully drained successful archive and no pending control.
    /// This is successor admission, NOT a retryable error. Legacy failure reports omit it.
    SettledSuccess,
}
impl RetryReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionUnavailable => "connection_unavailable",
            Self::SourceEnded => "source_ended",
            Self::ProgressStalled => "recording_progress_stalled",
            Self::SettledSuccess => "settled_success",
        }
    }
}

#[derive(Debug)]
pub(crate) struct AttemptOutcome {
    pub(crate) result: Result<(), &'static str>,
    // The historical field name is retained for existing native/controller callers. The
    // success marker is separate from all three failure observations and must not be retried.
    pub(crate) retry: Option<RetryReason>,
    pub(crate) recovery_required: bool,
    pub(crate) durable_pictures: u64,
}
impl AttemptOutcome {
    pub(super) fn new(result: Result<(), Failure>, stats: &Statistics) -> Self {
        // An observed normal archive finish proves the native drain completed. Otherwise
        // only an attempt that never started archive work may be abandoned automatically.
        // Confirmed work pins are recovery inputs, NOT permission to start a new capture.
        // Matching positive picture counts are still observed work, even when teardown
        // leaves no window or pin hint. They require the normal archive snapshot too.
        let work_never_started = stats.pins.last_confirmed().is_none()
            && stats.collected_pictures == 0
            && stats.durable_pictures == 0
            && stats.durable_windows == 0
            && stats.unpublished_prepared_bytes == 0;
        let recovery_required = stats.pins.candidate().is_some()
            || stats.unrecorded_work_receipt.is_some()
            || stats.pending_window.is_some()
            || stats.unpublished_prepared_pictures != 0
            || stats.unpublished_prepared_bytes != 0
            || stats.pending_source_only_nals != 0
            || stats.indexed_windows != stats.durable_windows
            // Pending-work hints may already have been cleared by teardown. Picture
            // accounting must independently agree before ANY source failure can retire
            // this generation, including EOF and connection-unavailable observations.
            || stats.collected_pictures != stats.durable_pictures
            || (stats.snapshot_digest.is_none() && !work_never_started);
        // Socket retirement can transfer a queued or partly dispatched control request.
        // A normal archive drain settles media custody, not that remote request.
        // Preserve the native result and reporting; do not authorize a successor.
        let retry = if recovery_required || stats.pending_request {
            None
        } else {
            match result {
                Ok(())
                    if stats.snapshot_digest.is_some()
                        && stats.durable_pictures != 0
                        && stats.durable_pictures == stats.collected_pictures =>
                {
                    Some(RetryReason::SettledSuccess)
                }
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
            collected_pictures: 4,
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
        assert!(
            AttemptOutcome::new(Ok(()), &Statistics::default())
                .retry
                .is_none()
        );
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
    fn picture_accounting_mismatch_blocks_every_successor_path() {
        for (collected, durable) in [
            (5, 4),
            (3, 4),
            (1, 0),
            (0, 1),
            (u64::MAX, u64::MAX - 1),
            (u64::MAX - 1, u64::MAX),
        ] {
            for result in [
                Err(Failure::Shortfall),
                Err(Failure::ConnectionUnavailable),
                Err(Failure::ProgressStalled),
                Ok(()),
            ] {
                let mut stats = ended();
                stats.connection_attempted = true;
                stats.collected_pictures = collected;
                stats.durable_pictures = durable;
                let outcome = AttemptOutcome::new(result, &stats);
                assert!(
                    outcome.recovery_required,
                    "{result:?}: {collected}/{durable}"
                );
                assert!(outcome.retry.is_none(), "{result:?}: {collected}/{durable}");
                assert_eq!(outcome.result, result.map_err(Failure::code));
                assert_eq!(outcome.durable_pictures, durable);
            }
        }
    }

    #[test]
    fn accepted_pictures_without_a_snapshot_cannot_disappear_at_source_retirement() {
        for failure in [Failure::Shortfall, Failure::ConnectionUnavailable] {
            let stats = Statistics {
                input_ended: true,
                connection_attempted: true,
                collected_pictures: 1,
                ..Statistics::default()
            };
            // No pending window, work pin or unpublished-byte hint survives. The
            // accepted picture count is still enough to require explicit recovery.
            let outcome = AttemptOutcome::new(Err(failure), &stats);
            assert!(outcome.recovery_required);
            assert!(outcome.retry.is_none());
            assert_eq!(outcome.result, Err(failure.code()));
        }
    }

    #[test]
    fn balanced_positive_picture_counts_still_require_an_archive_snapshot() {
        for pictures in [1, 4, u64::MAX] {
            for result in [
                Err(Failure::Shortfall),
                Err(Failure::ConnectionUnavailable),
                Err(Failure::ProgressStalled),
                Ok(()),
            ] {
                let stats = Statistics {
                    input_ended: true,
                    connection_attempted: true,
                    collected_pictures: pictures,
                    durable_pictures: pictures,
                    ..Statistics::default()
                };
                let outcome = AttemptOutcome::new(result, &stats);
                assert!(
                    outcome.recovery_required,
                    "{result:?}: {pictures} pictures"
                );
                assert!(outcome.retry.is_none());
                assert_eq!(outcome.result, result.map_err(Failure::code));
                assert_eq!(outcome.durable_pictures, pictures);
            }
        }
    }

    #[test]
    fn empty_source_attempts_remain_retryable_without_claiming_recovery() {
        let stats = Statistics {
            input_ended: true,
            connection_attempted: true,
            ..Statistics::default()
        };
        for (failure, reason) in [
            (Failure::Shortfall, RetryReason::SourceEnded),
            (
                Failure::ConnectionUnavailable,
                RetryReason::ConnectionUnavailable,
            ),
        ] {
            let outcome = AttemptOutcome::new(Err(failure), &stats);
            assert_eq!(outcome.retry, Some(reason));
            assert!(!outcome.recovery_required);
            assert_eq!(outcome.result, Err(failure.code()));
        }
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
        assert!(
            AttemptOutcome::new(Err(Failure::ProgressStalled), &stats)
                .retry
                .is_none()
        );
        stats = ended();
        stats.collected_pictures = 3;
        let outcome = AttemptOutcome::new(Err(Failure::ProgressStalled), &stats);
        assert!(outcome.retry.is_none());
        assert!(outcome.recovery_required);
        assert!(
            AttemptOutcome::new(Err(Failure::ProgressStalled), &Statistics::default())
                .retry
                .is_none()
        );
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

    #[test]
    fn pending_control_blocks_each_retry_reason_without_claiming_storage_damage() {
        for failure in [
            Failure::ConnectionUnavailable,
            Failure::Shortfall,
            Failure::ProgressStalled,
        ] {
            let mut stats = ended();
            stats.collected_pictures = stats.durable_pictures;
            stats.connection_attempted = true;
            stats.remote_session_may_exist = true;
            assert!(AttemptOutcome::new(Err(failure), &stats).retry.is_some());
            stats.pending_request = true;
            let outcome = AttemptOutcome::new(Err(failure), &stats);
            assert!(outcome.retry.is_none(), "{failure:?}");
            assert!(!outcome.recovery_required);
            assert_eq!(outcome.result, Err(failure.code()));
            assert_eq!(outcome.durable_pictures, stats.durable_pictures);
        }
    }

    #[test]
    fn settled_success_is_not_a_failure_retry_or_a_source_eof_claim() {
        let mut stats = ended();
        stats.input_ended = false;
        stats.collected_pictures = stats.durable_pictures;
        let outcome = AttemptOutcome::new(Ok(()), &stats);
        assert_eq!(outcome.result, Ok(()));
        assert_eq!(outcome.retry, Some(RetryReason::SettledSuccess));
        assert!(!outcome.recovery_required);
        assert!(!stats.input_ended);
    }

    #[test]
    fn completed_archive_with_pending_control_cannot_admit_a_successor() {
        let mut stats = ended();
        stats.collected_pictures = stats.durable_pictures;
        stats.pending_request = true;
        let outcome = AttemptOutcome::new(Ok(()), &stats);
        assert_eq!(outcome.result, Ok(())); // Media completion remains the native observation.
        assert!(outcome.retry.is_none());
        assert!(!outcome.recovery_required); // Remote control is not damaged archive custody.
        assert_eq!(outcome.durable_pictures, stats.durable_pictures);
    }

    #[test]
    fn successful_session_requires_all_existing_storage_barriers_before_continuation() {
        for condition in 0..8 {
            let mut stats = ended();
            stats.collected_pictures = stats.durable_pictures;
            match condition {
                0 => stats.pending_window = Some((ContentDigest::sha256(b"pending"), 1)),
                1 => stats.unrecorded_work_receipt = Some("receipt".into()),
                2 => stats.unpublished_prepared_pictures = 1,
                3 => stats.unpublished_prepared_bytes = 1,
                4 => stats.indexed_windows = 0,
                5 => stats.pending_source_only_nals = 1,
                6 => stats.snapshot_digest = None,
                _ => stats.collected_pictures += 1,
            }
            let outcome = AttemptOutcome::new(Ok(()), &stats);
            assert_eq!(outcome.result, Ok(()));
            assert!(outcome.retry.is_none(), "unsettled condition {condition}");
            assert!(outcome.recovery_required, "unsettled condition {condition}");
        }
    }

    #[test]
    fn nominal_success_without_an_observed_archive_finish_cannot_admit_a_successor() {
        let outcome = AttemptOutcome::new(Ok(()), &Statistics::default());
        assert_eq!(outcome.result, Ok(()));
        assert!(outcome.retry.is_none());
    }

    #[test]
    fn empty_finished_archive_is_not_a_successful_capture_session() {
        let stats = Statistics {
            snapshot_digest: Some(ContentDigest::sha256(b"empty finished archive")),
            ..Statistics::default()
        };
        let outcome = AttemptOutcome::new(Ok(()), &stats);
        assert_eq!(outcome.result, Ok(()));
        assert!(!outcome.recovery_required);
        assert!(outcome.retry.is_none());
    }
}
