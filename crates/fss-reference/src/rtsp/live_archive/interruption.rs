#![forbid(unsafe_code)]
//! Preserve an already-collected AVC prefix after a typed abrupt read failure.
//!
//! This is finalization of the existing, approved in-memory capture, not restart
//! recovery or reconnection. No original packet is shortened, no timing is guessed,
//! and no resource allowance is replenished. The sole existing archive writer owns
//! the verified prefix; the original acquisition failure owns everything else.

use super::*;
use crate::rtsp::live_avc::LiveAvcError;
use crate::rtsp::recording_collector::recovery::prepare_prefix as prepare_retired_prefix;
use crate::rtsp::tcp::TcpError;
use std::io::ErrorKind;

/// Deferred terminal ownership while the original writer drains one verified prefix.
/// A drained archive is deliberately not a completed acquisition.
pub(super) struct InterruptedCapture {
    pub(super) failure: LiveRecordingFailure,
    drained: bool,
}

impl LiveAvcArchive<'_> {
    /// Original acquisition failure while its verified prefix is being preserved.
    ///
    /// A runtime must stop preparing commands and drive only the existing archive.
    /// This observation is neither source EOF, successful capture, nor permission
    /// to reconnect. Normal window, catalog, and final archive receipts remain
    /// separate, followed by the original terminal failure and exact remainder.
    pub fn interruption(&self) -> Option<&LiveRecordingError> {
        self.interrupted.as_ref().map(|state| &state.failure.reason)
    }

    pub(super) fn preserve_read_failure(
        &mut self,
        error: LiveRecordingFailure,
        now: u64,
    ) -> Result<LiveArchiveStep, LiveArchiveFailure> {
        // This seam is reached only after the native recording poll has retired
        // its socket. Refusals from authorization, authentication, clocks, protocol,
        // collection, resource ceilings and request writes keep their old behavior.
        if !is_abrupt_read_failure(&error.reason)
            || self.interrupted.is_some()
            || self.completion.is_some()
            || !self.ready
        {
            return Err(self.capture_failure(error));
        }
        let prepared = error.retirement.as_deref().and_then(|retired| {
            // The network owner must have transferred its terminal state. Never
            // discard an additional ready window or relabel an untimed picture.
            if retired.connection.is_none()
                || retired.capture.collection.ready.is_some()
                || retired.capture.picture.is_some()
                || retired.capture.event.is_some()
                || retired.capture.trailing.is_some()
                || retired.unoffered_media.is_some()
                || retired.capture.collection.pending.key != self.binding.key()
            {
                return None;
            }
            let writer = self.writer.as_ref()?;
            if writer.pending().is_some() {
                return None;
            }
            let scope = writer.snapshot().namespace().scope();
            prepare_retired_prefix(
                &retired.capture.collection.pending,
                scope.recording.clone(),
                scope.time_scale,
                self.max_window_bytes,
            )
            .ok()
        });
        let Some((window, selected_packets)) = prepared else {
            // Verification/preparation was pure: return the complete original
            // retirement unchanged. A partial datagram never becomes a safe cut.
            return Err(self.capture_failure(error));
        };
        // Hold the original failure before offer so a storage refusal preserves
        // BOTH causes and every original. The closed native owner has no remaining
        // socket and contributes no second queue or terminal transfer.
        self.recording = None;
        self.interrupted = Some(InterruptedCapture {
            failure: error,
            drained: false,
        });
        let Some(writer) = self.writer.as_mut() else {
            return Err(self.fatal(LiveArchiveError::Invariant, None, Some(window)));
        };
        let admission = match writer.offer(window, self.max_window_bytes, now) {
            Ok(admission) => admission,
            Err(refusal) => {
                return Err(self.fatal(
                    LiveArchiveError::Archive(*refusal.reason),
                    None,
                    Some(*refusal.recording),
                ));
            }
        };
        // The existing writer has now accepted the immutable source-verified
        // recording. Only now relinquish the corresponding input copies. Later
        // packets and original transport/protocol uncertainty remain explicit.
        let Some(retired) = self
            .interrupted
            .as_mut()
            .and_then(|state| state.failure.retirement.as_deref_mut())
        else {
            return Err(self.fatal(LiveArchiveError::Invariant, None, None));
        };
        drop(
            retired
                .capture
                .collection
                .pending
                .sources
                .drain(..selected_packets),
        );
        retired.capture.collection.pending.pictures.clear();
        writer.finish();
        self.pause(now);
        Ok(LiveArchiveStep::WindowAccepted(admission))
    }

    /// Shared completion boundary for legacy and independently protected writers.
    pub(super) fn finish_archive(
        &mut self,
        progress: ArchiveWriteProgress,
    ) -> Result<LiveArchiveStep, LiveArchiveFailure> {
        if !matches!(&progress, ArchiveWriteProgress::Finished { .. }) {
            return Err(self.fatal(LiveArchiveError::Invariant, None, None));
        }
        if let Some(state) = &mut self.interrupted {
            if state.drained {
                return Err(self.fatal(LiveArchiveError::Invariant, None, None));
            }
            state.drained = true;
            // The exact native archive-completion witness is emitted ONCE, so
            // callers can retain its snapshot. Do not emit a successful capture
            // or synthesize OwnerStopped/InputEnded from a socket read failure.
            return Ok(LiveArchiveStep::Archive(progress));
        }
        let Some(cause) = self.completion else {
            return Err(self.fatal(LiveArchiveError::Invariant, None, None));
        };
        self.finished = true;
        Ok(LiveArchiveStep::Finished {
            archive: progress,
            cause,
        })
    }

    /// After the archive witness, transfer the original failure/remainder exactly once.
    /// No writer step, network operation, or second completion receipt occurs here.
    pub(super) fn finish_interruption(&mut self) -> Option<LiveArchiveFailure> {
        let reason = self
            .interrupted
            .as_ref()
            .filter(|state| state.drained)?
            .failure
            .reason
            .clone();
        Some(self.fatal(LiveArchiveError::Recording(Box::new(reason)), None, None))
    }
}

fn is_abrupt_read_failure(reason: &LiveRecordingError) -> bool {
    matches!(
        reason,
        LiveRecordingError::Network(LiveAvcError::Transport(TcpError::Io {
            operation: TcpOperation::Read,
            kind: ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted
                | ErrorKind::BrokenPipe
                | ErrorKind::UnexpectedEof
                | ErrorKind::NotConnected,
        }))
    )
}

#[cfg(test)]
mod classification_tests {
    use super::*;

    #[test]
    fn only_typed_abrupt_read_faults_admit_final_prefix_preservation() {
        for operation in [
            TcpOperation::Read,
            TcpOperation::Write,
            TcpOperation::Connect,
        ] {
            for kind in [
                ErrorKind::ConnectionReset,
                ErrorKind::ConnectionAborted,
                ErrorKind::BrokenPipe,
                ErrorKind::UnexpectedEof,
                ErrorKind::NotConnected,
                ErrorKind::WouldBlock,
                ErrorKind::Interrupted,
                ErrorKind::TimedOut,
                ErrorKind::PermissionDenied,
                ErrorKind::Other,
            ] {
                let reason = LiveRecordingError::Network(LiveAvcError::Transport(TcpError::Io {
                    operation,
                    kind,
                }));
                let admitted = operation == TcpOperation::Read
                    && matches!(
                        kind,
                        ErrorKind::ConnectionReset
                            | ErrorKind::ConnectionAborted
                            | ErrorKind::BrokenPipe
                            | ErrorKind::UnexpectedEof
                            | ErrorKind::NotConnected
                    );
                assert_eq!(is_abrupt_read_failure(&reason), admitted);
            }
        }
    }

    #[test]
    fn authority_expiry_and_resource_faults_do_not_admit_preservation() {
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
            let reason = LiveRecordingError::Network(LiveAvcError::Transport(error));
            assert!(!is_abrupt_read_failure(&reason));
        }
        assert!(!is_abrupt_read_failure(&LiveRecordingError::Network(
            LiveAvcError::WorkBudget
        )));
    }
}
