#![forbid(unsafe_code)]
//! Preserve a verified HEVC prefix after a terminal, typed socket read failure.
//! This finishes existing custody; it neither recaptures data nor admits a successor.

use std::io::ErrorKind;

use super::*;
use crate::rtsp::tcp::TcpError;

/// Original read failure and the exact source ownership released by prefix sealing.
/// Neither preparation nor these retained bytes prove a durable publication.
#[derive(Debug)]
pub struct HevcReadInterruption {
    /// Native error kind from a Read operation, never inferred from an error string.
    pub kind: ErrorKind,
    /// Ordinary replay-verified seal result. Its released datagrams remain owned here
    /// until terminal transfer, including if publication or its acknowledgement fails.
    pub seal: HevcCollectionSeal,
}

pub(super) struct InterruptedCapture {
    pub(super) recording: Option<SelectedHevcRecordingRetirement>,
    pub(super) receipt: HevcReadInterruption,
    pub(super) drained: bool,
}

impl JournaledLiveHevcArchive<'_, '_> {
    /// Original acquisition interruption while its verified prefix drains.
    /// Callers must drive storage only, preserve the normal publication receipts,
    /// and then accept the original terminal failure. This is not successful capture,
    /// source EOF, camera-health evidence, or permission to reconnect.
    pub fn interruption(&self) -> Option<&HevcReadInterruption> {
        self.interrupted.as_ref().map(|state| &state.receipt)
    }

    pub(super) fn preserve_read_failure(
        &mut self,
        failure: LiveHevcFailure,
        now: u64,
    ) -> Result<LiveHevcArchiveStep, LiveHevcArchiveFailure> {
        let Some(kind) = abrupt_read_kind(&failure.reason) else {
            return Err(self.network_failure(failure));
        };
        // A native retirement is mandatory: a retry-safe refusal must not be used
        // to manufacture socket closure. Held events, untimed pictures, existing
        // prepared work and unfinished publication retain their original paths.
        if failure.retirement.is_none()
            || self.interrupted.is_some()
            || self.completion.is_some()
            || !self.ready
            || self.writer.as_ref().is_none_or(|writer| writer.pending().is_some())
            || self.capture.as_ref().is_none_or(|capture| {
                capture.busy() || capture.collector().retained_samples() == 0
            })
        {
            return Err(self.network_failure(failure));
        }
        let seal = match self.capture.as_mut().map(|capture| capture.seal(now)) {
            Some(Ok(seal)) => seal,
            // Sealing is transactional on refusal. In particular a missing real
            // HEVC boundary, an unsafe shared-packet cut, or an expired collector
            // cannot be replaced with a guessed sample or a shortened datagram.
            _ => return Err(self.network_failure(failure)),
        };
        let mut recording = self.retire_input(failure.retirement.map(|r| *r), None, None);
        let window = recording
            .as_mut()
            .and_then(|retired| retired.capture.as_mut())
            .and_then(|capture| capture.collection.ready.take());
        let window_ready = seal.window_ready;
        // Save every original before offering or finishing the writer. A second
        // storage failure must retain the initial read cause, source remainder,
        // seal releases, and whichever exact window/work pin was not acknowledged.
        self.interrupted = Some(InterruptedCapture {
            recording,
            receipt: HevcReadInterruption { kind, seal },
            drained: false,
        });
        if !window_ready {
            return Err(self.fatal(LiveHevcArchiveError::Invariant, None, window));
        }
        let Some(window) = window else {
            return Err(self.fatal(LiveHevcArchiveError::Invariant, None, None));
        };
        let Some(writer) = self.writer.as_mut() else {
            return Err(self.fatal(LiveHevcArchiveError::Invariant, None, Some(window)));
        };
        let admission = match writer.offer(window, self.max_window_bytes, now) {
            Ok(admission) => admission,
            Err(refusal) => {
                return Err(self.fatal(
                    LiveHevcArchiveError::Archive(*refusal.reason),
                    None,
                    Some(*refusal.recording),
                ));
            }
        };
        // The SAME writer and pin journal own the final prefix; no new namespace,
        // work budget, deadline, or storage pause allowance is allocated.
        if let Err(error) = writer.finish(now) {
            return Err(self.fatal(LiveHevcArchiveError::Pins(error), None, None));
        }
        self.pause(now);
        Ok(LiveHevcArchiveStep::WindowAccepted(admission))
    }

    pub(super) fn finish_archive(
        &mut self,
        archive: ArchiveWriteProgress,
    ) -> Result<LiveHevcArchiveStep, LiveHevcArchiveFailure> {
        if !matches!(&archive, ArchiveWriteProgress::Finished { .. }) {
            return Err(self.fatal(LiveHevcArchiveError::Invariant, None, None));
        }
        if let Some(state) = &mut self.interrupted {
            if state.drained {
                return Err(self.fatal(LiveHevcArchiveError::Invariant, None, None));
            }
            state.drained = true;
            // Emit the native archive snapshot ONCE, without inventing a capture
            // completion cause. The original acquisition failure follows next.
            return Ok(LiveHevcArchiveStep::Archive(Box::new(
                JournaledArchiveProgress::Archive(archive),
            )));
        }
        let Some(cause) = self.completion else {
            return Err(self.fatal(LiveHevcArchiveError::Invariant, None, None));
        };
        self.finished = true;
        Ok(LiveHevcArchiveStep::Finished { archive, cause })
    }

    pub(super) fn finish_interruption(&mut self) -> Option<LiveHevcArchiveFailure> {
        let kind = self.interrupted.as_ref().filter(|state| state.drained)?.receipt.kind;
        Some(self.fatal(
            LiveHevcArchiveError::Network(LiveHevcError::Transport(TcpError::Io {
                operation: TcpOperation::Read,
                kind,
            })),
            None,
            None,
        ))
    }
}

fn abrupt_read_kind(reason: &LiveHevcError) -> Option<ErrorKind> {
    match reason {
        LiveHevcError::Transport(TcpError::Io {
            operation: TcpOperation::Read,
            kind: kind @ (ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted
                | ErrorKind::BrokenPipe
                | ErrorKind::UnexpectedEof
                | ErrorKind::NotConnected),
        }) => Some(*kind),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preservation_requires_a_typed_abrupt_read_not_a_write_or_connect_fault() {
        for operation in [TcpOperation::Read, TcpOperation::Write, TcpOperation::Connect] {
            for kind in [
                ErrorKind::ConnectionReset, ErrorKind::ConnectionAborted,
                ErrorKind::BrokenPipe, ErrorKind::UnexpectedEof, ErrorKind::NotConnected,
                ErrorKind::WouldBlock, ErrorKind::Interrupted, ErrorKind::TimedOut,
                ErrorKind::PermissionDenied, ErrorKind::Other,
            ] {
                let error = LiveHevcError::Transport(TcpError::Io { operation, kind });
                let expected = operation == TcpOperation::Read && matches!(kind,
                    ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
                    | ErrorKind::BrokenPipe | ErrorKind::UnexpectedEof | ErrorKind::NotConnected);
                assert_eq!(abrupt_read_kind(&error), expected.then_some(kind));
            }
        }
    }

    #[test]
    fn preservation_never_reclassifies_authority_deadline_or_budget_refusals() {
        for error in [
            TcpError::Deadline, TcpError::ReadDeadline, TcpError::WorkBudget,
            TcpError::RequestBudget, TcpError::PeerMismatch, TcpError::Interrupted,
            TcpError::WriteZero, TcpError::Denied(TcpDenial::Unauthorized),
            TcpError::Denied(TcpDenial::Revoked), TcpError::Denied(TcpDenial::Cancelled),
            TcpError::Denied(TcpDenial::Budget), TcpError::Denied(TcpDenial::Deadline),
        ] {
            assert!(abrupt_read_kind(&LiveHevcError::Transport(error)).is_none());
        }
        assert!(abrupt_read_kind(&LiveHevcError::WorkBudget).is_none());
        assert!(abrupt_read_kind(&LiveHevcError::Backpressure).is_none());
    }
}
