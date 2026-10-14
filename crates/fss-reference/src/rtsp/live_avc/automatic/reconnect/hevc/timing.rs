#![forbid(unsafe_code)]
//! Process-local, single-use correlation for independently computed picture timing.
//! A ticket is not a clock witness, authority grant, or durable recording identity.

use std::fmt;
use std::sync::Arc;

use fss_packet::StreamKey;

use crate::rtsp::hevc_recording_capture::HevcPictureTimingRequest;

/// Identity of one timing request produced by one live supervision owner.
///
/// Copies refer to the same request, not additional timing admissions. Repeated
/// polls preserve the ticket; a successful timing admission consumes it. A stale
/// copy cannot bind a later picture even when timestamps and other metadata repeat.
/// The private owner identity also separates two supervisors with identical inputs.
/// This correlation is intentionally process-local and cannot serve as persistence,
/// source custody, a trusted capture clock, or permission to perform any effect.
#[must_use]
#[derive(Clone)]
pub struct HevcTimingTicket {
    owner: Arc<()>,
    ordinal: u64,
    request: HevcPictureTimingRequest,
}
impl HevcTimingTicket {
    /// Exact source generation named by the original native timing request.
    pub fn key(&self) -> StreamKey {
        self.request.key
    }

    /// One-based request position within this supervisor, never reset by reconnect.
    /// This number alone is not a ticket and is not globally unique.
    pub fn ordinal(&self) -> u64 {
        self.ordinal
    }

    /// The unchanged native picture metadata. RTP time remains untrusted source time.
    pub fn request(&self) -> HevcPictureTimingRequest {
        self.request
    }
}
impl PartialEq for HevcTimingTicket {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.owner, &other.owner)
            && self.ordinal == other.ordinal
            && self.request == other.request
    }
}
impl Eq for HevcTimingTicket {}
impl fmt::Debug for HevcTimingTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HevcTimingTicket")
            .field("ordinal", &self.ordinal)
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

/// Payload-free timing-correlation refusal, distinct from an invalid timing value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HevcTimingRefusal {
    /// No current request matches this ticket, or it belongs to another supervisor.
    /// Original native work remains available; no timing or socket operation occurred.
    StaleTicket,
    /// The native owner changed a pending request without a successful admission.
    /// This invariant failure retires the owner and preserves its original work.
    InconsistentRequest,
    /// The supervisor's request ordinal cannot advance without reuse or overflow.
    /// This invariant failure retires the owner rather than reusing a ticket.
    CounterExhausted,
}
impl fmt::Display for HevcTimingRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HEVC timing correlation refused: {self:?}")
    }
}
impl std::error::Error for HevcTimingRefusal {}

/// At most one pending ticket. No history, reset, network operation or clock lookup.
/// Arc supplies a private process-local identity without randomness or a global counter.
/// Outstanding ticket copies keep that allocation alive, preventing address-reuse aliasing.
pub(super) struct TimingTickets {
    owner: Arc<()>,
    ordinal: u64,
    pending: Option<HevcTimingTicket>,
}
impl Default for TimingTickets {
    fn default() -> Self {
        Self {
            owner: Arc::new(()),
            ordinal: 0,
            pending: None,
        }
    }
}
impl TimingTickets {
    pub(super) fn current(&self) -> Option<HevcTimingTicket> {
        self.pending.clone()
    }

    pub(super) fn observe(
        &mut self,
        key: StreamKey,
        request: HevcPictureTimingRequest,
    ) -> Result<(), HevcTimingRefusal> {
        if request.key != key {
            return Err(HevcTimingRefusal::InconsistentRequest);
        }
        if let Some(pending) = &self.pending {
            return if pending.request == request {
                Ok(())
            } else {
                Err(HevcTimingRefusal::InconsistentRequest)
            };
        }
        let ordinal = self
            .ordinal
            .checked_add(1)
            .ok_or(HevcTimingRefusal::CounterExhausted)?;
        self.pending = Some(HevcTimingTicket {
            owner: Arc::clone(&self.owner),
            ordinal,
            request,
        });
        self.ordinal = ordinal;
        Ok(())
    }

    pub(super) fn admit(&self, ticket: &HevcTimingTicket) -> Result<(), HevcTimingRefusal> {
        if self.pending.as_ref() == Some(ticket) {
            Ok(())
        } else {
            Err(HevcTimingRefusal::StaleTicket)
        }
    }

    /// Success and retirement both invalidate the pending request, never the serial history.
    pub(super) fn clear(&mut self) {
        self.pending = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_packet::hevc::HevcBoundary;

    type Test = Result<(), Box<dyn std::error::Error>>;

    fn request() -> HevcPictureTimingRequest {
        HevcPictureTimingRequest {
            key: StreamKey {
                ingress: 1,
                generation: 1,
                ssrc: 7,
            },
            rtp_timestamp: 0,
            idr: true,
            boundary: HevcBoundary::EndOfSequence,
            bytes: 100,
        }
    }

    #[test]
    fn repeated_poll_is_stable_but_identical_later_picture_is_not_a_replay() -> Test {
        let mut tickets = TimingTickets::default();
        let request = request();
        tickets.observe(request.key, request)?;
        let first = tickets.current().ok_or("missing ticket")?;
        assert_eq!(first.ordinal(), 1);
        tickets.observe(request.key, request)?;
        assert_eq!(tickets.current().as_ref(), Some(&first));
        tickets.admit(&first)?;
        tickets.clear();
        assert_eq!(tickets.admit(&first), Err(HevcTimingRefusal::StaleTicket));
        tickets.observe(request.key, request)?;
        let second = tickets.current().ok_or("missing next ticket")?;
        assert_eq!(second.ordinal(), 2);
        assert_eq!(second.request(), first.request());
        assert_ne!(second, first);
        assert_eq!(tickets.admit(&first), Err(HevcTimingRefusal::StaleTicket));
        tickets.admit(&second)?;
        Ok(())
    }

    #[test]
    fn same_metadata_and_ordinal_do_not_cross_owner_boundaries() -> Test {
        let mut left = TimingTickets::default();
        let mut right = TimingTickets::default();
        let request = request();
        left.observe(request.key, request)?;
        right.observe(request.key, request)?;
        let a = left.current().ok_or("missing left ticket")?;
        let b = right.current().ok_or("missing right ticket")?;
        assert_eq!(a.ordinal(), b.ordinal());
        assert_eq!(a.request(), b.request());
        assert_ne!(a, b);
        assert_eq!(left.admit(&b), Err(HevcTimingRefusal::StaleTicket));
        assert_eq!(right.admit(&a), Err(HevcTimingRefusal::StaleTicket));
        left.admit(&a)?;
        right.admit(&b)?;
        Ok(())
    }

    #[test]
    fn retirement_and_new_generation_never_reset_the_ordinal() -> Test {
        let mut tickets = TimingTickets::default();
        let mut request = request();
        tickets.observe(request.key, request)?;
        let old = tickets.current().ok_or("missing old ticket")?;
        tickets.clear();
        request.key.generation += 1;
        tickets.observe(request.key, request)?;
        let next = tickets.current().ok_or("missing new ticket")?;
        assert_eq!(next.ordinal(), old.ordinal() + 1);
        assert_eq!(tickets.admit(&old), Err(HevcTimingRefusal::StaleTicket));
        tickets.admit(&next)?;
        Ok(())
    }

    #[test]
    fn inconsistent_native_request_cannot_replace_pending_timing() -> Test {
        let mut tickets = TimingTickets::default();
        let request = request();
        tickets.observe(request.key, request)?;
        let before = tickets.current();
        let mut different = request;
        different.rtp_timestamp += 1;
        assert_eq!(
            tickets.observe(request.key, different),
            Err(HevcTimingRefusal::InconsistentRequest)
        );
        assert_eq!(tickets.current(), before);
        different = request;
        different.key.generation += 1;
        assert_eq!(
            tickets.observe(request.key, different),
            Err(HevcTimingRefusal::InconsistentRequest)
        );
        assert_eq!(tickets.current(), before);
        Ok(())
    }

    #[test]
    fn ordinal_exhaustion_preserves_state_instead_of_wrapping() -> Test {
        let mut tickets = TimingTickets {
            ordinal: u64::MAX - 1,
            ..TimingTickets::default()
        };
        let request = request();
        tickets.observe(request.key, request)?;
        let last = tickets.current().ok_or("missing last ticket")?;
        assert_eq!(last.ordinal(), u64::MAX);
        tickets.clear();
        assert_eq!(
            tickets.observe(request.key, request),
            Err(HevcTimingRefusal::CounterExhausted)
        );
        assert_eq!(tickets.ordinal, u64::MAX);
        assert!(tickets.current().is_none());
        assert_eq!(tickets.admit(&last), Err(HevcTimingRefusal::StaleTicket));
        Ok(())
    }
}
